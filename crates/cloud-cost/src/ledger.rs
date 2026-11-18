use crate::fetch_error::LedgerFailure;
use crate::fetch_model::ListedObject;
use crate::listing::{MAX_KEYS_PER_PAGE, MAX_LIST_PAGES};
use crate::types::ExecFn;
use log::warn;
use serde_json::json;


pub const LEDGER_DDL: &str = "SELECT pg_advisory_xact_lock(hashtext('cloud_cost_ddl')); \
CREATE TABLE IF NOT EXISTS cloud_cost_objects (tenant text NOT NULL, source_id text NOT NULL, key text NOT NULL, \
etag text NOT NULL, size bigint NOT NULL, sha256 text NOT NULL, loaded_at bigint NOT NULL, PRIMARY KEY (tenant, source_id, key, etag)); \
CREATE TABLE IF NOT EXISTS cloud_cost_cursors (tenant text NOT NULL, source_id text NOT NULL, last_key text NOT NULL, \
PRIMARY KEY (tenant, source_id)); \
CREATE TABLE IF NOT EXISTS cloud_cost_rotation (tenant text NOT NULL, source_id text NOT NULL, round bigint NOT NULL, \
PRIMARY KEY (tenant, source_id)); \
CREATE TABLE IF NOT EXISTS cloud_cost_seen (tenant text NOT NULL, source_id text NOT NULL, object_key text NOT NULL, \
first_seen_round bigint NOT NULL, PRIMARY KEY (tenant, source_id, object_key)); \
CREATE OR REPLACE FUNCTION cloud_cost_sync_seen(p_tenant text, p_source text, p_listing text) RETURNS SETOF text AS $$ \
DECLARE v_round bigint; v_pending text[]; \
BEGIN \
PERFORM pg_advisory_xact_lock(hashtextextended('cloud_cost_seen/' || p_tenant || '/' || p_source, 0)); \
IF jsonb_array_length(p_listing::jsonb) > 100000 THEN RAISE EXCEPTION 'listing over the row bound'; END IF; \
INSERT INTO cloud_cost_rotation (tenant, source_id, round) VALUES (p_tenant, p_source, 1) \
ON CONFLICT (tenant, source_id) DO UPDATE SET round = cloud_cost_rotation.round + 1 RETURNING round INTO v_round; \
SELECT array_agg(l.k) INTO v_pending FROM jsonb_to_recordset(p_listing::jsonb) AS l(k text, e text) \
LEFT JOIN cloud_cost_objects o ON o.tenant = p_tenant AND o.source_id = p_source AND o.key = l.k AND o.etag = l.e \
WHERE o.sha256 IS NULL OR o.sha256 LIKE 'transient:%'; \
DELETE FROM cloud_cost_seen s WHERE s.tenant = p_tenant AND s.source_id = p_source \
AND NOT EXISTS (SELECT 1 FROM unnest(v_pending) AS u(k) WHERE u.k = s.object_key); \
INSERT INTO cloud_cost_seen (tenant, source_id, object_key, first_seen_round) \
SELECT p_tenant, p_source, u.k, v_round FROM unnest(v_pending) AS u(k) ON CONFLICT (tenant, source_id, object_key) DO NOTHING; \
RETURN QUERY SELECT s.object_key FROM cloud_cost_seen s WHERE s.tenant = p_tenant AND s.source_id = p_source \
ORDER BY s.first_seen_round, s.object_key; \
END $$ LANGUAGE plpgsql";


pub const SELECT_OBJECT: &str = "SELECT sha256 FROM cloud_cost_objects WHERE tenant = $1 AND source_id = $2 AND key = $3 AND etag = $4";


pub const INSERT_OBJECT: &str = "INSERT INTO cloud_cost_objects (tenant, source_id, key, etag, size, sha256, loaded_at) \
VALUES ($1, $2, $3, $4, $5::text::bigint, $6, $7::text::bigint) ON CONFLICT (tenant, source_id, key, etag) DO UPDATE SET \
size = EXCLUDED.size, sha256 = EXCLUDED.sha256, loaded_at = EXCLUDED.loaded_at WHERE cloud_cost_objects.sha256 LIKE 'transient:%'";


pub const SELECT_CURSOR: &str = "SELECT last_key FROM cloud_cost_cursors WHERE tenant = $1 AND source_id = $2";


pub const UPSERT_CURSOR: &str = "INSERT INTO cloud_cost_cursors (tenant, source_id, last_key) VALUES ($1, $2, $3) \
ON CONFLICT (tenant, source_id) DO UPDATE SET last_key = EXCLUDED.last_key";


pub const DELETE_CURSOR: &str = "DELETE FROM cloud_cost_cursors WHERE tenant = $1 AND source_id = $2";


pub const SYNC_SEEN: &str = "SELECT * FROM cloud_cost_sync_seen($1, $2, $3)";


pub const SELECT_LATEST: &str = "SELECT sha256 FROM cloud_cost_objects WHERE tenant = $1 AND source_id = $2 AND key = $3 \
ORDER BY loaded_at DESC LIMIT 1";


/// Rows of `cloud_cost_seen` per tenant and source: the listing cap, also checked inside the SQL function.
pub const MAX_SEEN_ROWS: usize = MAX_LIST_PAGES * MAX_KEYS_PER_PAGE;


/// A rewritten key whose latest version already failed this many times inherits that version's attempts and wait.
pub const INHERIT_FROM_ATTEMPTS: u32 = 2;


pub const REFUSED_PREFIX: &str = "refused:";


/// A transient refusal is the digest column `transient:<reason>:<attempts>:<next try in milliseconds>`.
pub const TRANSIENT_PREFIX: &str = "transient:";


/// The first wait after a transient refusal; it doubles per attempt.
pub const BACKOFF_BASE_MS: u64 = 900_000;


pub const BACKOFF_MAX_MS: u64 = 86_400_000;


pub const BACKOFF_MAX_POWER: u32 = 7;


pub const BACKOFF_FACTOR: u64 = 2;


/// What the ledger knows of one version (key and ETag) of an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerState {
    New,
    Loaded,
    Refused,
    Transient { attempts: u32, next_try: u64 },
}


/// The wait before the next download of an object refused `attempts` times: exponential from `BACKOFF_BASE_MS`, capped at `BACKOFF_MAX_MS`.
pub fn backoff_ms(attempts: u32) -> u64 {
    let power = attempts.saturating_sub(1).min(BACKOFF_MAX_POWER);
    BACKOFF_BASE_MS.saturating_mul(BACKOFF_FACTOR.pow(power)).min(BACKOFF_MAX_MS)
}


pub fn parse_backoff(tail: &str) -> Option<(u32, u64)> {
    let (head, next_try) = tail.rsplit_once(':')?;
    let (_reason, attempts) = head.rsplit_once(':')?;
    Some((attempts.parse().ok()?, next_try.parse().ok()?))
}


/// A row that does not parse is due now, as a new object would be.
pub fn transient_state(tail: &str) -> LedgerState {
    match parse_backoff(tail) {
        Some((attempts, next_try)) => LedgerState::Transient { attempts, next_try },
        None => {
            warn!("ledger row of a transient refusal is unreadable");
            LedgerState::Transient { attempts: 0, next_try: 0 }
        }
    }
}


/// Every statement binds the tenant as `$1`; the executor sends the parameters as text.
pub fn object_state(exec: &ExecFn<'_>, tenant: &str, source_id: &str, object: &ListedObject) -> Result<LedgerState, LedgerFailure> {
    let params = [tenant.to_owned(), source_id.to_owned(), object.key.clone(), object.etag.clone()];
    let rows = exec(SELECT_OBJECT, &params)?;
    Ok(match rows.first().and_then(|row| row.first()) {
        None => LedgerState::New,
        Some(digest) if digest.starts_with(REFUSED_PREFIX) => LedgerState::Refused,
        Some(digest) => digest.strip_prefix(TRANSIENT_PREFIX).map_or(LedgerState::Loaded, transient_state),
    })
}


/// Written after the ClickHouse load succeeded; a repeated write of the same version changes nothing.
pub fn record_loaded(exec: &ExecFn<'_>, tenant: &str, source_id: &str, object: &ListedObject, sha256: &str, now: u64) -> Result<(), LedgerFailure> {
    let params = [
        tenant.to_owned(),
        source_id.to_owned(),
        object.key.clone(),
        object.etag.clone(),
        object.size.to_string(),
        sha256.to_owned(),
        now.to_string(),
    ];
    exec(INSERT_OBJECT, &params).map(drop)
}


/// A refusal that will not change until the object does is kept in the digest column, so the object is not downloaded again.
pub fn record_refused(exec: &ExecFn<'_>, tenant: &str, source_id: &str, object: &ListedObject, reason: &str, now: u64) -> Result<(), LedgerFailure> {
    record_loaded(exec, tenant, source_id, object, &format!("{REFUSED_PREFIX}{reason}"), now)
}


/// A refusal a later round may see differently: kept with its attempt count and the time before which the object is not downloaded again.
pub fn record_transient(
    exec: &ExecFn<'_>,
    tenant: &str,
    source_id: &str,
    object: &ListedObject,
    reason: &str,
    attempts: u32,
    now: u64,
) -> Result<(), LedgerFailure> {
    let next_try = now.saturating_add(backoff_ms(attempts));
    record_loaded(
        exec,
        tenant,
        source_id,
        object,
        &format!("{TRANSIENT_PREFIX}{reason}:{attempts}:{next_try}"),
        now,
    )
}


pub fn read_key(exec: &ExecFn<'_>, select: &str, tenant: &str, source_id: &str) -> Result<Option<String>, LedgerFailure> {
    let rows = exec(select, &[tenant.to_owned(), source_id.to_owned()])?;
    Ok(rows.into_iter().next().and_then(|row| row.into_iter().next()))
}


pub fn write_key(exec: &ExecFn<'_>, statements: (&str, &str), tenant: &str, source_id: &str, key: Option<&str>) -> Result<(), LedgerFailure> {
    let mut params = vec![tenant.to_owned(), source_id.to_owned()];
    match key {
        Some(text) => {
            params.push(text.to_owned());
            exec(statements.0, &params)
        }
        None => exec(statements.1, &params),
    }
    .map(drop)
}


pub fn read_cursor(exec: &ExecFn<'_>, tenant: &str, source_id: &str) -> Result<Option<String>, LedgerFailure> {
    read_key(exec, SELECT_CURSOR, tenant, source_id)
}


/// A cursor is kept only while a listing is incomplete; a complete one clears it so the next round starts at the first key.
pub fn write_cursor(exec: &ExecFn<'_>, tenant: &str, source_id: &str, last_key: Option<&str>) -> Result<(), LedgerFailure> {
    write_key(exec, (UPSERT_CURSOR, DELETE_CURSOR), tenant, source_id, last_key)
}


/// One round of the first-seen ledger: the keys still to serve, oldest first seen first, then by key; the row sync runs inside the SQL function, under its lock.
pub fn sync_seen(exec: &ExecFn<'_>, tenant: &str, source_id: &str, objects: &[ListedObject]) -> Result<Vec<String>, LedgerFailure> {
    if objects.len() > MAX_SEEN_ROWS {
        Err(LedgerFailure)
    } else {
        let listing: Vec<_> = objects.iter().map(|object| json!({ "k": object.key, "e": object.etag })).collect();
        let rows = exec(SYNC_SEEN, &[tenant.to_owned(), source_id.to_owned(), json!(listing).to_string()])?;
        Ok(rows.into_iter().filter_map(|row| row.into_iter().next()).collect())
    }
}


/// The attempts and next try of the key's latest version when it is a transient refusal, whatever its ETag.
pub fn latest_backoff(exec: &ExecFn<'_>, tenant: &str, source_id: &str, key: &str) -> Result<Option<(u32, u64)>, LedgerFailure> {
    let rows = exec(SELECT_LATEST, &[tenant.to_owned(), source_id.to_owned(), key.to_owned()])?;
    Ok(rows
        .first()
        .and_then(|row| row.first())
        .and_then(|digest| digest.strip_prefix(TRANSIENT_PREFIX))
        .and_then(parse_backoff))
}


/// A stored next try is trusted only within `backoff_ms(attempts)` of now: a later one comes from a clock set back or a forged row, and is due now.
pub fn waiting(attempts: u32, next_try: u64, now: u64) -> bool {
    next_try > now && next_try <= now.saturating_add(backoff_ms(attempts))
}
