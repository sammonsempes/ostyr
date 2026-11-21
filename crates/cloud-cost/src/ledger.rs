use crate::fetch_error::LedgerFailure;
use crate::fetch_model::{ListedObject, SeenOrder, SeenWindow};
use crate::listing::{listed_bytes, MAX_KEYS_PER_PAGE, MAX_LISTED_BYTES, MAX_LIST_PAGES_PER_ROUND};
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
CREATE TABLE IF NOT EXISTS cloud_cost_seen (tenant text NOT NULL, source_id text NOT NULL, object_key text NOT NULL, etag text NOT NULL, \
first_seen_round bigint NOT NULL, weight integer NOT NULL, PRIMARY KEY (tenant, source_id, object_key, etag)); \
CREATE INDEX IF NOT EXISTS cloud_cost_seen_age ON cloud_cost_seen (tenant, source_id, first_seen_round) INCLUDE (weight) WHERE weight > 0; \
CREATE OR REPLACE FUNCTION cloud_cost_sync_seen(p_tenant text, p_source text, p_listing text, p_after text, p_until text, p_complete text, \
p_delete_cap bigint) \
RETURNS TABLE(out_key text, out_recorded text) AS $$ \
DECLARE v_listing jsonb; v_round bigint; v_keys text[]; v_etags text[]; v_hashes bytea[]; v_tids tid[]; v_room bigint; v_room_bytes bigint; \
v_found bigint; v_deleted bigint; \
BEGIN \
PERFORM pg_advisory_xact_lock(hashtextextended('cloud_cost_seen/' || p_tenant || '/' || p_source, 0)); \
IF octet_length(p_listing) > 8388608 THEN RAISE EXCEPTION 'listing over the byte bound'; END IF; \
v_listing := p_listing::jsonb; \
IF jsonb_array_length(v_listing) > 10000 THEN RAISE EXCEPTION 'listing over the row bound'; END IF; \
INSERT INTO cloud_cost_rotation (tenant, source_id, round) VALUES (p_tenant, p_source, 1) \
ON CONFLICT (tenant, source_id) DO UPDATE SET round = cloud_cost_rotation.round + 1 RETURNING round INTO v_round; \
SELECT COALESCE(array_agg(l.k), '{}'), COALESCE(array_agg(l.e), '{}'), \
COALESCE(array_agg(sha256(convert_to(length(l.k)::text || ':' || l.k || l.e, 'UTF8'))), '{}') \
INTO v_keys, v_etags, v_hashes \
FROM (SELECT DISTINCT r.k, r.e FROM jsonb_to_recordset(v_listing) AS r(k text, e text)) l \
WHERE COALESCE((SELECT o.sha256 FROM cloud_cost_objects o WHERE o.tenant = p_tenant AND o.source_id = p_source AND o.key = l.k AND o.etag = l.e), \
'transient:') LIKE 'transient:%'; \
SELECT COALESCE(array_agg(c.t), '{}') INTO v_tids FROM (SELECT s.ctid AS t FROM cloud_cost_seen s \
WHERE s.tenant = p_tenant AND s.source_id = p_source AND s.weight > 0 \
AND s.object_key COLLATE \"C\" > p_after COLLATE \"C\" AND (p_complete = 'true' OR s.object_key COLLATE \"C\" <= p_until COLLATE \"C\") \
AND sha256(convert_to(length(s.object_key)::text || ':' || s.object_key || s.etag, 'UTF8')) NOT IN (SELECT unnest(v_hashes)) \
ORDER BY s.first_seen_round LIMIT p_delete_cap * 2) c; \
v_found := COALESCE(cardinality(v_tids), 0); \
DELETE FROM cloud_cost_seen s WHERE s.tenant = p_tenant AND s.source_id = p_source AND s.ctid = ANY(v_tids[1:p_delete_cap::int]); \
GET DIAGNOSTICS v_deleted = ROW_COUNT; \
SELECT 200000 - count(*), 33554432 - COALESCE(sum(s.weight), 0) INTO v_room, v_room_bytes FROM cloud_cost_seen s \
WHERE s.tenant = p_tenant AND s.source_id = p_source AND s.weight > 0; \
INSERT INTO cloud_cost_seen (tenant, source_id, object_key, etag, first_seen_round, weight) \
SELECT p_tenant, p_source, n.k, n.e, v_round, n.w FROM (SELECT u.k, u.e, octet_length(u.k) + octet_length(u.e) AS w, \
sum(octet_length(u.k) + octet_length(u.e)) OVER (ORDER BY u.k COLLATE \"C\") AS run FROM unnest(v_keys, v_etags) AS u(k, e) \
WHERE (SELECT 1 FROM cloud_cost_seen s WHERE s.tenant = p_tenant AND s.source_id = p_source \
AND s.object_key = u.k AND s.etag = u.e LIMIT 1) IS NULL) n \
WHERE n.run <= v_room_bytes ORDER BY n.k COLLATE \"C\" LIMIT GREATEST(v_room, 0); \
RETURN QUERY SELECT u.k, (f.fs IS NOT NULL)::int::text FROM unnest(v_keys, v_etags) AS u(k, e) \
LEFT JOIN LATERAL (SELECT s.first_seen_round AS fs FROM cloud_cost_seen s \
WHERE s.tenant = p_tenant AND s.source_id = p_source AND s.object_key = u.k AND s.etag = u.e) f ON true \
ORDER BY f.fs NULLS LAST, u.k COLLATE \"C\"; \
out_key := ''; out_recorded := 'deferred:' || (v_found - v_deleted)::text; RETURN NEXT; \
END $$ LANGUAGE plpgsql SET enable_sort = off SET enable_seqscan = off SET jit = off SET search_path = pg_catalog, public, pg_temp";


pub const SELECT_OBJECT: &str = "SELECT sha256 FROM cloud_cost_objects WHERE tenant = $1 AND source_id = $2 AND key = $3 AND etag = $4";


pub const INSERT_OBJECT: &str = "INSERT INTO cloud_cost_objects (tenant, source_id, key, etag, size, sha256, loaded_at) \
VALUES ($1, $2, $3, $4, $5::text::bigint, $6, $7::text::bigint) ON CONFLICT (tenant, source_id, key, etag) DO UPDATE SET \
size = EXCLUDED.size, sha256 = EXCLUDED.sha256, loaded_at = EXCLUDED.loaded_at WHERE cloud_cost_objects.sha256 LIKE 'transient:%'";


pub const SELECT_CURSOR: &str = "SELECT last_key FROM cloud_cost_cursors WHERE tenant = $1 AND source_id = $2";


pub const UPSERT_CURSOR: &str = "INSERT INTO cloud_cost_cursors (tenant, source_id, last_key) VALUES ($1, $2, $3) \
ON CONFLICT (tenant, source_id) DO UPDATE SET last_key = EXCLUDED.last_key";


pub const DELETE_CURSOR: &str = "DELETE FROM cloud_cost_cursors WHERE tenant = $1 AND source_id = $2";


pub const SYNC_SEEN: &str = "SELECT * FROM cloud_cost_sync_seen($1, $2, $3, $4, $5, $6, $7::text::bigint)";


pub const SELECT_LATEST: &str = "SELECT sha256 FROM cloud_cost_objects WHERE tenant = $1 AND source_id = $2 AND key = $3 \
ORDER BY loaded_at DESC LIMIT 1";


/// Objects in one listing: the page cap, also checked inside the SQL function.
pub const MAX_LISTED_OBJECTS: usize = MAX_LIST_PAGES_PER_ROUND * MAX_KEYS_PER_PAGE;


/// Rows of `cloud_cost_seen` per tenant and source, enforced inside the SQL function under its lock; past it new versions are not recorded.
pub const MAX_SEEN_ROWS_PER_SOURCE: usize = 200_000;


/// Key and ETag bytes of `cloud_cost_seen` per tenant and source (the `weight` column), enforced in the SQL function like the row cap: sixteen windows of the longest keys.
pub const MAX_SEEN_BYTES_PER_SOURCE: usize = 33_554_432;


/// The listing text the SQL function accepts: `MAX_LISTED_BYTES` doubled for JSON escapes plus 40 bytes of syntax per object, rounded up.
pub const MAX_LISTING_TEXT_BYTES: usize = 8_388_608;


/// Rows of `cloud_cost_seen` one sync deletes, oldest first; the rest wait for a later round, whose window covers them again.
pub const MAX_SEEN_DELETES_PER_SYNC: usize = 10_000;


/// The first column of the row that reports the deletes left for later; no listed key is empty.
pub const DEFERRED_ROW_KEY: &str = "";


pub const DEFERRED_PREFIX: &str = "deferred:";


/// A rewritten key whose latest version already failed this many times inherits that version's attempts and wait.
pub const INHERIT_FROM_ATTEMPTS: u32 = 2;


/// The second column of a row the cap kept out of the ledger.
pub const UNRECORDED: &str = "0";


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


/// One round of the first-seen ledger: the versions still to serve, oldest first seen first, then by key, how many the row cap left unrecorded and how many deletes `delete_cap` deferred.
pub fn sync_seen(
    exec: &ExecFn<'_>,
    tenant: &str,
    source_id: &str,
    objects: &[ListedObject],
    window: &SeenWindow<'_>,
    delete_cap: usize,
) -> Result<SeenOrder, LedgerFailure> {
    if objects.len() > MAX_LISTED_OBJECTS || listed_bytes(objects) > MAX_LISTED_BYTES {
        Err(LedgerFailure)
    } else {
        let listing: Vec<_> = objects.iter().map(|object| json!({ "k": object.key, "e": object.etag })).collect();
        let params = [
            tenant.to_owned(),
            source_id.to_owned(),
            json!(listing).to_string(),
            window.after.map_or_else(String::new, str::to_owned),
            window.until.map_or_else(String::new, str::to_owned),
            window.complete.to_string(),
            delete_cap.to_string(),
        ];
        let rows = exec(SYNC_SEEN, &params)?;
        let (reports, listed): (Vec<Vec<String>>, Vec<Vec<String>>) = rows
            .into_iter()
            .partition(|row| row.first().map(String::as_str) == Some(DEFERRED_ROW_KEY));
        let unrecorded = listed.iter().filter(|row| row.get(1).map(String::as_str) == Some(UNRECORDED)).count();
        let deletes_deferred = reports
            .iter()
            .filter_map(|row| row.get(1))
            .filter_map(|text| text.strip_prefix(DEFERRED_PREFIX))
            .filter_map(|count| count.parse::<usize>().ok())
            .sum();
        Ok(SeenOrder {
            keys: listed.into_iter().filter_map(|row| row.into_iter().next()).collect(),
            unrecorded,
            deletes_deferred,
        })
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
