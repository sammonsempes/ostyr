use crate::fetch_error::LedgerFailure;
use crate::fetch_model::ListedObject;
use crate::types::ExecFn;
use log::warn;


pub const LEDGER_DDL: &str = "CREATE TABLE IF NOT EXISTS cloud_cost_objects (tenant text NOT NULL, source_id text NOT NULL, key text NOT NULL, \
etag text NOT NULL, size bigint NOT NULL, sha256 text NOT NULL, loaded_at bigint NOT NULL, PRIMARY KEY (tenant, source_id, key, etag)); \
CREATE TABLE IF NOT EXISTS cloud_cost_cursors (tenant text NOT NULL, source_id text NOT NULL, last_key text NOT NULL, \
PRIMARY KEY (tenant, source_id))";


pub const SELECT_OBJECT: &str = "SELECT sha256 FROM cloud_cost_objects WHERE tenant = $1 AND source_id = $2 AND key = $3 AND etag = $4";


pub const INSERT_OBJECT: &str = "INSERT INTO cloud_cost_objects (tenant, source_id, key, etag, size, sha256, loaded_at) \
VALUES ($1, $2, $3, $4, $5::text::bigint, $6, $7::text::bigint) ON CONFLICT (tenant, source_id, key, etag) DO UPDATE SET \
size = EXCLUDED.size, sha256 = EXCLUDED.sha256, loaded_at = EXCLUDED.loaded_at WHERE cloud_cost_objects.sha256 LIKE 'transient:%'";


pub const SELECT_CURSOR: &str = "SELECT last_key FROM cloud_cost_cursors WHERE tenant = $1 AND source_id = $2";


pub const UPSERT_CURSOR: &str = "INSERT INTO cloud_cost_cursors (tenant, source_id, last_key) VALUES ($1, $2, $3) \
ON CONFLICT (tenant, source_id) DO UPDATE SET last_key = EXCLUDED.last_key";


pub const DELETE_CURSOR: &str = "DELETE FROM cloud_cost_cursors WHERE tenant = $1 AND source_id = $2";


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


pub fn read_cursor(exec: &ExecFn<'_>, tenant: &str, source_id: &str) -> Result<Option<String>, LedgerFailure> {
    let rows = exec(SELECT_CURSOR, &[tenant.to_owned(), source_id.to_owned()])?;
    Ok(rows.into_iter().next().and_then(|row| row.into_iter().next()))
}


/// A cursor is kept only while a listing is incomplete; a complete one clears it so the next round starts at the first key.
pub fn write_cursor(exec: &ExecFn<'_>, tenant: &str, source_id: &str, last_key: Option<&str>) -> Result<(), LedgerFailure> {
    let mut params = vec![tenant.to_owned(), source_id.to_owned()];
    match last_key {
        Some(key) => {
            params.push(key.to_owned());
            exec(UPSERT_CURSOR, &params)
        }
        None => exec(DELETE_CURSOR, &params),
    }
    .map(drop)
}
