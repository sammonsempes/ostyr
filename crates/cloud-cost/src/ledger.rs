use crate::fetch_error::LedgerFailure;
use crate::fetch_model::ListedObject;
use crate::types::ExecFn;


pub const LEDGER_DDL: &str = "CREATE TABLE IF NOT EXISTS cloud_cost_objects (tenant text NOT NULL, source_id text NOT NULL, key text NOT NULL, \
etag text NOT NULL, size bigint NOT NULL, sha256 text NOT NULL, loaded_at bigint NOT NULL, PRIMARY KEY (tenant, source_id, key, etag)); \
CREATE TABLE IF NOT EXISTS cloud_cost_cursors (tenant text NOT NULL, source_id text NOT NULL, last_key text NOT NULL, \
PRIMARY KEY (tenant, source_id))";


pub const SELECT_OBJECT: &str = "SELECT sha256 FROM cloud_cost_objects WHERE tenant = $1 AND source_id = $2 AND key = $3 AND etag = $4";


pub const INSERT_OBJECT: &str = "INSERT INTO cloud_cost_objects (tenant, source_id, key, etag, size, sha256, loaded_at) \
VALUES ($1, $2, $3, $4, $5::text::bigint, $6, $7::text::bigint) ON CONFLICT DO NOTHING";


pub const SELECT_CURSOR: &str = "SELECT last_key FROM cloud_cost_cursors WHERE tenant = $1 AND source_id = $2";


pub const UPSERT_CURSOR: &str = "INSERT INTO cloud_cost_cursors (tenant, source_id, last_key) VALUES ($1, $2, $3) \
ON CONFLICT (tenant, source_id) DO UPDATE SET last_key = EXCLUDED.last_key";


pub const DELETE_CURSOR: &str = "DELETE FROM cloud_cost_cursors WHERE tenant = $1 AND source_id = $2";


pub const REFUSED_PREFIX: &str = "refused:";


/// What the ledger knows of one version (key and ETag) of an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerState {
    New,
    Loaded,
    Refused,
}


/// Every statement binds the tenant as `$1`; the executor sends the parameters as text.
pub fn object_state(exec: &ExecFn<'_>, tenant: &str, source_id: &str, object: &ListedObject) -> Result<LedgerState, LedgerFailure> {
    let params = [tenant.to_owned(), source_id.to_owned(), object.key.clone(), object.etag.clone()];
    let rows = exec(SELECT_OBJECT, &params)?;
    Ok(match rows.first().and_then(|row| row.first()) {
        None => LedgerState::New,
        Some(digest) if digest.starts_with(REFUSED_PREFIX) => LedgerState::Refused,
        Some(_digest) => LedgerState::Loaded,
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
