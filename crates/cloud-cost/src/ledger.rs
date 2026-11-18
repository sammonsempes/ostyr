use crate::fetch_error::LedgerFailure;
use crate::fetch_model::ListedObject;
use crate::types::ExecFn;


pub const LEDGER_DDL: &str = "CREATE TABLE IF NOT EXISTS cloud_cost_objects (tenant text NOT NULL, source_id text NOT NULL, key text NOT NULL, \
etag text NOT NULL, size bigint NOT NULL, sha256 text NOT NULL, loaded_at bigint NOT NULL, PRIMARY KEY (tenant, source_id, key, etag))";


pub const SELECT_OBJECT: &str = "SELECT key FROM cloud_cost_objects WHERE tenant = $1 AND source_id = $2 AND key = $3 AND etag = $4";


pub const INSERT_OBJECT: &str = "INSERT INTO cloud_cost_objects (tenant, source_id, key, etag, size, sha256, loaded_at) \
VALUES ($1, $2, $3, $4, $5::text::bigint, $6, $7::text::bigint) ON CONFLICT DO NOTHING";


/// Every statement binds the tenant as `$1`; the executor sends the parameters as text.
pub fn is_loaded(exec: &ExecFn<'_>, tenant: &str, source_id: &str, object: &ListedObject) -> Result<bool, LedgerFailure> {
    let params = [tenant.to_owned(), source_id.to_owned(), object.key.clone(), object.etag.clone()];
    exec(SELECT_OBJECT, &params).map(|rows| !rows.is_empty())
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
