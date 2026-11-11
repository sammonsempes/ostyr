use cmdb::summary::{DETAIL_ATTRIBUTES_SQL, DETAIL_KEYS_SQL, DETAIL_SQL, FIRST_LIST_SQL, NEXT_LIST_SQL};
use cmdb::types::Row;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use std::collections::{BTreeMap, VecDeque};
use std::ops::Bound;
use std::sync::{Mutex, MutexGuard, PoisonError};


pub enum Forced {
    Fail,
    Rows(Vec<Row>),
}


pub struct MemAsset {
    pub kind: String,
    pub lifecycle: String,
    pub version: u64,
    pub keys: Vec<(String, String)>,
    pub attributes: Vec<(String, String, String)>,
    pub open_conflicts: u64,
}


#[derive(Default)]
pub struct Db {
    pub tenants: Mutex<BTreeMap<String, BTreeMap<String, MemAsset>>>,
    pub forced: Mutex<VecDeque<Forced>>,
    pub statements: Mutex<Vec<(String, &'static str)>>,
}


pub fn lock<Guarded>(mutex: &Mutex<Guarded>) -> MutexGuard<'_, Guarded> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn malformed() -> PgError {
    PgError::Server {
        code: "22P02".to_owned(),
        class: "data",
    }
}


pub fn param(params: &[String], index: usize) -> Result<&String, PgError> {
    params.get(index).ok_or_else(malformed)
}


pub fn limit_of(params: &[String], index: usize) -> Result<usize, PgError> {
    param(params, index)?.parse::<usize>().map_err(|_bad| malformed())
}


pub fn summary_row(id: &str, asset: &MemAsset) -> Row {
    vec![
        id.to_owned(),
        asset.kind.clone(),
        asset.lifecycle.clone(),
        asset.version.to_string(),
        asset.keys.len().to_string(),
        asset.attributes.len().to_string(),
        asset.open_conflicts.to_string(),
    ]
}


pub fn handle(db: &Db, scope: &TenantScope, sql: &'static str, params: &[String]) -> Result<Vec<Row>, PgError> {
    lock(&db.statements).push((tenant_of(scope).to_owned(), sql));
    match lock(&db.forced).pop_front() {
        Some(Forced::Fail) => Err(PgError::Server {
            code: "XX000".to_owned(),
            class: "internal",
        }),
        Some(Forced::Rows(rows)) => Ok(rows),
        None => {
            let tenants = lock(&db.tenants);
            let empty = BTreeMap::new();
            let table = tenants.get(tenant_of(scope)).unwrap_or(&empty);
            if sql == FIRST_LIST_SQL {
                Ok(table
                    .iter()
                    .take(limit_of(params, 0)?)
                    .map(|(id, asset)| summary_row(id, asset))
                    .collect())
            } else if sql == NEXT_LIST_SQL {
                let after = param(params, 0)?;
                Ok(table
                    .range::<String, _>((Bound::Excluded(after), Bound::Unbounded))
                    .take(limit_of(params, 1)?)
                    .map(|(id, asset)| summary_row(id, asset))
                    .collect())
            } else if sql == DETAIL_SQL {
                let id = param(params, 0)?;
                Ok(table.get(id).map(|asset| summary_row(id, asset)).into_iter().collect())
            } else if sql == DETAIL_KEYS_SQL {
                let mut keys = table.get(param(params, 0)?).map_or_else(Vec::new, |asset| asset.keys.clone());
                keys.sort();
                Ok(keys.into_iter().take(limit_of(params, 1)?).map(|(key, value)| vec![key, value]).collect())
            } else if sql == DETAIL_ATTRIBUTES_SQL {
                let mut attributes = table.get(param(params, 0)?).map_or_else(Vec::new, |asset| asset.attributes.clone());
                attributes.sort();
                Ok(attributes
                    .into_iter()
                    .take(limit_of(params, 1)?)
                    .map(|(name, value, source)| vec![name, value, source])
                    .collect())
            } else {
                Err(malformed())
            }
        }
    }
}
