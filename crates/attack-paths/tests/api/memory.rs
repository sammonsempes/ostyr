use attack_paths::store::{GET_SQL, LIST_SQL, STORE_SQL};
use attack_paths::types::Row;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use std::sync::{Mutex, MutexGuard, PoisonError};


pub const PARAM_GENERATED: usize = 1;


pub const PARAM_DIGEST: usize = 2;


pub const PARAM_BODY: usize = 3;


pub const PARAM_TRUNCATED: usize = 4;


pub const PARAM_BUDGET: usize = 5;


pub const PARAM_UNSEARCHED: usize = 6;


pub const STORED_BASE: i64 = 1_700_000_000;


#[derive(Clone)]
pub struct Stored {
    pub tenant: String,
    pub id: i64,
    pub graph_digest: String,
    pub generated: String,
    pub digest: String,
    pub body: String,
    pub truncated: String,
    pub budget_reached: String,
    pub unsearched: String,
}


#[derive(Default)]
pub struct Db {
    pub rows: Mutex<Vec<Stored>>,
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


pub fn number<Parsed: std::str::FromStr>(params: &[String], index: usize) -> Result<Parsed, PgError> {
    params.get(index).and_then(|text| text.parse().ok()).ok_or_else(malformed)
}


pub fn text(params: &[String], index: usize) -> Result<String, PgError> {
    params.get(index).cloned().ok_or_else(malformed)
}


pub fn meta_row(stored: &Stored) -> Row {
    vec![
        stored.id.to_string(),
        stored.graph_digest.clone(),
        stored.generated.clone(),
        stored.digest.clone(),
        stored.body.len().to_string(),
        stored.truncated.clone(),
        stored.budget_reached.clone(),
        stored.unsearched.clone(),
        (STORED_BASE + stored.id).to_string(),
    ]
}


pub fn listed(db: &Db, tenant: &str, limit: usize) -> Vec<Row> {
    let mut found: Vec<Stored> = lock(&db.rows).iter().filter(|stored| stored.tenant == tenant).cloned().collect();
    found.sort_by_key(|stored| std::cmp::Reverse(stored.id));
    found.iter().take(limit).map(meta_row).collect()
}


pub fn insert(db: &Db, tenant: &str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let mut rows = lock(&db.rows);
    let id = i64::try_from(rows.len()).map_err(|_error| malformed())? + 1;
    rows.push(Stored {
        tenant: tenant.to_owned(),
        id,
        graph_digest: text(params, 0)?,
        generated: text(params, PARAM_GENERATED)?,
        digest: text(params, PARAM_DIGEST)?,
        body: text(params, PARAM_BODY)?,
        truncated: text(params, PARAM_TRUNCATED)?,
        budget_reached: text(params, PARAM_BUDGET)?,
        unsearched: text(params, PARAM_UNSEARCHED)?,
    });
    Ok(vec![vec!["stored".to_owned(), id.to_string()]])
}


pub fn handle(db: &Db, scope: &TenantScope, sql: &'static str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let tenant = tenant_of(scope);
    if sql == STORE_SQL {
        insert(db, tenant, params)
    } else if sql == LIST_SQL {
        Ok(listed(db, tenant, number(params, 0)?))
    } else if sql == GET_SQL {
        let id: i64 = number(params, 0)?;
        Ok(lock(&db.rows)
            .iter()
            .filter(|stored| stored.tenant == tenant && stored.id == id)
            .map(|stored| {
                vec![
                    stored.graph_digest.clone(),
                    stored.generated.clone(),
                    stored.digest.clone(),
                    stored.truncated.clone(),
                    stored.budget_reached.clone(),
                    stored.unsearched.clone(),
                    stored.body.clone(),
                ]
            })
            .collect())
    } else {
        Err(malformed())
    }
}
