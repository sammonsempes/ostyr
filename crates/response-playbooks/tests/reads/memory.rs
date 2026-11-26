use alerts::types::Row;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use response_playbooks::runs_read::{GET_SQL, LIST_FIRST_SQL, LIST_NEXT_SQL};
use std::sync::{Mutex, MutexGuard, PoisonError};


pub const CREATED_BASE: i64 = 1_700_000_000;


#[derive(Clone)]
pub struct Stored {
    pub tenant: String,
    pub id: String,
    pub seq: i64,
    pub alert_id: String,
    pub playbook: String,
    pub trace: String,
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


pub fn run_id(tag: char, seq: i64) -> String {
    format!("{tag}{seq:063x}")
}


pub fn meta_cells(stored: &Stored) -> Row {
    vec![
        stored.id.clone(),
        stored.alert_id.clone(),
        stored.playbook.clone(),
        "dry_run".to_owned(),
        "completed".to_owned(),
        "2".to_owned(),
        (CREATED_BASE + stored.seq).to_string(),
        stored.seq.to_string(),
    ]
}


pub fn listed(db: &Db, tenant: &str, after: Option<i64>, limit: usize) -> Vec<Row> {
    let mut found: Vec<Stored> = lock(&db.rows)
        .iter()
        .filter(|stored| stored.tenant == tenant && after.is_none_or(|bound| stored.seq < bound))
        .cloned()
        .collect();
    found.sort_by_key(|stored| std::cmp::Reverse(stored.seq));
    found.iter().take(limit).map(meta_cells).collect()
}


pub fn handle(db: &Db, scope: &TenantScope, sql: &'static str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let tenant = tenant_of(scope);
    if sql == LIST_FIRST_SQL {
        Ok(listed(db, tenant, None, number(params, 0)?))
    } else if sql == LIST_NEXT_SQL {
        Ok(listed(db, tenant, Some(number(params, 0)?), number(params, 1)?))
    } else if sql == GET_SQL {
        let id: &String = params.first().ok_or_else(malformed)?;
        Ok(lock(&db.rows)
            .iter()
            .filter(|stored| stored.tenant == tenant && &stored.id == id)
            .map(|stored| meta_cells(stored).into_iter().chain([stored.trace.clone()]).collect())
            .collect())
    } else {
        Err(malformed())
    }
}
