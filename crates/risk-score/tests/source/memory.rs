use alerts::types::{Row, RowFuture};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use risk_score::source::{RISK_ALERTS_NEXT_SQL, RISK_ALERTS_SQL};
use std::future::ready;
use std::sync::{Mutex, MutexGuard, PoisonError};


pub const SECOND_PARAM: usize = 1;


pub const THIRD_PARAM: usize = 2;


pub const TENANT_BIND: &str = "tenant = $1";


pub struct Stored {
    pub tenant: String,
    pub id: String,
    pub rule: String,
    pub severity: String,
    pub created: u64,
    pub host: String,
    pub user: String,
}


#[derive(Default)]
pub struct Db {
    pub rows: Vec<Stored>,
    pub fail: bool,
    pub forced: Option<Vec<Row>>,
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


pub fn number(params: &[String], index: usize) -> Result<u64, PgError> {
    params.get(index).ok_or_else(malformed)?.parse::<u64>().map_err(|_source| malformed())
}


pub fn row_of(stored: &Stored) -> Row {
    vec![
        stored.id.clone(),
        stored.rule.clone(),
        stored.severity.clone(),
        stored.created.to_string(),
        stored.host.clone(),
        stored.user.clone(),
    ]
}


pub fn select(db: &Db, scope: &TenantScope, sql: &'static str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let lower = number(params, 0)?;
    let limit =
        usize::try_from(params.last().ok_or_else(malformed)?.parse::<u64>().map_err(|_source| malformed())?).map_err(|_source| malformed())?;
    let cursor = if sql == RISK_ALERTS_NEXT_SQL {
        Some((number(params, SECOND_PARAM)?, params.get(THIRD_PARAM).ok_or_else(malformed)?.clone()))
    } else {
        None
    };
    let scoped = sql.contains(TENANT_BIND);
    let mut rows: Vec<&Stored> = db
        .rows
        .iter()
        .filter(|stored| !scoped || stored.tenant == tenant_of(scope))
        .filter(|stored| stored.created > lower)
        .filter(|stored| cursor.as_ref().is_none_or(|(created, id)| (stored.created, &stored.id) > (*created, id)))
        .collect();
    rows.sort_by(|left, right| (left.created, &left.id).cmp(&(right.created, &right.id)));
    Ok(rows.into_iter().take(limit).map(row_of).collect())
}


pub fn handle(db: &Db, scope: &TenantScope, sql: &'static str, params: &[String]) -> Result<Vec<Row>, PgError> {
    lock(&db.statements).push((tenant_of(scope).to_owned(), sql));
    if db.fail {
        Err(PgError::Server {
            code: "XX000".to_owned(),
            class: "internal",
        })
    } else if let Some(rows) = &db.forced {
        Ok(rows.clone())
    } else if sql == RISK_ALERTS_SQL || sql == RISK_ALERTS_NEXT_SQL {
        select(db, scope, sql, params)
    } else {
        Err(malformed())
    }
}


pub fn executor(db: &Db) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'_> + '_ {
    move |scope, sql, params| -> RowFuture<'_> { Box::pin(ready(handle(db, &scope, sql, &params))) }
}
