use crate::types::Table;
use alerts::store::{GET_SQL, INSERT_SQL, NEXT_SQL};
use alerts::types::Row;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};


pub enum Forced {
    Fail,
    Rows(Vec<Row>),
}


#[derive(Default)]
pub struct Db {
    pub tenants: Mutex<BTreeMap<String, Table>>,
    pub forced: Mutex<VecDeque<Forced>>,
    pub statements: Mutex<Vec<(String, &'static str)>>,
}


pub fn lock<Guarded>(mutex: &Mutex<Guarded>) -> MutexGuard<'_, Guarded> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn text(doc: &Value, field: &str) -> String {
    doc.get(field).and_then(Value::as_str).map_or_else(String::new, str::to_owned)
}


pub fn row_of(doc: &Value) -> (u64, Row) {
    let created = doc.get("created").and_then(Value::as_u64).unwrap_or(0);
    let event_ids = doc.get("event_ids").map_or_else(String::new, Value::to_string);
    let flag = doc.get("summary_truncated").and_then(Value::as_bool).unwrap_or(false);
    let original = doc.get("summary_original_bytes").and_then(Value::as_u64).unwrap_or(0);
    let row = vec![
        text(doc, "id"),
        text(doc, "rule_id"),
        text(doc, "rule_title"),
        text(doc, "severity"),
        text(doc, "event_time"),
        created.to_string(),
        text(doc, "host_name"),
        text(doc, "user_name"),
        event_ids,
        text(doc, "summary"),
        flag.to_string(),
        original.to_string(),
    ];
    (created, row)
}


pub fn malformed() -> PgError {
    PgError::Server {
        code: "22P02".to_owned(),
        class: "data",
    }
}


pub fn insert(table: &mut Table, params: &[String]) -> Result<Vec<Row>, PgError> {
    let document = params.first().ok_or_else(malformed)?;
    let docs: Vec<Value> = serde_json::from_str(document).map_err(|_source| malformed())?;
    let fresh = docs
        .iter()
        .filter(|doc| {
            let id = text(doc, "id");
            let new = !table.contains_key(&id);
            if new {
                table.insert(id, row_of(doc));
            }
            new
        })
        .count();
    Ok(vec![vec![fresh.to_string()]])
}


pub fn select(table: &Table, sql: &str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let limit = params.last().ok_or_else(malformed)?.parse::<usize>().map_err(|_source| malformed())?;
    let cursor = if sql == NEXT_SQL {
        let created = params.first().ok_or_else(malformed)?.parse::<u64>().map_err(|_source| malformed())?;
        Some((created, params.get(1).ok_or_else(malformed)?.clone()))
    } else {
        None
    };
    let mut entries: Vec<(u64, String, Row)> = table.iter().map(|(id, (created, row))| (*created, id.clone(), row.clone())).collect();
    entries.sort_by(|left, right| (right.0, &right.1).cmp(&(left.0, &left.1)));
    Ok(entries
        .into_iter()
        .filter(|(created, id, _row)| cursor.as_ref().is_none_or(|position| (*created, id.clone()) < *position))
        .take(limit)
        .map(|(_created, _id, row)| row)
        .collect())
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
            let mut tenants = lock(&db.tenants);
            let table = tenants.entry(tenant_of(scope).to_owned()).or_default();
            if sql == INSERT_SQL {
                insert(table, params)
            } else if sql == GET_SQL {
                Ok(table
                    .get(params.first().map_or("", String::as_str))
                    .map(|(_created, row)| row.clone())
                    .into_iter()
                    .collect())
            } else {
                select(table, sql, params)
            }
        }
    }
}
