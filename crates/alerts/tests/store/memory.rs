use crate::types::{Table, TriageKey, TriageRow};
use alerts::store::{GET_SQL, INSERT_SQL, NEXT_SQL, TRIAGE_GET_SQL, TRIAGE_INSERT_SQL, TRIAGE_UPDATE_SQL};
use alerts::types::Row;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::Value;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};


pub const STATUS_PARAM: usize = 1;


pub const ACTOR_PARAM: usize = 2;


pub const NOTE_PARAM: usize = 3;


pub const NOW_PARAM: usize = 4;


pub const READ_PARAM: usize = 5;


pub enum Forced {
    Fail,
    Rows(Vec<Row>),
}


#[derive(Default)]
pub struct Db {
    pub tenants: Mutex<BTreeMap<String, Table>>,
    pub triage: Mutex<BTreeMap<TriageKey, TriageRow>>,
    pub forced: Mutex<VecDeque<Forced>>,
    pub statements: Mutex<Vec<(String, &'static str)>>,
}


pub fn lock<Guarded>(mutex: &Mutex<Guarded>) -> MutexGuard<'_, Guarded> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn text(doc: &Value, field: &str) -> Result<String, PgError> {
    doc.get(field).and_then(Value::as_str).map(str::to_owned).ok_or_else(malformed)
}


pub fn optional_text(doc: &Value, field: &str) -> Result<String, PgError> {
    match doc.get(field) {
        Some(Value::Null) => Ok(String::new()),
        _other => text(doc, field),
    }
}


pub fn row_of(doc: &Value) -> Result<(u64, Row), PgError> {
    let created = doc.get("created").and_then(Value::as_u64).ok_or_else(malformed)?;
    let event_ids = doc.get("event_ids").map(Value::to_string).ok_or_else(malformed)?;
    let flag = doc.get("summary_truncated").and_then(Value::as_bool).ok_or_else(malformed)?;
    let original = doc.get("summary_original_bytes").and_then(Value::as_u64).ok_or_else(malformed)?;
    let row = vec![
        text(doc, "id")?,
        text(doc, "rule_id")?,
        text(doc, "rule_title")?,
        text(doc, "severity")?,
        text(doc, "event_time")?,
        created.to_string(),
        optional_text(doc, "host_name")?,
        optional_text(doc, "user_name")?,
        event_ids,
        text(doc, "summary")?,
        flag.to_string(),
        original.to_string(),
    ];
    Ok((created, row))
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
    let fresh = docs.iter().try_fold(0, |count, doc| -> Result<usize, PgError> {
        let row = row_of(doc)?;
        match table.entry(text(doc, "id")?) {
            Entry::Vacant(slot) => {
                slot.insert(row);
                Ok(count + 1)
            }
            Entry::Occupied(_taken) => Ok(count),
        }
    })?;
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


pub fn triage_statement(
    db: &Db,
    tenants: &BTreeMap<String, Table>,
    scope: &TenantScope,
    sql: &'static str,
    params: &[String],
) -> Result<Vec<Row>, PgError> {
    let tenant = tenant_of(scope).to_owned();
    let alert_id = params.first().ok_or_else(malformed)?.clone();
    let key = (tenant.clone(), alert_id.clone());
    let mut triage = lock(&db.triage);
    if sql == TRIAGE_GET_SQL {
        Ok(triage
            .get(&key)
            .map(|(status, actor, note, now, version)| vec![status.clone(), actor.clone(), note.clone(), now.to_string(), version.to_string()])
            .into_iter()
            .collect())
    } else if !tenants.get(&tenant).is_some_and(|table| table.contains_key(&alert_id)) {
        Ok(vec![vec!["0".to_owned(), String::new()]])
    } else {
        let now = params
            .get(NOW_PARAM)
            .ok_or_else(malformed)?
            .parse::<u64>()
            .map_err(|_source| malformed())?;
        let version = match (sql == TRIAGE_UPDATE_SQL, triage.get(&key)) {
            (false, None) => Some(1),
            (true, Some(current)) => {
                let read = params
                    .get(READ_PARAM)
                    .ok_or_else(malformed)?
                    .parse::<i64>()
                    .map_err(|_source| malformed())?;
                (current.4 == read).then_some(read + 1)
            }
            _other => None,
        };
        if let Some(next) = version {
            let row = (
                params.get(STATUS_PARAM).ok_or_else(malformed)?.clone(),
                params.get(ACTOR_PARAM).ok_or_else(malformed)?.clone(),
                params.get(NOTE_PARAM).ok_or_else(malformed)?.clone(),
                now,
                next,
            );
            triage.insert(key, row);
        }
        Ok(vec![vec!["1".to_owned(), version.map_or_else(String::new, |next| next.to_string())]])
    }
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
            } else if [TRIAGE_GET_SQL, TRIAGE_INSERT_SQL, TRIAGE_UPDATE_SQL].contains(&sql) {
                triage_statement(db, &tenants, scope, sql, params)
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
