use crate::types::Table;
use alerts::types::Row;
use cases::model::{Case, CaseEvent, CaseStatus, Comment, Observable};
use cases::store::{APPLY_SQL, ATTACH_SQL, COMMENT_SQL, GET_SQL, INSERT_SQL, NEXT_SQL, OBSERVABLE_SQL};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};


pub const CAP_INDEX: usize = 2;


pub enum Forced {
    Fail,
    Rows(Vec<Row>),
}


pub struct Entry {
    pub case: Case,
    pub version: i64,
    pub alerts: BTreeSet<String>,
}


#[derive(Default)]
pub struct Db {
    pub tenants: Mutex<BTreeMap<String, Table>>,
    pub known_alerts: Mutex<BTreeMap<String, BTreeSet<String>>>,
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


pub fn text(value: Option<&str>) -> String {
    value.map_or_else(String::new, str::to_owned)
}


pub fn label(value: &Value) -> String {
    value.as_str().map_or_else(String::new, str::to_owned)
}


pub fn row_of(entry: &Entry) -> Result<Row, PgError> {
    let case = &entry.case;
    let json = |value: Result<Value, serde_json::Error>| value.map(|doc| doc.to_string()).map_err(|_source| malformed());
    let resolution = case.resolution.map_or(Ok(String::new()), |found| {
        serde_json::to_value(found).map(|doc| label(&doc)).map_err(|_source| malformed())
    })?;
    Ok(vec![
        case.id.clone(),
        case.title.clone(),
        text(case.description.as_deref()),
        label(&serde_json::to_value(case.severity).map_err(|_source| malformed())?),
        label(&serde_json::to_value(case.status).map_err(|_source| malformed())?),
        resolution,
        text(case.assignee.as_deref()),
        text(case.template.as_deref()),
        text(case.case_type.as_deref()),
        case.created_at.to_string(),
        case.updated_at.to_string(),
        entry.version.to_string(),
        json(serde_json::to_value(&case.tasks))?,
        json(serde_json::to_value(&case.observables))?,
        json(serde_json::to_value(&case.comments))?,
        json(serde_json::to_value(&case.history))?,
    ])
}


pub fn insert(table: &mut Table, tenant: &str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let mut doc: Value = serde_json::from_str(param(params, 0)?).map_err(|_source| malformed())?;
    doc.as_object_mut()
        .ok_or_else(malformed)?
        .insert("tenant".to_owned(), Value::String(tenant.to_owned()));
    let case: Case = serde_json::from_value(doc).map_err(|_source| malformed())?;
    if table.contains_key(&case.id) {
        Ok(Vec::new())
    } else {
        let id = case.id.clone();
        table.insert(
            id.clone(),
            Entry {
                case,
                version: 1,
                alerts: BTreeSet::new(),
            },
        );
        Ok(vec![vec![id]])
    }
}


pub fn select(table: &Table, sql: &str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let limit = param(params, params.len().saturating_sub(1))?
        .parse::<usize>()
        .map_err(|_source| malformed())?;
    let cursor = if sql == NEXT_SQL {
        Some((
            param(params, 0)?.parse::<i64>().map_err(|_source| malformed())?,
            param(params, 1)?.clone(),
        ))
    } else {
        None
    };
    let mut entries: Vec<&Entry> = table.values().collect();
    entries.sort_by(|left, right| (right.case.created_at, &right.case.id).cmp(&(left.case.created_at, &left.case.id)));
    entries
        .into_iter()
        .filter(|entry| {
            cursor
                .as_ref()
                .is_none_or(|position| (entry.case.created_at, entry.case.id.clone()) < *position)
        })
        .take(limit)
        .map(row_of)
        .collect()
}


pub fn apply(table: &mut Table, params: &[String]) -> Result<Vec<Row>, PgError> {
    let change: Value = serde_json::from_str(param(params, 1)?).map_err(|_source| malformed())?;
    let cap = param(params, CAP_INDEX)?.parse::<usize>().map_err(|_source| malformed())?;
    let version = change.get("version").and_then(Value::as_i64).ok_or_else(malformed)?;
    let prior: CaseStatus = serde_json::from_value(change.get("prior_status").cloned().ok_or_else(malformed)?).map_err(|_source| malformed())?;
    match table.get_mut(param(params, 0)?) {
        Some(entry) if entry.version == version && entry.case.status == prior && entry.case.history.len() < cap => {
            let event: CaseEvent = serde_json::from_value(change.get("event").cloned().ok_or_else(malformed)?).map_err(|_source| malformed())?;
            entry.case.status = serde_json::from_value(change.get("status").cloned().ok_or_else(malformed)?).map_err(|_source| malformed())?;
            entry.case.resolution =
                serde_json::from_value(change.get("resolution").cloned().ok_or_else(malformed)?).map_err(|_source| malformed())?;
            entry.case.updated_at = change.get("updated_at").and_then(Value::as_i64).ok_or_else(malformed)?;
            entry.case.history.push(event);
            entry.version += 1;
            Ok(vec![vec![entry.version.to_string()]])
        }
        _ => Ok(Vec::new()),
    }
}


pub fn answer(found: bool, added: bool, size: usize) -> Vec<Row> {
    vec![vec![usize::from(found).to_string(), usize::from(added).to_string(), size.to_string()]]
}


pub fn comment(table: &mut Table, params: &[String]) -> Result<Vec<Row>, PgError> {
    let cap = param(params, CAP_INDEX)?.parse::<usize>().map_err(|_source| malformed())?;
    let new: Comment = serde_json::from_str(param(params, 1)?).map_err(|_source| malformed())?;
    Ok(match table.get_mut(param(params, 0)?) {
        Some(entry) => {
            let size = entry.case.comments.len();
            if size < cap {
                entry.case.comments.push(new);
            }
            answer(true, size < cap, size)
        }
        None => answer(false, false, 0),
    })
}


pub fn observable(table: &mut Table, params: &[String]) -> Result<Vec<Row>, PgError> {
    let cap = param(params, CAP_INDEX)?.parse::<usize>().map_err(|_source| malformed())?;
    let new: Observable = serde_json::from_str(param(params, 1)?).map_err(|_source| malformed())?;
    Ok(match table.get_mut(param(params, 0)?) {
        Some(entry) => {
            let size = entry.case.observables.len();
            let fresh = size < cap && !entry.case.observables.iter().any(|seen| seen.kind == new.kind && seen.value == new.value);
            if fresh {
                entry.case.observables.push(new);
            }
            answer(true, fresh, size)
        }
        None => answer(false, false, 0),
    })
}


pub fn attach(table: &mut Table, known: &BTreeSet<String>, params: &[String]) -> Result<Vec<Row>, PgError> {
    let cap = param(params, CAP_INDEX)?.parse::<usize>().map_err(|_source| malformed())?;
    let alert = param(params, 1)?;
    let alert_found = known.contains(alert);
    Ok(match table.get_mut(param(params, 0)?) {
        Some(entry) => {
            let linked = entry.alerts.len();
            let added = alert_found && linked < cap && entry.alerts.insert(alert.clone());
            vec![vec![
                "1".to_owned(),
                usize::from(alert_found).to_string(),
                usize::from(added).to_string(),
                linked.to_string(),
            ]]
        }
        None => vec![vec!["0".to_owned(), usize::from(alert_found).to_string(), "0".to_owned(), "0".to_owned()]],
    })
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
            let known = lock(&db.known_alerts).get(tenant_of(scope)).map_or_else(BTreeSet::new, Clone::clone);
            let table = tenants.entry(tenant_of(scope).to_owned()).or_default();
            if sql == INSERT_SQL {
                insert(table, tenant_of(scope), params)
            } else if sql == GET_SQL {
                table.get(param(params, 0)?).map(row_of).transpose().map(|row| row.into_iter().collect())
            } else if sql == APPLY_SQL {
                apply(table, params)
            } else if sql == COMMENT_SQL {
                comment(table, params)
            } else if sql == OBSERVABLE_SQL {
                observable(table, params)
            } else if sql == ATTACH_SQL {
                attach(table, &known, params)
            } else {
                select(table, sql, params)
            }
        }
    }
}
