use crate::error::StoreError;
use crate::model::{IncidentInput, IncidentUpdateInput};
use crate::store_model::{Cell, IncidentRef, NewIncident, Param, Statement};
use crate::types::Row;
use core_pg::migrate::Migration;
use core_pg::scope::{tenant_of, TenantScope};
use std::collections::BTreeMap;
use std::future::Future;


pub const MIGRATION_NAMESPACE: &str = "status_page";


pub const MIGRATIONS: [Migration; 1] = [Migration {
    version: "status_0001",
    sql: include_str!("../migrations/status_0001.sql"),
}];


pub const MAX_PUBLISHED: u32 = 500;


pub const MAX_UPDATES_PER_INCIDENT: i64 = 100;


pub const MAX_SERVICE_CHARACTERS: usize = 128;


pub const MAX_TITLE_CHARACTERS: usize = 200;


pub const MAX_MESSAGE_CHARACTERS: usize = 500;


pub const MAX_NOTE_CHARACTERS: usize = 2000;


pub const COL_ID: usize = 0;


pub const COL_VERSION: usize = 1;


pub const COL_SERVICE: usize = 1;


pub const COL_TITLE: usize = 2;


pub const COL_STARTED_AT: usize = 3;


pub const COL_RESOLVED_AT: usize = 4;


pub const COL_UPDATE_AT: usize = 1;


pub const COL_UPDATE_MESSAGE: usize = 2;


/// Params: `$2` service, `$3` title, `$4` published, `$5` started_at, `$6` internal note.
pub const CREATE_SQL: &str = "INSERT INTO status_incidents (tenant, service, public_title, published, started_at, internal_note) \
    VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, version";


/// Params: `$2` id, `$3` version, `$4` at, `$5` message, `$6` note, `$7` update limit; no row on a foreign id, stale version or full list.
pub const UPDATE_SQL: &str = "WITH bumped AS (UPDATE status_incidents SET version = version + 1 \
    WHERE tenant = $1 AND id = $2 AND version = $3 \
    AND (SELECT count(*) FROM status_incident_updates WHERE tenant = $1 AND incident = $2) < $7 RETURNING id, version) \
    INSERT INTO status_incident_updates (tenant, incident, at, message, internal_note) \
    SELECT $1::text, id, $4::bigint, $5::text, $6::text FROM bumped RETURNING incident, (SELECT version FROM bumped)";


/// Params: `$2` id, `$3` expected version, `$4` resolved_at.
pub const RESOLVE_SQL: &str = "UPDATE status_incidents SET resolved_at = $4, version = version + 1 \
    WHERE tenant = $1 AND id = $2 AND version = $3 AND resolved_at IS NULL RETURNING id, version";


/// Params: `$2` limit. No internal note or assignee column is selected.
pub const PUBLISHED_SQL: &str = "SELECT id, service, public_title, started_at, resolved_at FROM status_incidents \
    WHERE tenant = $1 AND published ORDER BY started_at DESC, id DESC LIMIT $2";


/// Params: `$2` limit, the same one as `PUBLISHED_SQL`. No internal note column is selected.
pub const UPDATES_SQL: &str = "SELECT incident, at, message FROM status_incident_updates WHERE tenant = $1 AND incident IN \
    (SELECT id FROM status_incidents WHERE tenant = $1 AND published ORDER BY started_at DESC, id DESC LIMIT $2) ORDER BY incident, at, seq";


pub fn is_refused(character: char, multiline: bool) -> bool {
    character.is_control() && !(multiline && character == '\n')
}


/// Bounded in characters, refused rather than cut; a control character is refused (a line break only where `multiline`).
pub fn check_text(field: &'static str, text: &str, max: usize, multiline: bool) -> Result<(), StoreError> {
    if text.chars().count() > max {
        Err(StoreError::TextTooLong { field, limit: max })
    } else if text.chars().any(|character| is_refused(character, multiline)) {
        Err(StoreError::TextInvalid { field })
    } else {
        Ok(())
    }
}


pub fn check_required(field: &'static str, text: &str, max: usize, multiline: bool) -> Result<(), StoreError> {
    if text.trim().is_empty() {
        Err(StoreError::TextInvalid { field })
    } else {
        check_text(field, text, max, multiline)
    }
}


pub async fn run<Executor, Pending>(exec: &mut Executor, scope: &TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<Row>, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    exec(scope, Statement { sql, params }).await
}


pub fn cell<'row>(row: &'row Row, index: usize, column: &'static str) -> Result<&'row Cell, StoreError> {
    row.get(index).ok_or(StoreError::BadRow { column })
}


pub fn cell_int(row: &Row, index: usize, column: &'static str) -> Result<i64, StoreError> {
    match cell(row, index, column)? {
        Cell::Int(value) => Ok(*value),
        _ => Err(StoreError::BadRow { column }),
    }
}


pub fn cell_text(row: &Row, index: usize, column: &'static str) -> Result<String, StoreError> {
    match cell(row, index, column)? {
        Cell::Text(value) => Ok(value.clone()),
        _ => Err(StoreError::BadRow { column }),
    }
}


pub fn cell_optional_int(row: &Row, index: usize, column: &'static str) -> Result<Option<i64>, StoreError> {
    match cell(row, index, column)? {
        Cell::Int(value) => Ok(Some(*value)),
        Cell::Null => Ok(None),
        Cell::Text(_) => Err(StoreError::BadRow { column }),
    }
}


/// Columns: id, version.
pub fn decode_ref(rows: &[Row]) -> Result<IncidentRef, StoreError> {
    let row = rows.first().ok_or(StoreError::BadRow { column: "id" })?;
    Ok(IncidentRef {
        id: cell_int(row, COL_ID, "id")?,
        version: cell_int(row, COL_VERSION, "version")?,
    })
}


/// A write that changed no row: not the tenant's incident, a stale version, or the update limit.
pub fn decode_changed(rows: &[Row]) -> Result<IncidentRef, StoreError> {
    if rows.is_empty() {
        Err(StoreError::Conflict)
    } else {
        decode_ref(rows)
    }
}


pub async fn create_incident<Executor, Pending>(exec: &mut Executor, scope: &TenantScope, incident: &NewIncident) -> Result<IncidentRef, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    check_required("service", &incident.service, MAX_SERVICE_CHARACTERS, false)?;
    check_required("title", &incident.title, MAX_TITLE_CHARACTERS, false)?;
    check_text("internal_note", &incident.internal_note, MAX_NOTE_CHARACTERS, true)?;
    let params = vec![
        Param::Text(incident.service.clone()),
        Param::Text(incident.title.clone()),
        Param::Bool(incident.published),
        Param::Int(incident.started_at),
        Param::Text(incident.internal_note.clone()),
    ];
    decode_ref(&run(exec, scope, CREATE_SQL, params).await?)
}


/// Appends an update and bumps the version in one statement; a stale `incident.version` is `Conflict`.
pub async fn add_update<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    incident: IncidentRef,
    at: i64,
    message: &str,
    internal_note: &str,
) -> Result<IncidentRef, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    check_required("message", message, MAX_MESSAGE_CHARACTERS, true)?;
    check_text("internal_note", internal_note, MAX_NOTE_CHARACTERS, true)?;
    let params = vec![
        Param::Int(incident.id),
        Param::Int(incident.version),
        Param::Int(at),
        Param::Text(message.to_owned()),
        Param::Text(internal_note.to_owned()),
        Param::Int(MAX_UPDATES_PER_INCIDENT),
    ];
    let rows = run(exec, scope, UPDATE_SQL, params).await?;
    decode_changed(&rows)
}


/// Sets `resolved_at` once; a resolved incident or a stale version is `Conflict`.
pub async fn resolve_incident<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    incident: IncidentRef,
    at: i64,
) -> Result<IncidentRef, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let params = vec![Param::Int(incident.id), Param::Int(incident.version), Param::Int(at)];
    decode_changed(&run(exec, scope, RESOLVE_SQL, params).await?)
}


pub fn group_updates(rows: &[Row]) -> Result<BTreeMap<i64, Vec<IncidentUpdateInput>>, StoreError> {
    rows.iter()
        .try_fold(BTreeMap::new(), |mut grouped: BTreeMap<i64, Vec<IncidentUpdateInput>>, row| {
            grouped.entry(cell_int(row, COL_ID, "incident")?).or_default().push(IncidentUpdateInput {
                at: cell_int(row, COL_UPDATE_AT, "at")?,
                message: cell_text(row, COL_UPDATE_MESSAGE, "message")?,
                internal_note: String::new(),
            });
            Ok(grouped)
        })
}


/// The internal note, assignee, assets and addresses are never selected: they come back empty.
pub fn decode_incident(tenant: &str, row: &Row, grouped: &BTreeMap<i64, Vec<IncidentUpdateInput>>) -> Result<IncidentInput, StoreError> {
    let id = cell_int(row, COL_ID, "id")?;
    Ok(IncidentInput {
        tenant: tenant.to_owned(),
        service: cell_text(row, COL_SERVICE, "service")?,
        published: true,
        public_title: cell_text(row, COL_TITLE, "public_title")?,
        started_at: cell_int(row, COL_STARTED_AT, "started_at")?,
        resolved_at: cell_optional_int(row, COL_RESOLVED_AT, "resolved_at")?,
        updates: grouped.get(&id).map_or_else(Vec::new, Clone::clone),
        internal_note: String::new(),
        assignee: String::new(),
        asset_ids: Vec::new(),
        addresses: Vec::new(),
    })
}


/// The newest published incidents of the tenant, at most `limit` (itself at most `MAX_PUBLISHED`), ready for `render`.
pub async fn published_incidents<Executor, Pending>(exec: &mut Executor, scope: &TenantScope, limit: u32) -> Result<Vec<IncidentInput>, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    if limit == 0 || limit > MAX_PUBLISHED {
        Err(StoreError::LimitOutOfRange { limit, max: MAX_PUBLISHED })
    } else {
        let incidents = run(exec, scope, PUBLISHED_SQL, vec![Param::Int(i64::from(limit))]).await?;
        let updates = run(exec, scope, UPDATES_SQL, vec![Param::Int(i64::from(limit))]).await?;
        let grouped = group_updates(&updates)?;
        incidents.iter().map(|row| decode_incident(tenant_of(scope), row, &grouped)).collect()
    }
}
