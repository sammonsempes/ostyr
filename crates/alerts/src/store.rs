use crate::error::StoreError;
use crate::id::{alert_id, is_alert_id};
use crate::model::{Alert, AlertPage, Cursor, Page, Severity, Summary, SEVERITY_COLUMN};
use crate::types::{Executor, Row};
use core_pg::migrate::Migration;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::{json, Value};
use std::cmp::Ordering;


pub const MIGRATION_NAMESPACE: &str = "alerts";


pub const MIGRATIONS: [Migration; 1] = [Migration {
    version: "001_alerts",
    sql: include_str!("../migrations/001_alerts.sql"),
}];


/// One statement (one implicit transaction): `$1` tenant, `$2` JSON array of alerts; answers the number of rows that were new.
pub const INSERT_SQL: &str = include_str!("../migrations/insert.sql");


pub const FIRST_SQL: &str = "SELECT id, rule_id, rule_title, severity, event_time, created::text, COALESCE(host_name, ''), COALESCE(user_name, ''), \
                             event_ids::text, summary, summary_truncated::text, summary_original_bytes::text FROM alerts WHERE tenant = $1 \
                             ORDER BY created DESC, id DESC LIMIT $2::text::bigint";


pub const NEXT_SQL: &str = "SELECT id, rule_id, rule_title, severity, event_time, created::text, COALESCE(host_name, ''), COALESCE(user_name, ''), \
                            event_ids::text, summary, summary_truncated::text, summary_original_bytes::text FROM alerts WHERE tenant = $1 \
                            AND (created, id) < ($2::text::bigint, $3::text) ORDER BY created DESC, id DESC LIMIT $4::text::bigint";


pub const GET_SQL: &str = "SELECT id, rule_id, rule_title, severity, event_time, created::text, COALESCE(host_name, ''), COALESCE(user_name, ''), \
                           event_ids::text, summary, summary_truncated::text, summary_original_bytes::text FROM alerts WHERE tenant = $1 \
                           AND id = $2::text";


pub const NUL: char = '\0';


pub const MAX_ALERTS_PER_INSERT: usize = 500;


pub const MAX_PAGE_SIZE: usize = 100;


pub const MAX_RULE_ID_CHARS: usize = 128;


pub const MAX_TITLE_CHARS: usize = 256;


pub const MAX_ENTITY_CHARS: usize = 256;


pub const MAX_EVENT_TIME_CHARS: usize = 64;


pub const MAX_EVENT_ID_CHARS: usize = 128;


pub const MAX_EVENT_IDS: usize = 100;


pub const MAX_SUMMARY_BYTES: usize = 8_192;


pub const MAX_CREATED_MICROS: u64 = i64::MAX as u64;


pub const ID_COLUMN: usize = 0;


pub const RULE_ID_COLUMN: usize = 1;


pub const TITLE_COLUMN: usize = 2;


pub const EVENT_TIME_COLUMN: usize = 4;


pub const CREATED_COLUMN: usize = 5;


pub const HOST_COLUMN: usize = 6;


pub const USER_COLUMN: usize = 7;


pub const EVENT_IDS_COLUMN: usize = 8;


pub const SUMMARY_COLUMN: usize = 9;


pub const TRUNCATED_COLUMN: usize = 10;


pub const ORIGINAL_BYTES_COLUMN: usize = 11;


/// The summary as JSON text, cut at `MAX_SUMMARY_BYTES` on a character boundary, with a flag and the uncut size.
pub fn summarise(value: &Value) -> Summary {
    let mut text = value.to_string();
    let original_bytes = text.len() as u64;
    let limit = text.len().min(MAX_SUMMARY_BYTES);
    let cut = text
        .char_indices()
        .map(|(index, _character)| index)
        .chain(std::iter::once(text.len()))
        .take_while(|index| *index <= limit)
        .fold(0, |_previous, index| index);
    text.truncate(cut);
    Summary {
        truncated: text.len() as u64 != original_bytes,
        text,
        original_bytes,
    }
}


pub fn check_text(field: &'static str, value: &str, limit: usize) -> Result<(), StoreError> {
    if value.is_empty() {
        Err(StoreError::FieldEmpty { field })
    } else if value.contains(NUL) {
        Err(StoreError::NulByte { field })
    } else if value.chars().take(limit + 1).count() > limit {
        Err(StoreError::FieldTooLong { field, limit })
    } else {
        Ok(())
    }
}


pub fn check_optional(field: &'static str, value: Option<&str>, limit: usize) -> Result<(), StoreError> {
    value.map_or(Ok(()), |text| check_text(field, text, limit))
}


pub fn check_events(event_ids: &[String]) -> Result<(), StoreError> {
    if event_ids.is_empty() || event_ids.len() > MAX_EVENT_IDS {
        Err(StoreError::BadEventCount { limit: MAX_EVENT_IDS })
    } else {
        event_ids
            .iter()
            .try_for_each(|event_id| check_text("event_id", event_id, MAX_EVENT_ID_CHARS))
    }
}


pub fn check_summary(summary: &Summary) -> Result<(), StoreError> {
    if summary.text.contains(NUL) {
        Err(StoreError::NulByte { field: "summary" })
    } else if summary.text.len() > MAX_SUMMARY_BYTES {
        Err(StoreError::FieldTooLong {
            field: "summary",
            limit: MAX_SUMMARY_BYTES,
        })
    } else {
        let consistent = match summary.original_bytes.cmp(&(summary.text.len() as u64)) {
            Ordering::Less => false,
            Ordering::Equal => !summary.truncated,
            Ordering::Greater => summary.truncated,
        };
        if consistent {
            Ok(())
        } else {
            Err(StoreError::BadSummary)
        }
    }
}


/// Every bound is checked here, before any SQL is sent; the id must be the one derived from the tenant, rule and events.
pub fn check_alert(scope: &TenantScope, alert: &Alert) -> Result<(), StoreError> {
    if alert.tenant != tenant_of(scope) {
        Err(StoreError::TenantMismatch)
    } else {
        check_text("rule_id", &alert.rule_id, MAX_RULE_ID_CHARS)?;
        check_text("rule_title", &alert.rule_title, MAX_TITLE_CHARS)?;
        check_text("event_time", &alert.event_time, MAX_EVENT_TIME_CHARS)?;
        check_optional("host_name", alert.host_name.as_deref(), MAX_ENTITY_CHARS)?;
        check_optional("user_name", alert.user_name.as_deref(), MAX_ENTITY_CHARS)?;
        check_events(&alert.event_ids)?;
        check_summary(&alert.summary)?;
        if alert.created_micros > MAX_CREATED_MICROS {
            Err(StoreError::BadCreated)
        } else if alert.id != alert_id(&alert.tenant, &alert.rule_id, &alert.event_ids) {
            Err(StoreError::IdMismatch)
        } else {
            Ok(())
        }
    }
}


pub fn alert_doc(alert: &Alert) -> Value {
    json!({
        "id": alert.id,
        "rule_id": alert.rule_id,
        "rule_title": alert.rule_title,
        "severity": alert.severity.to_string(),
        "event_time": alert.event_time,
        "created": alert.created_micros,
        "host_name": alert.host_name,
        "user_name": alert.user_name,
        "event_ids": alert.event_ids,
        "summary": alert.summary.text,
        "summary_truncated": alert.summary.truncated,
        "summary_original_bytes": alert.summary.original_bytes,
    })
}


pub fn cell(row: &Row, column: usize) -> Result<&str, StoreError> {
    row.get(column).map(String::as_str).ok_or(StoreError::BadRow { column })
}


pub fn number(row: &Row, column: usize) -> Result<u64, StoreError> {
    cell(row, column)?.parse().map_err(|source| StoreError::BadNumber { column, source })
}


pub fn flag(row: &Row, column: usize) -> Result<bool, StoreError> {
    match cell(row, column)? {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(StoreError::BadRow { column }),
    }
}


pub fn entity(row: &Row, column: usize) -> Result<Option<String>, StoreError> {
    let text = cell(row, column)?;
    Ok((!text.is_empty()).then(|| text.to_owned()))
}


/// The tenant comes from the scope the query ran under, never from a column.
pub fn alert_from_row(scope: &TenantScope, row: &Row) -> Result<Alert, StoreError> {
    Ok(Alert {
        id: cell(row, ID_COLUMN)?.to_owned(),
        tenant: tenant_of(scope).to_owned(),
        rule_id: cell(row, RULE_ID_COLUMN)?.to_owned(),
        rule_title: cell(row, TITLE_COLUMN)?.to_owned(),
        severity: cell(row, SEVERITY_COLUMN)?.parse::<Severity>()?,
        event_time: cell(row, EVENT_TIME_COLUMN)?.to_owned(),
        created_micros: number(row, CREATED_COLUMN)?,
        host_name: entity(row, HOST_COLUMN)?,
        user_name: entity(row, USER_COLUMN)?,
        event_ids: serde_json::from_str(cell(row, EVENT_IDS_COLUMN)?).map_err(StoreError::BadEvents)?,
        summary: Summary {
            text: cell(row, SUMMARY_COLUMN)?.to_owned(),
            truncated: flag(row, TRUNCATED_COLUMN)?,
            original_bytes: number(row, ORIGINAL_BYTES_COLUMN)?,
        },
    })
}


pub fn check_id(id: &str) -> Result<(), StoreError> {
    if is_alert_id(id) {
        Ok(())
    } else {
        Err(StoreError::BadId)
    }
}


pub fn check_cursor(cursor: &Cursor) -> Result<(), StoreError> {
    check_id(&cursor.id).map_err(|_bad_id| StoreError::BadCursor)?;
    if cursor.created_micros > MAX_CREATED_MICROS {
        Err(StoreError::BadCursor)
    } else {
        Ok(())
    }
}


pub fn format_cursor(cursor: &Cursor) -> String {
    format!("{}.{}", cursor.created_micros, cursor.id)
}


/// `<created microseconds>.<alert id>`; a negative, overflowing or malformed value is refused.
pub fn parse_cursor(text: &str) -> Result<Cursor, StoreError> {
    let (created, id) = text.split_once('.').ok_or(StoreError::BadCursor)?;
    let created_micros = created.parse::<u64>().map_err(|_malformed| StoreError::BadCursor)?;
    let cursor = Cursor {
        created_micros,
        id: id.to_owned(),
    };
    check_cursor(&cursor)?;
    Ok(cursor)
}


pub fn check_page(page: &Page) -> Result<(), StoreError> {
    if page.size == 0 || page.size > MAX_PAGE_SIZE {
        Err(StoreError::BadPageSize { limit: MAX_PAGE_SIZE })
    } else {
        page.after.as_ref().map_or(Ok(()), check_cursor)
    }
}


/// Inserts the alerts under the scope's tenant, idempotently on (tenant, id), and returns how many were new.
pub async fn insert_alerts(exec: Executor<'_, '_>, scope: &TenantScope, alerts: &[Alert]) -> Result<usize, StoreError> {
    if alerts.len() > MAX_ALERTS_PER_INSERT {
        Err(StoreError::TooManyAlerts {
            limit: MAX_ALERTS_PER_INSERT,
        })
    } else {
        alerts.iter().try_for_each(|alert| check_alert(scope, alert))?;
        if alerts.is_empty() {
            Ok(0)
        } else {
            let docs: Vec<Value> = alerts.iter().map(alert_doc).collect();
            let document = serde_json::to_string(&docs).map_err(StoreError::Document)?;
            let rows = exec(scope.clone(), INSERT_SQL, vec![document]).await?;
            let answer = rows.first().ok_or(StoreError::BadRow { column: 0 })?;
            cell(answer, 0)?
                .parse::<usize>()
                .map_err(|source| StoreError::BadNumber { column: 0, source })
        }
    }
}


/// Newest first; the keyset is (created, id) and the page holds at most `MAX_PAGE_SIZE` alerts.
pub async fn list_alerts(exec: Executor<'_, '_>, scope: &TenantScope, page: &Page) -> Result<AlertPage, StoreError> {
    check_page(page)?;
    let fetch = (page.size + 1).to_string();
    let rows = match &page.after {
        None => exec(scope.clone(), FIRST_SQL, vec![fetch]).await?,
        Some(cursor) => exec(scope.clone(), NEXT_SQL, vec![cursor.created_micros.to_string(), cursor.id.clone(), fetch]).await?,
    };
    let mut alerts = rows
        .iter()
        .map(|row| alert_from_row(scope, row))
        .collect::<Result<Vec<Alert>, StoreError>>()?;
    let more = alerts.len() > page.size;
    alerts.truncate(page.size);
    let next = alerts.last().filter(|_last| more).map(|last| Cursor {
        created_micros: last.created_micros,
        id: last.id.clone(),
    });
    Ok(AlertPage { alerts, next })
}


pub async fn get_alert(exec: Executor<'_, '_>, scope: &TenantScope, id: &str) -> Result<Option<Alert>, StoreError> {
    check_id(id)?;
    let rows = exec(scope.clone(), GET_SQL, vec![id.to_owned()]).await?;
    rows.first().map(|row| alert_from_row(scope, row)).transpose()
}
