use crate::error::CaseStoreError;
use crate::model::{Case, CaseStatus, Comment, Observable, Task};
use crate::observable::normalise_value;
use crate::stored::{AlertLinkItem, CaseCursor, CaseList, CasePage, Labels, LinkList, LinkPage, Parts, Stored};
use crate::transition::{apply_action, CaseAction};
use alerts::id::is_alert_id;
use alerts::types::{Executor, Row};
use core_pg::migrate::Migration;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::{json, Value};


pub const MIGRATION_NAMESPACE: &str = "cases";


pub const MIGRATIONS: [Migration; 2] = [
    Migration {
        version: "001_cases",
        sql: include_str!("../migrations/001_cases.sql"),
    },
    Migration {
        version: "002_link_attribution",
        sql: include_str!("../migrations/002_link_attribution.sql"),
    },
];


/// `$1` tenant, `$2` JSON document of the case; answers the id when the row is new.
pub const INSERT_SQL: &str = include_str!("../migrations/insert.sql");


/// `$2` case id, `$3` JSON `{status, resolution, updated_at, event, version}`, `$4` history cap; answers the new version, or nothing.
pub const APPLY_SQL: &str = include_str!("../migrations/apply.sql");


/// `$2` case id, `$3` comment JSON, `$4` cap; answers found, added, size.
pub const COMMENT_SQL: &str = include_str!("../migrations/comment.sql");


/// `$2` case id, `$3` observable JSON with its normalised value, `$4` cap; answers found, added, size.
pub const OBSERVABLE_SQL: &str = include_str!("../migrations/observable.sql");


/// `$2` case id, `$3` alert id, `$4` cap, `$5` now, `$6` actor; answers found case, found alert, added, linked, same.
pub const ATTACH_SQL: &str = include_str!("../migrations/attach.sql");


/// `$2` case id, `$3` page size; answers (case id, alert id, linked by, linked at; empty when unknown) rows of the case, so an empty page of an existing case is one row.
pub const LINKS_SQL: &str = include_str!("../migrations/links.sql");


/// `$2` case id, `$3` last alert id, `$4` page size; as `LINKS_SQL` after the cursor.
pub const LINKS_AFTER_SQL: &str = include_str!("../migrations/links_after.sql");


pub const FIRST_SQL: &str = "SELECT id, title, COALESCE(description, ''), severity, status, COALESCE(resolution, ''), COALESCE(assignee, ''), \
                             COALESCE(template, ''), COALESCE(case_type, ''), created_at::text, updated_at::text, version::text, tasks::text, \
                             observables::text, comments::text, history::text FROM cases WHERE tenant = $1 \
                             ORDER BY cases.created_at DESC, cases.id DESC LIMIT $2::text::bigint";


pub const NEXT_SQL: &str = "SELECT id, title, COALESCE(description, ''), severity, status, COALESCE(resolution, ''), COALESCE(assignee, ''), \
                            COALESCE(template, ''), COALESCE(case_type, ''), created_at::text, updated_at::text, version::text, tasks::text, \
                            observables::text, comments::text, history::text FROM cases WHERE tenant = $1 \
                            AND (created_at, id) < ($2::text::bigint, $3::text) \
                            ORDER BY cases.created_at DESC, cases.id DESC LIMIT $4::text::bigint";


pub const GET_SQL: &str = "SELECT id, title, COALESCE(description, ''), severity, status, COALESCE(resolution, ''), COALESCE(assignee, ''), \
                           COALESCE(template, ''), COALESCE(case_type, ''), created_at::text, updated_at::text, version::text, tasks::text, \
                           observables::text, comments::text, history::text FROM cases WHERE tenant = $1 AND id = $2::text";


/// Summary columns only (no description, comments, observables or history text): counts are `jsonb_array_length`, alert links a correlated count.
pub const FIRST_SUMMARY_SQL: &str = "SELECT id, title, severity, status, COALESCE(assignee, ''), COALESCE(case_type, ''), created_at::text, \
                                     updated_at::text, version::text, jsonb_array_length(tasks)::text, jsonb_array_length(observables)::text, \
                                     jsonb_array_length(comments)::text, jsonb_array_length(history)::text, \
                                     (SELECT count(*) FROM case_alerts WHERE case_alerts.tenant = cases.tenant AND case_alerts.case_id = cases.id)::text \
                                     FROM cases WHERE tenant = $1 ORDER BY cases.created_at DESC, cases.id DESC LIMIT $2::text::bigint";


pub const NEXT_SUMMARY_SQL: &str = "SELECT id, title, severity, status, COALESCE(assignee, ''), COALESCE(case_type, ''), created_at::text, \
                                    updated_at::text, version::text, jsonb_array_length(tasks)::text, jsonb_array_length(observables)::text, \
                                    jsonb_array_length(comments)::text, jsonb_array_length(history)::text, \
                                    (SELECT count(*) FROM case_alerts WHERE case_alerts.tenant = cases.tenant AND case_alerts.case_id = cases.id)::text \
                                    FROM cases WHERE tenant = $1 AND (created_at, id) < ($2::text::bigint, $3::text) \
                                    ORDER BY cases.created_at DESC, cases.id DESC LIMIT $4::text::bigint";


/// The summary columns, then description, resolution, template and the tasks text; comments, observables and history stay counts.
pub const DETAIL_SQL: &str = "SELECT id, title, severity, status, COALESCE(assignee, ''), COALESCE(case_type, ''), created_at::text, \
                              updated_at::text, version::text, jsonb_array_length(tasks)::text, jsonb_array_length(observables)::text, \
                              jsonb_array_length(comments)::text, jsonb_array_length(history)::text, \
                              (SELECT count(*) FROM case_alerts WHERE case_alerts.tenant = cases.tenant AND case_alerts.case_id = cases.id)::text, \
                              COALESCE(description, ''), COALESCE(resolution, ''), COALESCE(template, ''), tasks::text \
                              FROM cases WHERE tenant = $1 AND id = $2::text";


pub const NUL: char = '\0';


pub const MAX_ID_CHARS: usize = 128;


pub const MAX_TITLE_CHARS: usize = 256;


pub const MAX_NAME_CHARS: usize = 256;


pub const MAX_DESCRIPTION_CHARS: usize = 8_192;


pub const MAX_COMMENT_CHARS: usize = 8_192;


pub const MAX_OBSERVABLE_CHARS: usize = 2_048;


pub const MAX_TASKS: usize = 100;


pub const MAX_TASK_LOG: usize = 50;


pub const MAX_OBSERVABLES: usize = 500;


pub const MAX_COMMENTS: usize = 500;


pub const MAX_HISTORY: usize = 1_000;


pub const MAX_ALERTS_PER_CASE: usize = 1_000;


pub const MAX_PAGE_SIZE: usize = 100;


pub const ID_COLUMN: usize = 0;


pub const TITLE_COLUMN: usize = 1;


pub const DESCRIPTION_COLUMN: usize = 2;


pub const SEVERITY_COLUMN: usize = 3;


pub const STATUS_COLUMN: usize = 4;


pub const RESOLUTION_COLUMN: usize = 5;


pub const ASSIGNEE_COLUMN: usize = 6;


pub const TEMPLATE_COLUMN: usize = 7;


pub const TYPE_COLUMN: usize = 8;


pub const CREATED_COLUMN: usize = 9;


pub const UPDATED_COLUMN: usize = 10;


pub const VERSION_COLUMN: usize = 11;


pub const TASKS_COLUMN: usize = 12;


pub const OBSERVABLES_COLUMN: usize = 13;


pub const COMMENTS_COLUMN: usize = 14;


pub const HISTORY_COLUMN: usize = 15;


pub const SUMMARY_ID_COLUMN: usize = 0;


pub const SUMMARY_TITLE_COLUMN: usize = 1;


pub const SUMMARY_SEVERITY_COLUMN: usize = 2;


pub const SUMMARY_STATUS_COLUMN: usize = 3;


pub const SUMMARY_ASSIGNEE_COLUMN: usize = 4;


pub const SUMMARY_TYPE_COLUMN: usize = 5;


pub const SUMMARY_CREATED_COLUMN: usize = 6;


pub const SUMMARY_UPDATED_COLUMN: usize = 7;


pub const SUMMARY_VERSION_COLUMN: usize = 8;


pub const SUMMARY_TASKS_COLUMN: usize = 9;


pub const SUMMARY_OBSERVABLES_COLUMN: usize = 10;


pub const SUMMARY_COMMENTS_COLUMN: usize = 11;


pub const SUMMARY_HISTORY_COLUMN: usize = 12;


pub const SUMMARY_ALERTS_COLUMN: usize = 13;


pub const DETAIL_DESCRIPTION_COLUMN: usize = 14;


pub const DETAIL_RESOLUTION_COLUMN: usize = 15;


pub const DETAIL_TEMPLATE_COLUMN: usize = 16;


pub const DETAIL_TASKS_COLUMN: usize = 17;


pub const ADDED_COLUMN: usize = 1;


pub const SIZE_COLUMN: usize = 2;


pub const ALERT_FOUND_COLUMN: usize = 1;


pub const ATTACH_ADDED_COLUMN: usize = 2;


pub const ATTACH_LINKED_COLUMN: usize = 3;


pub const ATTACH_SAME_COLUMN: usize = 4;


pub const LINK_ALERT_COLUMN: usize = 1;


pub const LINK_BY_COLUMN: usize = 2;


pub const LINK_AT_COLUMN: usize = 3;


pub fn check_text(field: &'static str, value: &str, limit: usize) -> Result<(), CaseStoreError> {
    if value.is_empty() {
        Err(CaseStoreError::FieldEmpty { field })
    } else if value.chars().take(limit + 1).count() > limit {
        Err(CaseStoreError::FieldTooLong { field, limit })
    } else if value.contains(NUL) {
        Err(CaseStoreError::NulByte { field })
    } else {
        Ok(())
    }
}


pub fn check_optional(field: &'static str, value: Option<&str>, limit: usize) -> Result<(), CaseStoreError> {
    value.map_or(Ok(()), |text| check_text(field, text, limit))
}


pub fn check_time(field: &'static str, value: i64) -> Result<(), CaseStoreError> {
    if value < 0 {
        Err(CaseStoreError::BadTime { field })
    } else {
        Ok(())
    }
}


pub fn check_count(field: &'static str, count: usize, limit: usize) -> Result<(), CaseStoreError> {
    if count > limit {
        Err(CaseStoreError::TooMany { field, limit })
    } else {
        Ok(())
    }
}


pub fn check_task(task: &Task) -> Result<(), CaseStoreError> {
    check_text("task_title", &task.title, MAX_TITLE_CHARS)?;
    check_count("task_log", task.log.len(), MAX_TASK_LOG)?;
    task.log
        .iter()
        .try_for_each(|entry| check_text("task_actor", &entry.actor, MAX_NAME_CHARS))
}


/// Every bound is checked before any SQL; a new case is `new` and holds no observable, comment or history (they have their own statements).
pub fn check_case(scope: &TenantScope, case: &Case) -> Result<(), CaseStoreError> {
    if case.tenant != tenant_of(scope) {
        Err(CaseStoreError::TenantMismatch)
    } else if case.status != CaseStatus::New
        || case.resolution.is_some()
        || !case.observables.is_empty()
        || !case.comments.is_empty()
        || !case.history.is_empty()
    {
        Err(CaseStoreError::NotNew)
    } else {
        check_text("id", &case.id, MAX_ID_CHARS)?;
        check_text("title", &case.title, MAX_TITLE_CHARS)?;
        check_optional("description", case.description.as_deref(), MAX_DESCRIPTION_CHARS)?;
        check_optional("assignee", case.assignee.as_deref(), MAX_NAME_CHARS)?;
        check_optional("template", case.template.as_deref(), MAX_NAME_CHARS)?;
        check_optional("case_type", case.case_type.as_deref(), MAX_NAME_CHARS)?;
        check_time("created_at", case.created_at)?;
        check_time("updated_at", case.updated_at)?;
        check_count("tasks", case.tasks.len(), MAX_TASKS)?;
        case.tasks.iter().try_for_each(check_task)
    }
}


pub fn check_comment(comment: &Comment) -> Result<(), CaseStoreError> {
    check_text("author", &comment.author, MAX_NAME_CHARS)?;
    check_text("comment", &comment.text, MAX_COMMENT_CHARS)?;
    check_time("comment_at", comment.at)
}


/// The observable as it is stored: its value normalised, so the dedupe in SQL compares what `already_seen` compares.
pub fn checked_observable(observable: &Observable) -> Result<Value, CaseStoreError> {
    check_text("observable", &observable.value, MAX_OBSERVABLE_CHARS)?;
    check_text("source", &observable.source, MAX_NAME_CHARS)?;
    let value = normalise_value(observable.kind, &observable.value);
    check_text("observable", &value, MAX_OBSERVABLE_CHARS)?;
    Ok(json!({
        "kind": observable.kind,
        "value": value,
        "tlp": observable.tlp,
        "pap": observable.pap,
        "ioc": observable.ioc,
        "source": observable.source,
    }))
}


pub fn check_cursor(cursor: &CaseCursor) -> Result<(), CaseStoreError> {
    check_time("cursor_created_at", cursor.created_at)?;
    check_text("cursor_id", &cursor.id, MAX_ID_CHARS)
}


pub fn check_page(page: &CasePage) -> Result<(), CaseStoreError> {
    if page.size == 0 || page.size > MAX_PAGE_SIZE {
        Err(CaseStoreError::BadPageSize { limit: MAX_PAGE_SIZE })
    } else if let Some(cursor) = &page.after {
        check_cursor(cursor)
    } else {
        Ok(())
    }
}


/// `<created_at>.<id>`; the id may hold dots, the first one ends the numerals.
pub fn format_cursor(cursor: &CaseCursor) -> String {
    format!("{}.{}", cursor.created_at, cursor.id)
}


/// ASCII numerals that fit `i64`, then a bounded id without NUL: anything else is `BadCursor`, so no cursor text reaches SQL unchecked.
pub fn parse_cursor(text: &str) -> Result<CaseCursor, CaseStoreError> {
    let (numerals, id) = text.split_once('.').ok_or(CaseStoreError::BadCursor)?;
    let created_at = numerals
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| numerals.parse::<i64>().ok())
        .flatten()
        .ok_or(CaseStoreError::BadCursor)?;
    let cursor = CaseCursor {
        created_at,
        id: id.to_owned(),
    };
    check_cursor(&cursor).map_err(|_invalid| CaseStoreError::BadCursor)?;
    Ok(cursor)
}


pub fn case_doc(case: &Case) -> Value {
    json!({
        "id": case.id,
        "title": case.title,
        "description": case.description,
        "severity": case.severity,
        "status": case.status,
        "resolution": case.resolution,
        "assignee": case.assignee,
        "template": case.template,
        "case_type": case.case_type,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
        "tasks": case.tasks,
        "observables": case.observables,
        "comments": case.comments,
        "history": case.history,
    })
}


pub fn cell(row: &Row, column: usize) -> Result<&str, CaseStoreError> {
    row.get(column).map(String::as_str).ok_or(CaseStoreError::BadRow { column })
}


pub fn optional(row: &Row, column: usize) -> Result<Option<String>, CaseStoreError> {
    Ok(Some(cell(row, column)?).filter(|text| !text.is_empty()).map(str::to_owned))
}


pub fn number(row: &Row, column: usize) -> Result<i64, CaseStoreError> {
    cell(row, column)?
        .parse::<i64>()
        .map_err(|source| CaseStoreError::BadNumber { column, source })
}


pub fn count(row: &Row, column: usize) -> Result<usize, CaseStoreError> {
    cell(row, column)?
        .parse::<usize>()
        .map_err(|source| CaseStoreError::BadNumber { column, source })
}


pub fn case_from_row(scope: &TenantScope, row: &Row) -> Result<Stored, CaseStoreError> {
    let labels: Labels = serde_json::from_value(json!({
        "severity": cell(row, SEVERITY_COLUMN)?,
        "status": cell(row, STATUS_COLUMN)?,
        "resolution": optional(row, RESOLUTION_COLUMN)?,
    }))
    .map_err(CaseStoreError::BadLabels)?;
    let parts_text = format!(
        "{{\"tasks\":{},\"observables\":{},\"comments\":{},\"history\":{}}}",
        cell(row, TASKS_COLUMN)?,
        cell(row, OBSERVABLES_COLUMN)?,
        cell(row, COMMENTS_COLUMN)?,
        cell(row, HISTORY_COLUMN)?
    );
    let parts: Parts = serde_json::from_str(&parts_text).map_err(CaseStoreError::BadDocument)?;
    Ok(Stored {
        version: number(row, VERSION_COLUMN)?,
        case: Case {
            id: cell(row, ID_COLUMN)?.to_owned(),
            tenant: tenant_of(scope).to_owned(),
            title: cell(row, TITLE_COLUMN)?.to_owned(),
            description: optional(row, DESCRIPTION_COLUMN)?,
            severity: labels.severity,
            status: labels.status,
            resolution: labels.resolution,
            assignee: optional(row, ASSIGNEE_COLUMN)?,
            template: optional(row, TEMPLATE_COLUMN)?,
            case_type: optional(row, TYPE_COLUMN)?,
            created_at: number(row, CREATED_COLUMN)?,
            updated_at: number(row, UPDATED_COLUMN)?,
            tasks: parts.tasks,
            observables: parts.observables,
            comments: parts.comments,
            history: parts.history,
        },
    })
}


pub async fn create_case(exec: Executor<'_, '_>, scope: &TenantScope, case: &Case) -> Result<(), CaseStoreError> {
    check_case(scope, case)?;
    let rows = exec(scope.clone(), INSERT_SQL, vec![case_doc(case).to_string()]).await?;
    if rows.is_empty() {
        Err(CaseStoreError::Exists)
    } else {
        Ok(())
    }
}


pub async fn get_case(exec: Executor<'_, '_>, scope: &TenantScope, id: &str) -> Result<Option<Stored>, CaseStoreError> {
    check_text("id", id, MAX_ID_CHARS)?;
    let rows = exec(scope.clone(), GET_SQL, vec![id.to_owned()]).await?;
    rows.first().map(|row| case_from_row(scope, row)).transpose()
}


/// Newest first; the keyset is (created_at, id) and the page holds at most `MAX_PAGE_SIZE` cases.
pub async fn list_cases(exec: Executor<'_, '_>, scope: &TenantScope, page: &CasePage) -> Result<CaseList, CaseStoreError> {
    check_page(page)?;
    let fetch = (page.size + 1).to_string();
    let rows = match &page.after {
        None => exec(scope.clone(), FIRST_SQL, vec![fetch]).await?,
        Some(cursor) => exec(scope.clone(), NEXT_SQL, vec![cursor.created_at.to_string(), cursor.id.clone(), fetch]).await?,
    };
    let mut cases = rows
        .iter()
        .map(|row| case_from_row(scope, row))
        .collect::<Result<Vec<Stored>, CaseStoreError>>()?;
    let more = cases.len() > page.size;
    cases.truncate(page.size);
    let next = cases.last().filter(|_last| more).map(|last| CaseCursor {
        created_at: last.case.created_at,
        id: last.case.id.clone(),
    });
    Ok(CaseList { cases, next })
}


pub fn check_actor_and_time(actor: &str, now: i64) -> Result<(), CaseStoreError> {
    check_text("actor", actor, MAX_NAME_CHARS)?;
    check_time("now", now)
}


/// Applies the action to the snapshot and writes the case and its event in one statement guarded by the snapshot's version.
pub async fn apply_to_stored(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    stored: &Stored,
    action: CaseAction,
    actor: &str,
    now: i64,
) -> Result<Stored, CaseStoreError> {
    check_actor_and_time(actor, now)?;
    check_text("id", &stored.case.id, MAX_ID_CHARS)?;
    if stored.case.tenant != tenant_of(scope) {
        Err(CaseStoreError::TenantMismatch)
    } else if stored.case.history.len() >= MAX_HISTORY {
        Err(CaseStoreError::Full {
            what: "history",
            limit: MAX_HISTORY,
        })
    } else {
        let mut case = stored.case.clone();
        let event = apply_action(&mut case, action, actor, now)?;
        let change = json!({
            "status": case.status,
            "resolution": case.resolution,
            "updated_at": now,
            "event": event,
            "version": stored.version,
            "prior_status": stored.case.status,
        });
        let rows = exec(
            scope.clone(),
            APPLY_SQL,
            vec![stored.case.id.clone(), change.to_string(), MAX_HISTORY.to_string()],
        )
        .await?;
        let answer = rows.first().ok_or(CaseStoreError::Conflict)?;
        Ok(Stored {
            case,
            version: number(answer, 0)?,
        })
    }
}


/// Reads the case, then `apply_to_stored`: a change between the two is `Conflict`, never a lost update.
pub async fn apply_case_action(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    id: &str,
    action: CaseAction,
    actor: &str,
    now: i64,
) -> Result<Stored, CaseStoreError> {
    check_actor_and_time(actor, now)?;
    let stored = get_case(exec, scope, id).await?.ok_or(CaseStoreError::NotFound)?;
    apply_to_stored(exec, scope, &stored, action, actor, now).await
}


/// Runs an append statement; answers (added, size) or `NotFound`.
pub async fn append(exec: Executor<'_, '_>, scope: &TenantScope, sql: &'static str, params: Vec<String>) -> Result<(bool, usize), CaseStoreError> {
    let rows = exec(scope.clone(), sql, params).await?;
    let answer = rows.first().ok_or(CaseStoreError::BadRow { column: ID_COLUMN })?;
    if count(answer, ID_COLUMN)? == 0 {
        Err(CaseStoreError::NotFound)
    } else {
        Ok((count(answer, ADDED_COLUMN)? > 0, count(answer, SIZE_COLUMN)?))
    }
}


pub async fn add_comment(exec: Executor<'_, '_>, scope: &TenantScope, case_id: &str, comment: &Comment) -> Result<(), CaseStoreError> {
    check_text("id", case_id, MAX_ID_CHARS)?;
    check_comment(comment)?;
    let params = vec![case_id.to_owned(), json!(comment).to_string(), MAX_COMMENTS.to_string()];
    let (added, _size) = append(exec, scope, COMMENT_SQL, params).await?;
    if added {
        Ok(())
    } else {
        Err(CaseStoreError::Full {
            what: "comments",
            limit: MAX_COMMENTS,
        })
    }
}


/// `true` when added, `false` when the case already holds the same kind and normalised value.
pub async fn add_observable(exec: Executor<'_, '_>, scope: &TenantScope, case_id: &str, observable: &Observable) -> Result<bool, CaseStoreError> {
    check_text("id", case_id, MAX_ID_CHARS)?;
    let document = checked_observable(observable)?;
    let params = vec![case_id.to_owned(), document.to_string(), MAX_OBSERVABLES.to_string()];
    let (added, size) = append(exec, scope, OBSERVABLE_SQL, params).await?;
    if !added && size >= MAX_OBSERVABLES {
        Err(CaseStoreError::Full {
            what: "observables",
            limit: MAX_OBSERVABLES,
        })
    } else {
        Ok(added)
    }
}


/// Stores the alert id with its actor and time on the link row; the case and the alert must both exist in the scope's tenant. `true` when newly linked.
pub async fn attach_alert(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    case_id: &str,
    alert_id: &str,
    (actor, now): (&str, i64),
) -> Result<bool, CaseStoreError> {
    check_text("id", case_id, MAX_ID_CHARS)?;
    check_actor_and_time(actor, now)?;
    if !is_alert_id(alert_id) {
        Err(CaseStoreError::BadAlertId)
    } else {
        let params = vec![
            case_id.to_owned(),
            alert_id.to_owned(),
            MAX_ALERTS_PER_CASE.to_string(),
            now.to_string(),
            actor.to_owned(),
        ];
        let rows = exec(scope.clone(), ATTACH_SQL, params).await?;
        let answer = rows.first().ok_or(CaseStoreError::BadRow { column: ID_COLUMN })?;
        let added = count(answer, ATTACH_ADDED_COLUMN)? > 0;
        let already = count(answer, ATTACH_SAME_COLUMN)? > 0;
        if count(answer, ID_COLUMN)? == 0 {
            Err(CaseStoreError::NotFound)
        } else if count(answer, ALERT_FOUND_COLUMN)? == 0 {
            Err(CaseStoreError::AlertNotFound)
        } else if added || already {
            Ok(added)
        } else if count(answer, ATTACH_LINKED_COLUMN)? >= MAX_ALERTS_PER_CASE {
            Err(CaseStoreError::Full {
                what: "alerts",
                limit: MAX_ALERTS_PER_CASE,
            })
        } else {
            Ok(false)
        }
    }
}


/// An empty actor or time is a link written before the attribution columns existed: unknown.
pub fn link_of(row: &Row) -> Result<AlertLinkItem, CaseStoreError> {
    let linked_by = cell(row, LINK_BY_COLUMN)?;
    let linked_at = cell(row, LINK_AT_COLUMN)?;
    let at = if linked_at.is_empty() {
        None
    } else {
        Some(
            linked_at
                .parse::<i64>()
                .map_err(|_source| CaseStoreError::BadRow { column: LINK_AT_COLUMN })?,
        )
    };
    Ok(AlertLinkItem {
        alert_id: cell(row, LINK_ALERT_COLUMN)?.to_owned(),
        linked_by: (!linked_by.is_empty()).then(|| linked_by.to_owned()),
        linked_at: at,
    })
}


/// A page size of 1 to `MAX_PAGE_SIZE` and a cursor of 64 lowercase hexadecimal characters, or it is refused before any SQL.
pub fn check_link_page(page: &LinkPage) -> Result<(), CaseStoreError> {
    if page.size == 0 || page.size > MAX_PAGE_SIZE {
        Err(CaseStoreError::BadPageSize { limit: MAX_PAGE_SIZE })
    } else if page.after.as_deref().is_some_and(|alert_id| !is_alert_id(alert_id)) {
        Err(CaseStoreError::BadCursor)
    } else {
        Ok(())
    }
}


/// The alerts linked to the case with their attribution, in ascending alert id order; `NotFound` when the case is absent from the tenant.
pub async fn list_links(exec: Executor<'_, '_>, scope: &TenantScope, case_id: &str, page: &LinkPage) -> Result<LinkList, CaseStoreError> {
    check_text("id", case_id, MAX_ID_CHARS)?;
    check_link_page(page)?;
    let fetch = (page.size + 1).to_string();
    let rows = match &page.after {
        None => exec(scope.clone(), LINKS_SQL, vec![case_id.to_owned(), fetch]).await?,
        Some(after) => exec(scope.clone(), LINKS_AFTER_SQL, vec![case_id.to_owned(), after.clone(), fetch]).await?,
    };
    if rows.is_empty() {
        Err(CaseStoreError::NotFound)
    } else {
        let mut alerts = rows
            .iter()
            .map(link_of)
            .collect::<Result<Vec<AlertLinkItem>, CaseStoreError>>()?
            .into_iter()
            .filter(|link| !link.alert_id.is_empty())
            .collect::<Vec<AlertLinkItem>>();
        let more = alerts.len() > page.size;
        alerts.truncate(page.size);
        let next = alerts.last().filter(|_last| more).map(|last| last.alert_id.clone());
        Ok(LinkList { alerts, next })
    }
}
