use crate::error::CaseStoreError;
use crate::model::Resolution;
use crate::store::{
    cell, check_page, check_text, count, number, optional, DETAIL_DESCRIPTION_COLUMN, DETAIL_RESOLUTION_COLUMN, DETAIL_SQL, DETAIL_TASKS_COLUMN,
    DETAIL_TEMPLATE_COLUMN, FIRST_SUMMARY_SQL, MAX_ID_CHARS, NEXT_SUMMARY_SQL, SUMMARY_ALERTS_COLUMN, SUMMARY_ASSIGNEE_COLUMN,
    SUMMARY_COMMENTS_COLUMN, SUMMARY_CREATED_COLUMN, SUMMARY_HISTORY_COLUMN, SUMMARY_ID_COLUMN, SUMMARY_OBSERVABLES_COLUMN, SUMMARY_SEVERITY_COLUMN,
    SUMMARY_STATUS_COLUMN, SUMMARY_TASKS_COLUMN, SUMMARY_TITLE_COLUMN, SUMMARY_TYPE_COLUMN, SUMMARY_UPDATED_COLUMN, SUMMARY_VERSION_COLUMN,
};
use crate::stored::{CaseCounts, CaseCursor, CaseDetail, CasePage, CaseSummary, Labels, SummaryList};
use alerts::types::{Executor, Row};
use core_pg::scope::TenantScope;
use serde_json::{json, Value};


pub fn summary_from_row(row: &Row) -> Result<CaseSummary, CaseStoreError> {
    let labels: Labels = serde_json::from_value(json!({
        "severity": cell(row, SUMMARY_SEVERITY_COLUMN)?,
        "status": cell(row, SUMMARY_STATUS_COLUMN)?,
    }))
    .map_err(CaseStoreError::BadLabels)?;
    Ok(CaseSummary {
        id: cell(row, SUMMARY_ID_COLUMN)?.to_owned(),
        title: cell(row, SUMMARY_TITLE_COLUMN)?.to_owned(),
        severity: labels.severity,
        status: labels.status,
        assignee: optional(row, SUMMARY_ASSIGNEE_COLUMN)?,
        case_type: optional(row, SUMMARY_TYPE_COLUMN)?,
        created_at: number(row, SUMMARY_CREATED_COLUMN)?,
        updated_at: number(row, SUMMARY_UPDATED_COLUMN)?,
        version: number(row, SUMMARY_VERSION_COLUMN)?,
        counts: CaseCounts {
            tasks: count(row, SUMMARY_TASKS_COLUMN)?,
            observables: count(row, SUMMARY_OBSERVABLES_COLUMN)?,
            comments: count(row, SUMMARY_COMMENTS_COLUMN)?,
            history: count(row, SUMMARY_HISTORY_COLUMN)?,
            alerts: count(row, SUMMARY_ALERTS_COLUMN)?,
        },
    })
}


pub fn detail_from_row(row: &Row) -> Result<CaseDetail, CaseStoreError> {
    let resolution = optional(row, DETAIL_RESOLUTION_COLUMN)?
        .map(|text| serde_json::from_value::<Resolution>(Value::String(text)))
        .transpose()
        .map_err(CaseStoreError::BadLabels)?;
    Ok(CaseDetail {
        summary: summary_from_row(row)?,
        description: optional(row, DETAIL_DESCRIPTION_COLUMN)?,
        resolution,
        template: optional(row, DETAIL_TEMPLATE_COLUMN)?,
        tasks: serde_json::from_str(cell(row, DETAIL_TASKS_COLUMN)?).map_err(CaseStoreError::BadDocument)?,
    })
}


/// The id is checked before SQL; the case's comments, observables and history are never read.
pub async fn get_case_detail(exec: Executor<'_, '_>, scope: &TenantScope, id: &str) -> Result<Option<CaseDetail>, CaseStoreError> {
    check_text("id", id, MAX_ID_CHARS)?;
    let rows = exec(scope.clone(), DETAIL_SQL, vec![id.to_owned()]).await?;
    rows.first().map(detail_from_row).transpose()
}


/// Newest first like `list_cases`, but each case is a summary: a page never carries comments, observables or history.
pub async fn list_case_summaries(exec: Executor<'_, '_>, scope: &TenantScope, page: &CasePage) -> Result<SummaryList, CaseStoreError> {
    check_page(page)?;
    let fetch = (page.size + 1).to_string();
    let rows = match &page.after {
        None => exec(scope.clone(), FIRST_SUMMARY_SQL, vec![fetch]).await?,
        Some(cursor) => {
            exec(
                scope.clone(),
                NEXT_SUMMARY_SQL,
                vec![cursor.created_at.to_string(), cursor.id.clone(), fetch],
            )
            .await?
        }
    };
    let mut summaries = rows.iter().map(summary_from_row).collect::<Result<Vec<CaseSummary>, CaseStoreError>>()?;
    let more = summaries.len() > page.size;
    summaries.truncate(page.size);
    let next = summaries.last().filter(|_last| more).map(|last| CaseCursor {
        created_at: last.created_at,
        id: last.id.clone(),
    });
    Ok(SummaryList { summaries, next })
}
