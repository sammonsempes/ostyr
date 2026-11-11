use crate::alerts::{map_status, optional, page_path, printable, NONE_MARK, SHORT_ID_CHARS};
use crate::commands::{bad_reply, call_with_session, FIRST_SUCCESS};
use crate::error::CliError;
use crate::model::{CaseDetailView, CasePageView, CaseSummaryView, Context, HttpMethod, Report};
use time::OffsetDateTime;


pub const CASE_ID_MAX_CHARS: usize = 128;


/// Renders unix seconds as UTC RFC 3339, or `-` when out of range.
pub fn format_time(seconds: i64) -> String {
    OffsetDateTime::from_unix_timestamp(seconds).map_or_else(
        |_| NONE_MARK.to_owned(),
        |moment| {
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                moment.year(),
                u8::from(moment.month()),
                moment.day(),
                moment.hour(),
                moment.minute(),
                moment.second()
            )
        },
    )
}


/// The web UI's case id grammar: an ASCII alphanumeric first, then alphanumerics and `._-`, at most 128 characters.
pub fn valid_case_id(id: &str) -> bool {
    id.chars().count() <= CASE_ID_MAX_CHARS
        && id.chars().next().is_some_and(|first| first.is_ascii_alphanumeric())
        && id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '.' || character == '_' || character == '-')
}


pub fn table_row(case: &CaseSummaryView) -> String {
    let short: String = case.id.chars().take(SHORT_ID_CHARS).collect();
    [
        printable(&short),
        printable(&case.severity),
        printable(&case.status),
        printable(&case.title),
        optional(case.assignee.as_deref()),
        format_time(case.updated_at),
    ]
    .join("\t")
}


pub fn list_text(page: &CasePageView) -> String {
    let footer = page
        .next_cursor
        .as_deref()
        .map_or_else(|| "no more cases".to_owned(), |cursor| format!("next cursor: {}", printable(cursor)));
    std::iter::once("id\tseverity\tstatus\ttitle\tassignee\tupdated".to_owned())
        .chain(page.items.iter().map(table_row))
        .chain(std::iter::once(footer))
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn show_text(case: &CaseDetailView) -> String {
    let summary = &case.summary;
    let counts = &summary.counts;
    let header = [
        format!("id: {}", printable(&summary.id)),
        format!("title: {}", printable(&summary.title)),
        format!("severity: {}", printable(&summary.severity)),
        format!("status: {}", printable(&summary.status)),
        format!("assignee: {}", optional(summary.assignee.as_deref())),
        format!("type: {}", optional(summary.case_type.as_deref())),
        format!("created: {}", format_time(summary.created_at)),
        format!("updated: {}", format_time(summary.updated_at)),
        format!("version: {}", summary.version),
        format!(
            "counts: tasks {} observables {} comments {} history {} alerts {}",
            counts.tasks, counts.observables, counts.comments, counts.history, counts.alerts
        ),
        format!("description: {}", optional(case.description.as_deref())),
        format!("resolution: {}", optional(case.resolution.as_deref())),
        format!("template: {}", optional(case.template.as_deref())),
    ];
    header
        .into_iter()
        .chain(
            case.tasks
                .iter()
                .map(|task| format!("task: {} ({})", printable(&task.title), printable(&task.status))),
        )
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn cases_list(ctx: &Context, limit: Option<u32>, cursor: Option<&str>) -> Result<Report, CliError> {
    let path = page_path("/cases", limit, cursor)?;
    let body = call_with_session(ctx, HttpMethod::Get, &path).map_err(map_status)?;
    let page: CasePageView = serde_json::from_str(&body).map_err(bad_reply(FIRST_SUCCESS))?;
    Ok(Report {
        text: list_text(&page),
        json: serde_json::from_str(&body)?,
    })
}


pub fn cases_show(ctx: &Context, id: &str) -> Result<Report, CliError> {
    if valid_case_id(id) {
        let body = call_with_session(ctx, HttpMethod::Get, &format!("/cases/{id}")).map_err(map_status)?;
        let case: CaseDetailView = serde_json::from_str(&body).map_err(bad_reply(FIRST_SUCCESS))?;
        Ok(Report {
            text: show_text(&case),
            json: serde_json::from_str(&body)?,
        })
    } else {
        Err(CliError::InvalidArgument("case id"))
    }
}
