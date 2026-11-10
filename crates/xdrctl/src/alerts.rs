use crate::commands::{bad_reply, call_with_session, FIRST_SUCCESS};
use crate::error::CliError;
use crate::model::{AlertPage, AlertView, Context, HttpMethod, Report};


pub const SHORT_ID_CHARS: usize = 12;


pub const ID_MAX_CHARS: usize = 64;


pub const CURSOR_MAX_CHARS: usize = 1024;


pub const NONE_MARK: &str = "-";


pub const STATUS_UNAUTHORIZED: u16 = 401;


pub const STATUS_FORBIDDEN: u16 = 403;


pub const STATUS_NOT_FOUND: u16 = 404;


pub const STATUS_TOO_MANY: u16 = 429;


pub const BIDI_CONTROLS: &[char] = &[
    '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];


/// Escapes control and bidirectional characters so a hostile value cannot drive the terminal.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() || BIDI_CONTROLS.contains(&character) {
                character.escape_unicode().to_string()
            } else {
                character.to_string()
            }
        })
        .collect()
}


pub fn optional(value: Option<&str>) -> String {
    value.map_or_else(|| NONE_MARK.to_owned(), printable)
}


/// Maps the statuses with a fixed meaning to messages of the client's own, so no server text is echoed for them.
pub fn map_status(error: CliError) -> CliError {
    match error {
        CliError::Refused {
            status: STATUS_UNAUTHORIZED, ..
        } => CliError::Unauthorized,
        CliError::Refused {
            status: STATUS_FORBIDDEN, ..
        } => CliError::Forbidden,
        CliError::Refused {
            status: STATUS_NOT_FOUND, ..
        } => CliError::NotFound,
        CliError::Refused { status: STATUS_TOO_MANY, .. } => CliError::RateLimited,
        other => other,
    }
}


pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.chars().count() <= ID_MAX_CHARS && id.chars().all(|character| character.is_ascii_hexdigit())
}


pub fn valid_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.chars().count() <= CURSOR_MAX_CHARS
        && cursor
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_' || character == '=')
}


pub fn list_path(limit: Option<u32>, cursor: Option<&str>) -> Result<String, CliError> {
    if cursor.is_some_and(|value| !valid_cursor(value)) {
        Err(CliError::InvalidArgument("cursor"))
    } else {
        let query = limit
            .map(|value| format!("limit={value}"))
            .into_iter()
            .chain(cursor.map(|value| format!("cursor={value}")))
            .collect::<Vec<_>>()
            .join("&");
        Ok(if query.is_empty() {
            "/alerts".to_owned()
        } else {
            format!("/alerts?{query}")
        })
    }
}


pub fn table_row(alert: &AlertView) -> String {
    let short: String = alert.id.chars().take(SHORT_ID_CHARS).collect();
    [
        printable(&short),
        printable(&alert.severity),
        printable(&alert.rule_title),
        optional(alert.host_name.as_deref()),
        optional(alert.user_name.as_deref()),
        printable(&alert.event_time),
    ]
    .join("\t")
}


pub fn list_text(page: &AlertPage) -> String {
    let footer = page
        .next_cursor
        .as_deref()
        .map_or_else(|| "no more alerts".to_owned(), |cursor| format!("next cursor: {}", printable(cursor)));
    std::iter::once("id\tseverity\trule\thost\tuser\tevent time".to_owned())
        .chain(page.items.iter().map(table_row))
        .chain(std::iter::once(footer))
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn show_text(alert: &AlertView) -> String {
    [
        format!("id: {}", printable(&alert.id)),
        format!("rule: {} ({})", printable(&alert.rule_title), printable(&alert.rule_id)),
        format!("severity: {}", printable(&alert.severity)),
        format!("event time: {}", printable(&alert.event_time)),
        format!("created: {}", printable(&alert.created)),
        format!("host: {}", optional(alert.host_name.as_deref())),
        format!("user: {}", optional(alert.user_name.as_deref())),
        format!("events: {}", printable(&alert.event_ids.join(","))),
        format!("summary: {}", printable(&alert.summary.to_string())),
        format!("summary truncated: {}", alert.summary_truncated),
    ]
    .join("\n")
}


pub fn alerts_list(ctx: &Context, limit: Option<u32>, cursor: Option<&str>) -> Result<Report, CliError> {
    let path = list_path(limit, cursor)?;
    let body = call_with_session(ctx, HttpMethod::Get, &path).map_err(map_status)?;
    let page: AlertPage = serde_json::from_str(&body).map_err(bad_reply(FIRST_SUCCESS))?;
    Ok(Report {
        text: list_text(&page),
        json: serde_json::from_str(&body)?,
    })
}


pub fn alerts_show(ctx: &Context, id: &str) -> Result<Report, CliError> {
    if valid_id(id) {
        let body = call_with_session(ctx, HttpMethod::Get, &format!("/alerts/{id}")).map_err(map_status)?;
        let alert: AlertView = serde_json::from_str(&body).map_err(bad_reply(FIRST_SUCCESS))?;
        Ok(Report {
            text: show_text(&alert),
            json: serde_json::from_str(&body)?,
        })
    } else {
        Err(CliError::InvalidArgument("alert id"))
    }
}
