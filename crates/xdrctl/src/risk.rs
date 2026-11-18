use crate::alerts::{is_hidden, map_status, printable};
use crate::assets::{id_printable, id_segment};
use crate::cases::format_time;
use crate::commands::{bad_reply, call_with_session, FIRST_SUCCESS};
use crate::error::CliError;
use crate::model::{Context, HttpMethod, Report, RiskEntityRow, RiskKind, RiskListReply, RiskShowReply, RiskTruncatedView};


pub const RISK_ID_MAX_BYTES: usize = 256;


pub const STATUS_UNAVAILABLE: u16 = 503;


pub fn kind_word(kind: RiskKind) -> &'static str {
    match kind {
        RiskKind::Host => "host",
        RiskKind::User => "user",
    }
}


/// The id grammar checked before any request: 1 to 256 bytes (the server's `MAX_ENTITY_ID_BYTES`), no hidden character, no leading `-`.
pub fn valid_risk_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= RISK_ID_MAX_BYTES && !id.starts_with('-') && !id.chars().any(is_hidden)
}


/// 401, 403, 404 and 429 are mapped by `map_status`; 503 is the fixed "unavailable" message.
pub fn map_risk_status(error: CliError) -> CliError {
    match map_status(error) {
        CliError::Refused {
            status: STATUS_UNAVAILABLE, ..
        } => CliError::Unavailable,
        other => other,
    }
}


pub fn list_path(limit: Option<u32>, kind: Option<RiskKind>) -> String {
    let query = limit
        .map(|value| format!("limit={value}"))
        .into_iter()
        .chain(kind.map(|value| format!("kind={}", kind_word(value))))
        .collect::<Vec<_>>()
        .join("&");
    if query.is_empty() {
        "/risk/entities".to_owned()
    } else {
        format!("/risk/entities?{query}")
    }
}


pub fn entity_row(entity: &RiskEntityRow) -> String {
    [
        printable(&entity.kind),
        id_printable(&entity.id),
        entity.value.to_string(),
        entity.contributions_used.to_string(),
        entity.contributions_dropped.to_string(),
    ]
    .join("\t")
}


pub fn truncated_line(truncated: &RiskTruncatedView, limit: Option<u32>) -> String {
    let requested = limit.map_or_else(|| "default".to_owned(), |value| value.to_string());
    format!(
        "TRUNCATED: read {} of cap {}, limit {} ({})",
        truncated.read,
        truncated.cap,
        requested,
        printable(&truncated.limit)
    )
}


pub fn refused_text(reply: &RiskListReply) -> String {
    reply
        .refused
        .iter()
        .map(|(kind, count)| format!("{}={count}", printable(kind)))
        .collect::<Vec<_>>()
        .join(",")
}


pub fn list_text(reply: &RiskListReply, limit: Option<u32>) -> String {
    let summary = format!(
        "computed_at {} alerts_read {} informational {} refused {}",
        format_time(reply.computed_at),
        reply.alerts_read,
        reply.informational,
        refused_text(reply)
    );
    reply
        .entities
        .iter()
        .map(entity_row)
        .chain(std::iter::once(summary))
        .chain(reply.truncated.as_ref().map(|truncated| truncated_line(truncated, limit)))
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn show_text(reply: &RiskShowReply) -> String {
    let entity = &reply.entity;
    [
        format!("kind: {}", printable(&entity.kind)),
        format!("id: {}", id_printable(&entity.id)),
        format!("value: {}", entity.value),
        format!("contributions used: {}", entity.contributions_used),
        format!("contributions dropped: {}", entity.contributions_dropped),
        format!("computed_at: {}", format_time(reply.computed_at)),
    ]
    .into_iter()
    .chain(reply.truncated.as_ref().map(|truncated| truncated_line(truncated, None)))
    .collect::<Vec<_>>()
    .join("\n")
}


pub fn risk_list(ctx: &Context, limit: Option<u32>, kind: Option<RiskKind>) -> Result<Report, CliError> {
    let body = call_with_session(ctx, HttpMethod::Get, &list_path(limit, kind)).map_err(map_risk_status)?;
    let reply: RiskListReply = serde_json::from_str(&body).map_err(bad_reply(FIRST_SUCCESS))?;
    Ok(Report {
        text: list_text(&reply, limit),
        json: serde_json::from_str(&body)?,
    })
}


pub fn risk_show(ctx: &Context, kind: RiskKind, id: &str) -> Result<Report, CliError> {
    if valid_risk_id(id) {
        let path = format!("/risk/entities/{}/{}", kind_word(kind), id_segment(id));
        let body = call_with_session(ctx, HttpMethod::Get, &path).map_err(map_risk_status)?;
        let reply: RiskShowReply = serde_json::from_str(&body).map_err(bad_reply(FIRST_SUCCESS))?;
        Ok(Report {
            text: show_text(&reply),
            json: serde_json::from_str(&body)?,
        })
    } else {
        Err(CliError::InvalidArgument("risk id"))
    }
}
