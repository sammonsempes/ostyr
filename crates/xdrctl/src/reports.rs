use crate::alerts::{map_status, printable};
use crate::cases::format_time;
use crate::commands::{bad_reply, call_with_session, FIRST_SUCCESS};
use crate::error::CliError;
use crate::model::{AttackBodyView, AttackItemView, AttackListReply, Context, GrcBodyView, GrcItemView, GrcListReply, HttpMethod, Report};
use serde::Deserialize;
use serde_json::Value;


pub const FRAMEWORK_MAX_BYTES: usize = 64;


pub const MAX_LIST_ROWS: usize = 100;


pub const MAX_SHOWN_CHARS: usize = 256;


pub const CUT_MARK: &str = "...[cut]";


pub const GRC_LIST: &str = "/grc/reports";


pub const ATTACK_LIST: &str = "/attack-paths/reports";


/// A copy of the grc crate's `is_identifier` (`[A-Za-z0-9][A-Za-z0-9._-]*`, at most 64 bytes); xdrctl has no dependency on grc.
pub fn valid_framework(text: &str) -> bool {
    let mut characters = text.chars();
    text.len() <= FRAMEWORK_MAX_BYTES
        && characters.next().is_some_and(|first| first.is_ascii_alphanumeric())
        && characters.all(|next| next.is_ascii_alphanumeric() || matches!(next, '.' | '_' | '-'))
}


/// The server's report id: ASCII digits only, within `i64`.
pub fn parse_report_id(text: &str) -> Option<i64> {
    text.bytes().all(|byte| byte.is_ascii_digit()).then(|| text.parse::<i64>().ok()).flatten()
}


/// Server text for a terminal: escaped by `printable` and cut at `MAX_SHOWN_CHARS` characters with a visible marker.
pub fn shown(text: &str) -> String {
    let kept: String = text.chars().take(MAX_SHOWN_CHARS).collect();
    let mark = if text.chars().nth(MAX_SHOWN_CHARS).is_some() { CUT_MARK } else { "" };
    format!("{}{mark}", printable(&kept))
}


pub fn list_path(base: &str, framework: Option<&str>, limit: Option<u32>) -> Result<String, CliError> {
    if framework.is_some_and(|name| !valid_framework(name)) {
        Err(CliError::InvalidArgument("framework"))
    } else {
        let query = framework
            .map(|name| format!("framework={name}"))
            .into_iter()
            .chain(limit.map(|value| format!("limit={value}")))
            .collect::<Vec<_>>()
            .join("&");
        Ok(if query.is_empty() { base.to_owned() } else { format!("{base}?{query}") })
    }
}


/// The checked id and the request path built from it, before any request.
pub fn show_target(base: &str, id: &str) -> Result<(i64, String), CliError> {
    parse_report_id(id)
        .map(|number| (number, format!("{base}/{number}")))
        .ok_or(CliError::InvalidArgument("report id"))
}


pub fn truncated_rows(total: usize) -> Option<String> {
    (total > MAX_LIST_ROWS).then(|| format!("TRUNCATED: showing {MAX_LIST_ROWS} of {total} reports"))
}


pub fn grc_row(item: &GrcItemView) -> String {
    [
        item.id.to_string(),
        shown(&item.framework),
        item.version.to_string(),
        shown(&item.generated),
        item.bytes.to_string(),
        format_time(item.stored_at),
        shown(&item.digest),
    ]
    .join("\t")
}


pub fn grc_list_text(reply: &GrcListReply) -> String {
    std::iter::once("id\tframework\tversion\tgenerated\tbytes\tstored_at\tdigest".to_owned())
        .chain(reply.items.iter().take(MAX_LIST_ROWS).map(grc_row))
        .chain(truncated_rows(reply.items.len()))
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn grc_show_text(id: i64, body: &GrcBodyView) -> String {
    let counts = &body.counts;
    [
        format!("id: {id}"),
        format!("framework: {}", shown(&body.framework)),
        format!("version: {}", body.version),
        format!("generated: {}", shown(&body.generated)),
        format!(
            "counts: compliant {} partially compliant {} non compliant {} not assessable {}",
            counts.compliant, counts.partially_compliant, counts.non_compliant, counts.not_assessable
        ),
        format!("controls: {}", body.controls.len()),
        format!("gaps: {}", body.gaps.len()),
        format!("plan items: {}", body.plan.len()),
    ]
    .join("\n")
}


pub fn attack_row(item: &AttackItemView) -> String {
    [
        item.id.to_string(),
        shown(&item.generated),
        item.bytes.to_string(),
        item.truncated.to_string(),
        item.budget_reached.to_string(),
        item.unsearched_count.to_string(),
        format_time(item.stored_at),
        shown(&item.graph_digest),
        shown(&item.digest),
    ]
    .join("\t")
}


pub fn attack_list_text(reply: &AttackListReply) -> String {
    std::iter::once("id\tgenerated\tbytes\ttruncated\tbudget reached\tunsearched\tstored_at\tgraph digest\tdigest".to_owned())
        .chain(reply.items.iter().take(MAX_LIST_ROWS).map(attack_row))
        .chain(truncated_rows(reply.items.len()))
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn attack_show_text(id: i64, body: &AttackBodyView) -> String {
    [
        format!("id: {id}"),
        format!("graph digest: {}", shown(&body.graph_digest)),
        format!("truncated: {}", body.truncated),
        format!("budget reached: {}", body.budget_reached),
        format!("unsearched entries: {}", body.unsearched.len()),
        format!("paths: {}", body.paths.len()),
        format!("choke points: {}", body.choke_points.len()),
        format!("recommendations: {}", body.recommendations.len()),
    ]
    .join("\n")
}


/// Typed summary of a parsed body; the error keeps only category, line and column, never the peer's text.
pub fn parse_reply<'de, Reply: Deserialize<'de>>(json: &'de Value) -> Result<Reply, CliError> {
    Reply::deserialize(json).map_err(bad_reply(FIRST_SUCCESS))
}


pub fn fetch(ctx: &Context, path: &str) -> Result<Value, CliError> {
    let body = call_with_session(ctx, HttpMethod::Get, path).map_err(map_status)?;
    serde_json::from_str(&body).map_err(bad_reply(FIRST_SUCCESS))
}


pub fn grc_list(ctx: &Context, framework: Option<&str>, limit: Option<u32>) -> Result<Report, CliError> {
    let path = list_path(GRC_LIST, framework, limit)?;
    let json = fetch(ctx, &path)?;
    let reply: GrcListReply = parse_reply(&json)?;
    Ok(Report {
        text: grc_list_text(&reply),
        json,
    })
}


pub fn grc_show(ctx: &Context, id: &str) -> Result<Report, CliError> {
    let (number, path) = show_target(GRC_LIST, id)?;
    let json = fetch(ctx, &path)?;
    let body: GrcBodyView = parse_reply(&json)?;
    Ok(Report {
        text: grc_show_text(number, &body),
        json,
    })
}


pub fn attack_paths_list(ctx: &Context, limit: Option<u32>) -> Result<Report, CliError> {
    let path = list_path(ATTACK_LIST, None, limit)?;
    let json = fetch(ctx, &path)?;
    let reply: AttackListReply = parse_reply(&json)?;
    Ok(Report {
        text: attack_list_text(&reply),
        json,
    })
}


pub fn attack_paths_show(ctx: &Context, id: &str) -> Result<Report, CliError> {
    let (number, path) = show_target(ATTACK_LIST, id)?;
    let json = fetch(ctx, &path)?;
    let body: AttackBodyView = parse_reply(&json)?;
    Ok(Report {
        text: attack_show_text(number, &body),
        json,
    })
}
