use crate::alerts::{map_status, NONE_MARK};
use crate::commands::{bad_reply, call_with_session, FIRST_SUCCESS};
use crate::error::CliError;
use crate::model::{Context, GroupRow, GroupsReply, HttpMethod, Report};
use crate::reports::shown;


pub const GROUPS_PATH: &str = "/alert-groups";


pub const STATUS_UNAVAILABLE: u16 = 503;


pub const INCOMPLETE_NOTICE: &str = "INCOMPLETE: older alerts of the tenant remain unread, counts may be understated";


/// 401, 403, 404 and 429 are mapped by `map_status`; 503 is the fixed "unavailable" message.
pub fn map_groups_status(error: CliError) -> CliError {
    match map_status(error) {
        CliError::Refused {
            status: STATUS_UNAVAILABLE, ..
        } => CliError::GroupsUnavailable,
        other => other,
    }
}


pub fn yes_no(flag: bool) -> &'static str {
    if flag {
        "yes"
    } else {
        "no"
    }
}


pub fn group_line(group: &GroupRow) -> String {
    [
        shown(&group.rule_id),
        group.host_name.as_deref().map_or_else(|| NONE_MARK.to_owned(), shown),
        group.user_name.as_deref().map_or_else(|| NONE_MARK.to_owned(), shown),
        group.alert_count.to_string(),
        group.duplicates.to_string(),
        shown(&group.max_severity),
        shown(&group.first_time),
        shown(&group.last_time),
        format!("omitted {}", yes_no(group.omitted)),
        format!("cut_at_older {}", yes_no(group.cut_at_older)),
    ]
    .join("\t")
}


pub fn groups_text(reply: &GroupsReply) -> String {
    let footer = format!(
        "alerts read {}, complete {}, oldest {}",
        reply.alerts_read,
        yes_no(reply.complete),
        reply.oldest_read.as_deref().map_or_else(|| "none".to_owned(), shown)
    );
    (!reply.complete)
        .then(|| INCOMPLETE_NOTICE.to_owned())
        .into_iter()
        .chain(reply.groups.iter().map(group_line))
        .chain(std::iter::once(footer))
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn alert_groups(ctx: &Context) -> Result<Report, CliError> {
    let body = call_with_session(ctx, HttpMethod::Get, GROUPS_PATH).map_err(map_groups_status)?;
    let reply: GroupsReply = serde_json::from_str(&body).map_err(bad_reply(FIRST_SUCCESS))?;
    Ok(Report {
        text: groups_text(&reply),
        json: serde_json::from_str(&body)?,
    })
}
