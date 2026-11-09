use crate::error::OncallError;
use crate::limits::{
    MAX_RENDER_ENTRIES, MAX_VALUE_LEN, NTFY_BODY_LEN, NTFY_SUBJECT_LEN, SLACK_BODY_LEN, SLACK_SUBJECT_LEN, SMS_BODY_LEN, SMS_SUBJECT_LEN,
    SMTP_BODY_LEN, SMTP_SUBJECT_LEN, TEAMS_BODY_LEN, TEAMS_SUBJECT_LEN, WEBHOOK_BODY_LEN, WEBHOOK_SUBJECT_LEN,
};
use crate::model::{AlertNotice, Channel, ChannelKind, Message};
use serde_json::Value;
use std::collections::BTreeMap;


pub const MARKDOWN_SPECIAL: &str = "\\`*_{}[]()#+-.!|<>~&";


pub fn json_string(text: &str) -> String {
    Value::String(text.to_string()).to_string()
}


/// Maximum characters of (subject, body) for a kind, counted before escaping.
pub fn bounds(kind: ChannelKind) -> (usize, usize) {
    match kind {
        ChannelKind::Smtp => (SMTP_SUBJECT_LEN, SMTP_BODY_LEN),
        ChannelKind::Webhook => (WEBHOOK_SUBJECT_LEN, WEBHOOK_BODY_LEN),
        ChannelKind::Ntfy => (NTFY_SUBJECT_LEN, NTFY_BODY_LEN),
        ChannelKind::Teams => (TEAMS_SUBJECT_LEN, TEAMS_BODY_LEN),
        ChannelKind::Slack => (SLACK_SUBJECT_LEN, SLACK_BODY_LEN),
        ChannelKind::Sms => (SMS_SUBJECT_LEN, SMS_BODY_LEN),
    }
}


pub fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}


pub fn escape_markdown(text: &str) -> String {
    text.chars().fold(String::with_capacity(text.len()), |mut escaped, character| {
        if MARKDOWN_SPECIAL.contains(character) {
            escaped.push('\\');
        }
        escaped.push(character);
        escaped
    })
}


pub fn section(title: &str, entries: &BTreeMap<String, String>) -> String {
    entries
        .iter()
        .take(MAX_RENDER_ENTRIES)
        .map(|(key, value)| format!("{title} {key}: {}", truncate(value, MAX_VALUE_LEN as usize)))
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn check_no_line_break(field: &'static str, text: &str) -> Result<(), OncallError> {
    if text.contains(['\r', '\n']) {
        Err(OncallError::HeaderInjection { field })
    } else {
        Ok(())
    }
}


/// One message for one channel: texts cut to the kind's bounds, then escaped for the target format.
pub fn render(alert: &AlertNotice, channel: &Channel) -> Result<Message, OncallError> {
    let raw_subject = format!("[{}] {}", alert.tenant, alert.name);
    check_no_line_break("subject", &raw_subject)?;
    check_no_line_break("address", &channel.target)?;
    let (subject_len, body_len) = bounds(channel.kind);
    let subject = truncate(&raw_subject, subject_len);
    let body = truncate(
        &format!("{}\n{}", section("label", &alert.labels), section("annotation", &alert.annotations)),
        body_len,
    );
    Ok(match channel.kind {
        ChannelKind::Smtp | ChannelKind::Ntfy | ChannelKind::Sms => Message { subject, body },
        ChannelKind::Teams | ChannelKind::Slack => Message {
            subject: escape_markdown(&subject),
            body: escape_markdown(&body),
        },
        ChannelKind::Webhook => Message {
            body: format!(
                "{{\"tenant\":{},\"subject\":{},\"text\":{}}}",
                json_string(&alert.tenant),
                json_string(&subject),
                json_string(&body)
            ),
            subject,
        },
    })
}
