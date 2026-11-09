use crate::channel::redacted_target;
use crate::error::OncallError;
use crate::limits::{MAX_CHANNELS, MAX_REASON_LEN};
use crate::model::{AlertNotice, Channel, NotifyFailure};
use crate::render::{render, truncate};
use crate::types::Sender;
use crate::validate::check_between;


pub fn failure(channel: &Channel, reason: &str) -> NotifyFailure {
    let safe = truncate(&reason.replace(&channel.target, &redacted_target(channel)), MAX_REASON_LEN);
    tracing::warn!(channel = %channel.name, target = %redacted_target(channel), reason = %safe, "notification failed");
    NotifyFailure {
        channel: channel.name.clone(),
        reason: safe,
    }
}


pub fn notify_one(alert: &AlertNotice, channel: &Channel, send: &mut Sender) -> Option<NotifyFailure> {
    if channel.tenant != alert.tenant {
        Some(failure(channel, "channel belongs to another tenant"))
    } else {
        match render(alert, channel) {
            Err(error) => Some(failure(channel, &error.to_string())),
            Ok(message) => send(channel, &message).err().map(|reason| failure(channel, &reason)),
        }
    }
}


/// Sends the alert on every channel; a failing channel does not stop the others and is returned with its name.
pub fn notify(alert: &AlertNotice, channels: &[Channel], mut send: Sender) -> Result<Vec<NotifyFailure>, OncallError> {
    check_between("channels", channels.len() as u64, 0, MAX_CHANNELS)?;
    Ok(channels.iter().filter_map(|channel| notify_one(alert, channel, &mut send)).collect())
}
