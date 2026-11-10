use crate::alert::FailureReason;
use crate::channel::{redacted_target, validate_channel};
use crate::error::OncallError;
use crate::limits::{MAX_CHANNELS, MAX_REASON_LEN};
use crate::model::{AlertNotice, Channel, NotifyFailure};
use crate::render::{render, truncate};
use crate::store::reason_text;
use crate::types::Sender;
use crate::validate::check_between;


/// The caller gets the closed reason; the detail only reaches the log, cut to `MAX_REASON_LEN`.
pub fn failure(channel: &Channel, reason: FailureReason, detail: &str) -> NotifyFailure {
    let safe = truncate(detail, MAX_REASON_LEN);
    let target = redacted_target(channel);
    let text = reason_text(reason);
    tracing::warn!(channel = ?channel.name, target = %target, reason = text, detail = ?safe, "notification failed");
    NotifyFailure {
        channel: channel.name.clone(),
        reason,
    }
}


pub fn notify_one(alert: &AlertNotice, channel: &Channel, send: &mut Sender) -> Option<NotifyFailure> {
    if channel.tenant != alert.tenant {
        Some(failure(channel, FailureReason::OtherTenant, reason_text(FailureReason::OtherTenant)))
    } else {
        match validate_channel(channel).and_then(|()| render(alert, channel)) {
            Err(error) => Some(failure(channel, FailureReason::InvalidMessage, &error.to_string())),
            Ok(message) => send(channel, &message)
                .err()
                .map(|_| failure(channel, FailureReason::SenderFailed, reason_text(FailureReason::SenderFailed))),
        }
    }
}


/// Sends the alert on every channel; a failing channel does not stop the others and is returned with its name.
pub fn notify(alert: &AlertNotice, channels: &[Channel], mut send: Sender) -> Result<Vec<NotifyFailure>, OncallError> {
    check_between("channels", channels.len() as u64, 0, MAX_CHANNELS)?;
    Ok(channels.iter().filter_map(|channel| notify_one(alert, channel, &mut send)).collect())
}
