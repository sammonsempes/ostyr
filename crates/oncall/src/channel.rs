use crate::error::OncallError;
use crate::limits::{MAX_PATH_LEN, MAX_TARGET_LEN};
use crate::load::read_file_limited;
use crate::model::{Channel, ChannelKind};
use crate::smtp::parse_address;
use crate::validate::{check_between, check_name};
use core_config::parse::parse_document;
use std::path::Path;
use url::Url;


pub fn invalid(channel: &Channel, reason: &'static str) -> OncallError {
    OncallError::InvalidChannel {
        channel: channel.name.clone(),
        reason,
    }
}


pub fn is_address(target: &str) -> bool {
    parse_address(target).is_ok()
}


pub fn check_https(channel: &Channel) -> Result<(), OncallError> {
    match Url::parse(&channel.target) {
        Ok(url) if url.scheme() == "https" => Ok(()),
        _ => Err(invalid(channel, "target must be an https:// URL")),
    }
}


pub fn validate_channel(channel: &Channel) -> Result<(), OncallError> {
    check_name("channel name", &channel.name)?;
    check_name("channel tenant", &channel.tenant)?;
    check_between("target", channel.target.chars().count() as u64, 1, MAX_TARGET_LEN)?;
    if let Some(path) = &channel.secret_file {
        check_between("secret_file", path.chars().count() as u64, 1, MAX_PATH_LEN)?;
    }
    match channel.kind {
        ChannelKind::Smtp if is_address(&channel.target) => Ok(()),
        ChannelKind::Smtp => Err(invalid(channel, "target must be an address without CR, LF or spaces")),
        _ => check_https(channel),
    }
}


/// Scheme and host only: the path and query of a webhook URL carry its secret.
pub fn redacted_target(channel: &Channel) -> String {
    match Url::parse(&channel.target) {
        Ok(url) => url.origin().ascii_serialization(),
        Err(_) => String::from("<address>"),
    }
}


pub fn parse_channel(text: &str, file: &str) -> Result<Channel, OncallError> {
    let channel: Channel = parse_document(text, file)?;
    validate_channel(&channel)?;
    Ok(channel)
}


pub fn load_channel(path: &Path) -> Result<Channel, OncallError> {
    parse_channel(&read_file_limited(path)?, &path.display().to_string())
}
