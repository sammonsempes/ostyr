//! Strict loader of the opt-in list of Redfish devices.

use crate::error::FetchError;
use crate::grammar::is_clean_ident;
use crate::limits::{MAX_DEVICES, MAX_DEVICES_BYTES, MAX_PATH_TEXT_BYTES, MAX_TIMEOUT_MS, MAX_USERNAME_CHARS, MIN_TIMEOUT_MS};
use crate::model::{RedfishDevice, RedfishDeviceFile};
use std::collections::BTreeSet;
use ureq::http::Uri;


fn require(accepted: bool, index: usize, field: &'static str) -> Result<(), FetchError> {
    if accepted {
        Ok(())
    } else {
        Err(FetchError::InvalidDevice { index, field })
    }
}


/// The base URL without a trailing slash; `is_base_url` guarantees it is `https://` and an authority.
pub fn base_of(device: &RedfishDevice) -> &str {
    device.base_url.trim_end_matches('/')
}


pub fn is_base_url(text: &str) -> bool {
    let trimmed = text.trim_end_matches('/');
    text.parse::<Uri>().is_ok_and(|uri| {
        let authority = uri.authority().map_or("", |found| found.as_str());
        [
            text.len() <= MAX_PATH_TEXT_BYTES,
            uri.scheme_str() == Some("https"),
            uri.path() == "/",
            uri.query().is_none(),
            !authority.is_empty(),
            !authority.contains('@'),
            trimmed == format!("https://{authority}"),
        ]
        .iter()
        .all(|accepted| *accepted)
    })
}


pub fn is_path_text(text: &str) -> bool {
    (1..=MAX_PATH_TEXT_BYTES).contains(&text.len())
}


pub fn is_username(text: &str) -> bool {
    let count = text.chars().count();
    let clean = text.chars().all(|letter| letter.is_ascii_alphanumeric() || "._@-".contains(letter));
    [(1..=MAX_USERNAME_CHARS).contains(&count), clean].iter().all(|accepted| *accepted)
}


pub fn check_device(index: usize, device: &RedfishDevice) -> Result<(), FetchError> {
    require(is_clean_ident(&device.name), index, "name")?;
    require(is_base_url(&device.base_url), index, "base_url")?;
    require(
        device.ca_file.is_some() != device.insecure_skip_verify,
        index,
        "ca_file or insecure_skip_verify",
    )?;
    require(device.ca_file.as_ref().is_none_or(|path| is_path_text(path)), index, "ca_file")?;
    require(is_username(&device.username), index, "username")?;
    require(is_path_text(&device.password_file), index, "password_file")?;
    require((MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&device.timeout_ms), index, "timeout_ms")
}


pub fn validated(devices: Vec<RedfishDevice>) -> Result<Vec<RedfishDevice>, FetchError> {
    if devices.len() > MAX_DEVICES {
        Err(FetchError::TooManyDevices { limit: MAX_DEVICES })
    } else {
        devices.iter().enumerate().try_for_each(|(index, device)| check_device(index, device))?;
        let names: BTreeSet<&str> = devices.iter().map(|device| device.name.as_str()).collect();
        require(names.len() == devices.len(), devices.len(), "name repeated")?;
        Ok(devices)
    }
}


pub fn parse_devices(text: &str) -> Result<Vec<RedfishDevice>, FetchError> {
    if text.len() > MAX_DEVICES_BYTES {
        Err(FetchError::DevicesTooLarge { limit: MAX_DEVICES_BYTES })
    } else {
        let file: RedfishDeviceFile = serde_saphyr::from_str(text).map_err(|error| FetchError::Devices(Box::new(error)))?;
        validated(file.devices)
    }
}
