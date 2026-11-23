//! One element of the winget update envelope: decoding and field grammar.

use crate::model::{Device, Update, WingetSkip};
use crate::validate::{is_spaced_version, is_winget_package_id, is_winget_version};
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::value::RawValue;


pub const UNKNOWN_VERSION: &str = "Unknown";


pub const ARCHITECTURE: &str = "any";


pub const KNOWN_SOURCES: [&str; 2] = ["winget", "msstore"];


#[derive(Debug, Deserialize)]
pub struct Envelope<'a> {
    #[serde(rename = "Updates", borrow)]
    pub updates: Vec<&'a RawValue>,
}


#[derive(Debug, Deserialize)]
pub struct Counted {
    #[serde(rename = "Updates")]
    pub updates: Option<Vec<IgnoredAny>>,
}


#[derive(Debug, Deserialize)]
pub struct RawPackage {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "InstalledVersion")]
    pub installed_version: String,
    #[serde(rename = "AvailableVersion")]
    pub available_version: String,
    #[serde(rename = "Source")]
    pub source: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub update: Update,
    pub unknown_installed: bool,
    pub other_source: bool,
}


pub fn is_object(text: &str) -> bool {
    text.trim_start().starts_with('{')
}


pub fn decode_package(device: &Device, text: &str) -> Result<Decoded, WingetSkip> {
    let object = Some(text).filter(|value| is_object(value)).ok_or(WingetSkip::Malformed)?;
    let raw: RawPackage = serde_json::from_str(object).map_err(|_| WingetSkip::Malformed)?;
    finish_package(device, raw)
}


pub fn finish_package(device: &Device, raw: RawPackage) -> Result<Decoded, WingetSkip> {
    let installed_unknown = raw.installed_version.is_empty() || raw.installed_version == UNKNOWN_VERSION || is_spaced_version(&raw.installed_version);
    let installed_valid = installed_unknown || is_winget_version(&raw.installed_version);
    if is_winget_package_id(&raw.id) && installed_valid && is_winget_version(&raw.available_version) {
        let other_source = !KNOWN_SOURCES.contains(&raw.source.as_str());
        Ok(Decoded {
            update: Update {
                tenant: device.tenant.clone(),
                device_id: device.device_id.clone(),
                package: raw.id,
                architecture: ARCHITECTURE.to_string(),
                installed_version: (!installed_unknown).then_some(raw.installed_version),
                candidate_version: raw.available_version,
                origin: (!other_source).then_some(raw.source),
                security: false,
                advisory_id: None,
                severity: None,
            },
            unknown_installed: installed_unknown,
            other_source,
        })
    } else {
        Err(WingetSkip::Malformed)
    }
}
