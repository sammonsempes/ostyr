//! One element of the Windows Update Agent search envelope: decoding and field grammar.

use crate::limits::{MAX_ITEMS_PER_UPDATE, MAX_TITLE_BYTES};
use crate::model::{DecodedUpdate, Device, SeverityWord, WindowsSeverity, WindowsSkip, WindowsUpdate};
use crate::scan::is_forbidden;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::value::RawValue;


pub const SECURITY_UPDATES_CLASSIFICATION: &str = "0fa1201d-4330-4fa8-8ae9-b877473b6441";


pub const GUID_GROUP_LENGTHS: [usize; 5] = [8, 4, 4, 4, 12];


pub const KB_MIN_DIGITS: usize = 6;


pub const KB_MAX_DIGITS: usize = 8;


pub const MAX_REBOOT_BEHAVIOR: u64 = 2;


#[derive(Debug, Deserialize)]
pub struct Envelope<'a> {
    #[serde(rename = "ResultCode")]
    pub result_code: i64,
    #[serde(rename = "Updates", borrow)]
    pub updates: Vec<&'a RawValue>,
}


#[derive(Debug, Deserialize)]
pub struct Counted {
    #[serde(rename = "ResultCode")]
    pub result_code: i64,
    #[serde(rename = "Updates")]
    pub updates: Option<Vec<IgnoredAny>>,
}


#[derive(Debug, Deserialize)]
pub struct CountedItems {
    #[serde(rename = "KBArticleIDs")]
    pub kb_ids: Vec<IgnoredAny>,
    #[serde(rename = "CategoryIDs")]
    pub category_ids: Vec<IgnoredAny>,
}


#[derive(Debug, Deserialize)]
pub struct RawUpdate<'a> {
    #[serde(rename = "UpdateID")]
    pub update_id: String,
    #[serde(rename = "RevisionNumber")]
    pub revision: u64,
    #[serde(rename = "KBArticleIDs", borrow)]
    pub kb_ids: Vec<&'a RawValue>,
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "MsrcSeverity")]
    pub severity: Option<String>,
    #[serde(rename = "CategoryIDs", borrow)]
    pub category_ids: Vec<&'a RawValue>,
    #[serde(rename = "IsHidden")]
    pub hidden: bool,
    #[serde(rename = "IsMandatory")]
    pub mandatory: bool,
    #[serde(rename = "RebootBehavior")]
    pub reboot_behavior: u64,
}


pub fn decode_update(device: &Device, text: &str) -> Result<DecodedUpdate, WindowsSkip> {
    let object = Some(text).filter(|value| is_object(value)).ok_or(WindowsSkip::Malformed)?;
    let counted: CountedItems = serde_json::from_str(object).map_err(|_| WindowsSkip::Malformed)?;
    if counted.kb_ids.len() > MAX_ITEMS_PER_UPDATE || counted.category_ids.len() > MAX_ITEMS_PER_UPDATE {
        Err(WindowsSkip::TooManyItems)
    } else {
        let raw: RawUpdate = serde_json::from_str(object).map_err(|_| WindowsSkip::Malformed)?;
        finish_update(device, &raw)
    }
}


pub fn is_object(text: &str) -> bool {
    text.trim_start().starts_with('{')
}


pub fn finish_update(device: &Device, raw: &RawUpdate) -> Result<DecodedUpdate, WindowsSkip> {
    let update_id = guid_lowercase(&raw.update_id).ok_or(WindowsSkip::Malformed)?;
    let revision = u32::try_from(raw.revision)
        .ok()
        .filter(|value| *value >= 1)
        .ok_or(WindowsSkip::Malformed)?;
    let kb_ids = decode_items(&raw.kb_ids, kb_number)?;
    let category_ids = decode_items(&raw.category_ids, guid_lowercase)?;
    let reboot_behavior = u8::try_from(raw.reboot_behavior)
        .ok()
        .filter(|value| u64::from(*value) <= MAX_REBOOT_BEHAVIOR)
        .ok_or(WindowsSkip::Malformed)?;
    if raw.title.chars().any(is_forbidden) {
        Err(WindowsSkip::ControlCharacters)
    } else {
        let word = severity_word(raw.severity.as_deref());
        let security = word != SeverityWord::Absent || category_ids.iter().any(|id| id == SECURITY_UPDATES_CLASSIFICATION);
        Ok(DecodedUpdate {
            update: WindowsUpdate {
                tenant: device.tenant.clone(),
                device_id: device.device_id.clone(),
                update_id,
                revision,
                kb_ids,
                title: cut_title(&raw.title),
                severity: match word {
                    SeverityWord::Known(severity) => Some(severity),
                    SeverityWord::Absent | SeverityWord::Unknown => None,
                },
                security,
                hidden: raw.hidden,
                mandatory: raw.mandatory,
                reboot_behavior,
                category_ids,
            },
            unknown_severity: word == SeverityWord::Unknown,
        })
    }
}


pub fn decode_items(items: &[&RawValue], check: fn(&str) -> Option<String>) -> Result<Vec<String>, WindowsSkip> {
    items
        .iter()
        .map(|item| {
            serde_json::from_str::<String>(item.get())
                .map_err(|_| WindowsSkip::Malformed)
                .and_then(|text| check(&text).ok_or(WindowsSkip::Malformed))
        })
        .collect()
}


pub fn kb_number(text: &str) -> Option<String> {
    Some(text)
        .filter(|value| (KB_MIN_DIGITS..=KB_MAX_DIGITS).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit()))
        .map(str::to_string)
}


pub fn guid_lowercase(text: &str) -> Option<String> {
    let groups: Vec<&str> = text.split('-').collect();
    let well_formed = groups.len() == GUID_GROUP_LENGTHS.len()
        && groups
            .iter()
            .zip(GUID_GROUP_LENGTHS)
            .all(|(group, length)| group.len() == length && group.bytes().all(|byte| byte.is_ascii_hexdigit()));
    well_formed.then(|| text.to_ascii_lowercase())
}


pub fn severity_word(text: Option<&str>) -> SeverityWord {
    match text {
        None | Some("") => SeverityWord::Absent,
        Some("Critical") => SeverityWord::Known(WindowsSeverity::Critical),
        Some("Important") => SeverityWord::Known(WindowsSeverity::Important),
        Some("Moderate") => SeverityWord::Known(WindowsSeverity::Moderate),
        Some("Low") => SeverityWord::Known(WindowsSeverity::Low),
        Some(_) => SeverityWord::Unknown,
    }
}


pub fn cut_title(title: &str) -> String {
    if title.len() > MAX_TITLE_BYTES {
        let (head, tail) = title.split_at(title.floor_char_boundary(MAX_TITLE_BYTES));
        format!("{head}[cut, {} bytes]", tail.len())
    } else {
        title.to_string()
    }
}
