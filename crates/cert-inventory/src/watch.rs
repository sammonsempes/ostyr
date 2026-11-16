use crate::error::{WatchError, ZoneReason};
use core_config::parse::{parse_document, read_text_capped};
use core_pg::scope::{tenant_scope, TenantScope};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::io::Read;


pub const MAX_ZONES: usize = 256;


pub const MAX_WATCH_FILE_BYTES: u64 = 16_384;


pub const MAX_HOSTNAME_BYTES: usize = 253;


pub const MAX_LABEL_BYTES: usize = 63;


pub const MIN_LABELS: usize = 2;


/// One tenant's watched zones, each already normalised (lowercase, no root dot, valid hostname, not a public suffix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchList {
    pub scope: TenantScope,
    pub zones: Vec<String>,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWatch {
    tenant: String,
    zones: Vec<String>,
}


/// Reads at most `MAX_WATCH_FILE_BYTES` and parses strictly; `file` only labels errors.
pub fn load_watch_list(reader: &mut dyn Read, file: &str) -> Result<WatchList, WatchError> {
    let text = read_text_capped(reader, file, MAX_WATCH_FILE_BYTES)?;
    parse_watch_list(&text, file)
}


pub fn parse_watch_list(text: &str, file: &str) -> Result<WatchList, WatchError> {
    let raw: RawWatch = parse_document(text, file)?;
    let scope = tenant_scope(&raw.tenant).map_err(WatchError::Tenant)?;
    if raw.zones.len() > MAX_ZONES {
        Err(WatchError::TooManyZones { max: MAX_ZONES })
    } else {
        let zones = raw
            .zones
            .iter()
            .enumerate()
            .map(|(index, zone)| normalise_zone(zone).map_err(|reason| WatchError::Zone { index, reason }))
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen = BTreeSet::new();
        zones.iter().enumerate().try_for_each(|(index, zone)| {
            if seen.insert(zone.as_str()) {
                Ok(())
            } else {
                Err(WatchError::Zone {
                    index,
                    reason: ZoneReason::Duplicate,
                })
            }
        })?;
        Ok(WatchList { scope, zones })
    }
}


/// One trailing root dot is stripped and the name lowercased; everything else must already be a plain registrable hostname.
pub fn normalise_zone(raw: &str) -> Result<String, ZoneReason> {
    let trimmed = raw.strip_suffix('.').unwrap_or(raw);
    if trimmed.len() > MAX_HOSTNAME_BYTES {
        Err(ZoneReason::TooLong)
    } else {
        let name = trimmed.to_ascii_lowercase();
        let labels = name.split('.').collect::<Vec<_>>();
        labels.iter().try_for_each(|label| check_label(label))?;
        if labels.len() < MIN_LABELS {
            Err(ZoneReason::TooFewLabels)
        } else if labels.last().is_some_and(|last| last.bytes().all(|byte| byte.is_ascii_digit())) {
            Err(ZoneReason::IpLiteral)
        } else if psl::suffix(name.as_bytes()).is_some_and(|suffix| suffix.as_bytes() == name.as_bytes()) {
            Err(ZoneReason::PublicSuffix)
        } else {
            Ok(name)
        }
    }
}


fn check_label(label: &str) -> Result<(), ZoneReason> {
    if label.is_empty() || label.len() > MAX_LABEL_BYTES || label.starts_with('-') || label.ends_with('-') {
        Err(ZoneReason::BadLabel)
    } else if label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        Ok(())
    } else {
        Err(ZoneReason::BadCharacter)
    }
}
