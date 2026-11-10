use crate::error::RowError;
use crate::header::{Columns, Family};
use crate::types::{Label, LeaseKey};
use core_export::ecs::{blank_event, EcsEvent, EndpointFields, EventFields, HostFields};
use ecs_normalise::suricata::clean;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use time::OffsetDateTime;


pub const MODULE: &str = "kea";


pub const DATASET: &str = "kea.lease";


pub const MAX_HOSTNAME_CHARS: usize = 253;


pub const MAX_LABEL_CHARS: usize = 63;


pub const MAC_OCTETS: usize = 6;


pub const MAC_OCTET_DIGITS: usize = 2;


pub const STATE_DEFAULT: u32 = 0;


pub const STATE_DECLINED: u32 = 1;


pub const STATE_EXPIRED_RECLAIMED: u32 = 2;


pub const HOSTNAME_RAW_LABEL: &str = "kea_hostname_raw";


/// One converted row and the key that identifies it across a file rewrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Converted {
    pub event: EcsEvent,
    pub key: LeaseKey,
}


/// ECS form of a MAC: six two-digit hex octets separated by `:` or `-`, upper case and dash separated.
pub fn normalise_mac(text: &str) -> Option<String> {
    let octets: Vec<&str> = text.split([':', '-']).collect();
    let valid = octets.len() == MAC_OCTETS
        && octets
            .iter()
            .all(|octet| octet.len() == MAC_OCTET_DIGITS && octet.chars().all(|found| found.is_ascii_hexdigit()));
    valid.then(|| octets.join("-").to_ascii_uppercase())
}


fn valid_label(label: &str) -> bool {
    (1..=MAX_LABEL_CHARS).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|found| found.is_ascii_alphanumeric() || found == '-' || found == '_')
}


/// A hostname in DNS grammar (trailing dot dropped), or `None`.
pub fn valid_hostname(text: &str) -> Option<String> {
    let trimmed = text.strip_suffix('.').unwrap_or(text);
    let valid = !trimmed.is_empty() && trimmed.len() <= MAX_HOSTNAME_CHARS && trimmed.split('.').all(valid_label);
    valid.then(|| trimmed.to_string())
}


/// The ECS hostname when the text is a valid one, otherwise the cleaned and cut raw text as a label.
pub fn hostname_fields(raw: &str) -> (Option<String>, Option<Label>) {
    if raw.is_empty() {
        (None, None)
    } else {
        let valid = valid_hostname(raw);
        let label = valid.is_none().then(|| (HOSTNAME_RAW_LABEL.to_string(), clean(raw)));
        (valid, label)
    }
}


fn field<'a>(fields: &[&'a str], index: usize) -> &'a str {
    fields.get(index).copied().unwrap_or("")
}


fn address_of(family: Family, text: &str) -> Result<String, RowError> {
    match family {
        Family::V4 => Ipv4Addr::from_str(text).map(|found| found.to_string()),
        Family::V6 => Ipv6Addr::from_str(text).map(|found| found.to_string()),
    }
    .map_err(|_| RowError::Address)
}


fn mac_of(family: Family, text: &str) -> Result<Option<String>, RowError> {
    match (family, text.is_empty()) {
        (Family::V6, true) => Ok(None),
        _ => normalise_mac(text).map(Some).ok_or(RowError::Mac),
    }
}


fn seconds(text: &str, error: RowError) -> Result<i64, RowError> {
    u64::from_str(text).ok().and_then(|number| i64::try_from(number).ok()).ok_or(error)
}


fn action_of(state: u32) -> String {
    match state {
        STATE_DEFAULT => "lease-assigned".to_string(),
        STATE_DECLINED => "lease-declined".to_string(),
        STATE_EXPIRED_RECLAIMED => "lease-expired-reclaimed".to_string(),
        other => format!("lease-state-{other}"),
    }
}


/// Maps one lease row (already split on the header's column count) to an ECS event.
pub fn convert_row(columns: &Columns, text: &str) -> Result<Converted, RowError> {
    let fields: Vec<&str> = text.split(',').take(columns.count + 1).collect();
    if fields.len() != columns.count {
        Err(RowError::ColumnCount)
    } else {
        let address = address_of(columns.family, field(&fields, columns.address))?;
        let mac = mac_of(columns.family, columns.hwaddr.map_or("", |index| field(&fields, index)))?;
        let end = seconds(field(&fields, columns.expire), RowError::Expire)?;
        let lifetime = seconds(field(&fields, columns.valid_lifetime), RowError::Lifetime)?;
        let start = end.checked_sub(lifetime).filter(|found| *found >= 0).ok_or(RowError::Range)?;
        let subnet = u32::from_str(field(&fields, columns.subnet_id)).map_err(|_| RowError::Subnet)?;
        let state = u32::from_str(field(&fields, columns.state)).map_err(|_| RowError::State)?;
        let (hostname, raw_label) = hostname_fields(field(&fields, columns.hostname));
        let duid = columns.duid.map(|index| field(&fields, index)).filter(|found| !found.is_empty());
        let labels = [
            Some(("subnet_id".to_string(), subnet.to_string())),
            duid.map(|found| ("duid".to_string(), clean(found))),
            raw_label,
        ];
        let timestamp = OffsetDateTime::from_unix_timestamp(start).map_err(|_| RowError::Range)?;
        let event_end = OffsetDateTime::from_unix_timestamp(end).map_err(|_| RowError::Range)?;
        let key = (end, address.clone(), mac.clone().unwrap_or_else(String::new));
        let event = EcsEvent {
            event: EventFields {
                kind: Some("event".to_string()),
                category: vec!["network".to_string()],
                types: vec!["info".to_string()],
                action: Some(action_of(state)),
                dataset: Some(DATASET.to_string()),
                module: Some(MODULE.to_string()),
                start: Some(timestamp),
                end: Some(event_end),
                ..EventFields::default()
            },
            host: hostname.map(|name| HostFields {
                hostname: Some(name),
                ..HostFields::default()
            }),
            source: Some(EndpointFields {
                ip: Some(address),
                mac,
                ..EndpointFields::default()
            }),
            labels: labels.into_iter().flatten().collect(),
            ..blank_event(timestamp)
        };
        Ok(Converted { event, key })
    }
}
