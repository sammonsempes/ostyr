//! EVE `fileinfo` lines in, ECS events out; the file content never reaches either.


use crate::model::Sighting;
use crate::reader::split_name;
use core_export::ecs::{blank_event, EcsEvent, EndpointFields, EventFields, FileFields, HashFields, RuleFields};
use serde::Deserialize;
use std::net::IpAddr;
use time::OffsetDateTime;


const FILEINFO_MARK: &str = "\"fileinfo\"";


const FILEINFO_TYPE: &str = "fileinfo";


const ECS_SEVERITY: u32 = 70;


#[derive(Debug, Deserialize)]
pub struct EveLine {
    pub event_type: Option<String>,
    pub src_ip: Option<IpAddr>,
    pub dest_ip: Option<IpAddr>,
    pub fileinfo: Option<EveFile>,
}


#[derive(Debug, Deserialize)]
pub struct EveFile {
    pub sha256: Option<String>,
    pub stored: Option<bool>,
}


/// What one EVE line is to the scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Ignored,
    Malformed,
    Stored(Sighting),
}


/// A line over `max_line_bytes` or not valid for the fields read is `Malformed`; a line that is not a stored `fileinfo` is `Ignored`.
pub fn parse_line(line: &str, max_line_bytes: usize) -> Parsed {
    match (line.len() > max_line_bytes, line.contains(FILEINFO_MARK)) {
        (true, _) => Parsed::Malformed,
        (false, false) => Parsed::Ignored,
        (false, true) => serde_json::from_str::<EveLine>(line).map_or(Parsed::Malformed, sighting_of),
    }
}


/// A stored `fileinfo` whose hash is not 64 lowercase hex is `Malformed`.
pub fn sighting_of(line: EveLine) -> Parsed {
    let stored = line.fileinfo.filter(|_| line.event_type.as_deref() == Some(FILEINFO_TYPE));
    match stored.filter(|file| file.stored == Some(true)).map(|file| file.sha256) {
        None => Parsed::Ignored,
        Some(Some(sha256)) if split_name(&sha256).is_some() => Parsed::Stored(Sighting {
            sha256,
            src_ip: line.src_ip,
            dest_ip: line.dest_ip,
        }),
        Some(_) => Parsed::Malformed,
    }
}


fn endpoint(ip: Option<IpAddr>) -> Option<EndpointFields> {
    ip.map(|address| EndpointFields {
        ip: Some(address.to_string()),
        ..EndpointFields::default()
    })
}


/// One event for one rule that matched one file; `size` is the number of bytes actually scanned.
pub fn match_event(sighting: &Sighting, size: u64, rule_name: &str, now: OffsetDateTime) -> EcsEvent {
    EcsEvent {
        event: EventFields {
            kind: Some("alert".to_string()),
            category: vec!["file".to_string(), "malware".to_string()],
            types: vec!["info".to_string()],
            action: Some("file-scan-match".to_string()),
            dataset: Some("ndr.yara".to_string()),
            module: Some("ndr".to_string()),
            provider: Some("yara-x".to_string()),
            severity: Some(ECS_SEVERITY),
            ..EventFields::default()
        },
        file: Some(FileFields {
            size: Some(size),
            hash: Some(HashFields {
                sha256: Some(sighting.sha256.clone()),
                ..HashFields::default()
            }),
            ..FileFields::default()
        }),
        source: endpoint(sighting.src_ip),
        destination: endpoint(sighting.dest_ip),
        rule: Some(RuleFields {
            name: Some(rule_name.to_string()),
            ..RuleFields::default()
        }),
        ..blank_event(now)
    }
}
