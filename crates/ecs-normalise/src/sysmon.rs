use crate::error::SysmonError;
use crate::sysmon_input::{parse_event, RawEvent};
use crate::types::{Fields, SeenIds};
use core_export::ecs::{
    blank_event, DnsFields, DnsQuestion, EcsEvent, EndpointFields, EventFields, FileFields, HashFields, HostFields, NetworkFields, OsFields,
    ParentFields, PeFields, ProcessFields, RegistryFields, UserFields,
};
use std::net::IpAddr;
use std::num::ParseIntError;
use std::str::FromStr;
use time::format_description::well_known::Rfc3339;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};
use tracing::{debug, warn};


pub const SYSMON_MODULE: &str = "sysmon";


pub const WINDOWS_OS_TYPE: &str = "windows";


const UTC_TIME_FORMAT: &[BorrowedFormatItem<'static>] = format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond]");


const REGISTRY_CATEGORY: &str = "registry";


/// Which ECS group the `Hashes` field of an event describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashTarget {
    Process,
    File,
}


/// One supported Sysmon event id: its ECS classification and the Sigma Windows category (`action`).
#[derive(Debug, Clone, Copy)]
pub struct Kind {
    pub id: &'static str,
    pub category: &'static str,
    pub kind_type: &'static str,
    pub action: &'static str,
    pub subject: &'static str,
    pub hashes: HashTarget,
    pub extras: &'static [&'static str],
}


const PROCESS_EXTRAS: &[&str] = &["IntegrityLevel", "LogonId", "Company", "Description", "Product", "FileVersion"];


const ACCESS_EXTRAS: &[&str] = &[
    "TargetImage",
    "TargetProcessGuid",
    "TargetProcessId",
    "GrantedAccess",
    "CallTrace",
    "SourceThreadId",
];


const REGISTRY_EXTRAS: &[&str] = &["EventType", "Details", "NewName"];


pub const KINDS: &[Kind] = &[
    Kind {
        id: "1",
        category: "process",
        kind_type: "start",
        action: "process_creation",
        subject: "",
        hashes: HashTarget::Process,
        extras: PROCESS_EXTRAS,
    },
    Kind {
        id: "3",
        category: "network",
        kind_type: "connection",
        action: "network_connection",
        subject: "",
        hashes: HashTarget::File,
        extras: &[],
    },
    Kind {
        id: "5",
        category: "process",
        kind_type: "end",
        action: "process_termination",
        subject: "",
        hashes: HashTarget::File,
        extras: &[],
    },
    Kind {
        id: "7",
        category: "library",
        kind_type: "start",
        action: "image_load",
        subject: "",
        hashes: HashTarget::File,
        extras: &["Signed", "Signature", "SignatureStatus", "Company", "Description"],
    },
    Kind {
        id: "8",
        category: "process",
        kind_type: "change",
        action: "create_remote_thread",
        subject: "Source",
        hashes: HashTarget::File,
        extras: &[
            "TargetImage",
            "TargetProcessGuid",
            "TargetProcessId",
            "StartAddress",
            "NewThreadId",
            "StartModule",
            "StartFunction",
        ],
    },
    Kind {
        id: "10",
        category: "process",
        kind_type: "access",
        action: "process_access",
        subject: "Source",
        hashes: HashTarget::File,
        extras: ACCESS_EXTRAS,
    },
    Kind {
        id: "11",
        category: "file",
        kind_type: "creation",
        action: "file_event",
        subject: "",
        hashes: HashTarget::File,
        extras: &["CreationUtcTime"],
    },
    Kind {
        id: "12",
        category: REGISTRY_CATEGORY,
        kind_type: "change",
        action: "registry_event",
        subject: "",
        hashes: HashTarget::File,
        extras: REGISTRY_EXTRAS,
    },
    Kind {
        id: "13",
        category: REGISTRY_CATEGORY,
        kind_type: "change",
        action: "registry_event",
        subject: "",
        hashes: HashTarget::File,
        extras: REGISTRY_EXTRAS,
    },
    Kind {
        id: "14",
        category: REGISTRY_CATEGORY,
        kind_type: "change",
        action: "registry_event",
        subject: "",
        hashes: HashTarget::File,
        extras: REGISTRY_EXTRAS,
    },
    Kind {
        id: "22",
        category: "network",
        kind_type: "protocol",
        action: "dns_query",
        subject: "",
        hashes: HashTarget::File,
        extras: &["QueryResults", "QueryStatus"],
    },
    Kind {
        id: "23",
        category: "file",
        kind_type: "deletion",
        action: "file_delete",
        subject: "",
        hashes: HashTarget::File,
        extras: &["IsExecutable", "Archived"],
    },
    Kind {
        id: "26",
        category: "file",
        kind_type: "deletion",
        action: "file_delete",
        subject: "",
        hashes: HashTarget::File,
        extras: &["IsExecutable"],
    },
    Kind {
        id: "27",
        category: "file",
        kind_type: "denied",
        action: "file_block_executable",
        subject: "",
        hashes: HashTarget::File,
        extras: &[],
    },
    Kind {
        id: "28",
        category: "file",
        kind_type: "denied",
        action: "file_block_shredding",
        subject: "",
        hashes: HashTarget::File,
        extras: &[],
    },
];


fn text(fields: &Fields, name: &str) -> Option<String> {
    fields.get(name).filter(|value| !value.is_empty()).cloned()
}


fn number<Value: FromStr<Err = ParseIntError>>(fields: &Fields, name: &str) -> Result<Option<Value>, SysmonError> {
    text(fields, name)
        .map(|value| {
            value.parse::<Value>().map_err(|source| SysmonError::BadNumber {
                field: name.to_string(),
                source,
            })
        })
        .transpose()
}


fn non_empty<Group: Default + PartialEq>(group: Group) -> Option<Group> {
    Some(group).filter(|found| *found != Group::default())
}


fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}


fn parse_hashes(hashes: &str) -> Result<HashFields, SysmonError> {
    hashes.split(',').try_fold(HashFields::default(), |mut found, entry| {
        let (algorithm, value) = entry.split_once('=').ok_or(SysmonError::BadHashes)?;
        match algorithm.trim().to_ascii_lowercase().as_str() {
            "md5" => found.md5 = Some(value.to_string()),
            "sha1" => found.sha1 = Some(value.to_string()),
            "sha256" => found.sha256 = Some(value.to_string()),
            other => debug!(algorithm = other, "unmapped hash algorithm"),
        }
        Ok(found)
    })
}


fn hashes(fields: &Fields, wanted: bool) -> Result<Option<HashFields>, SysmonError> {
    if wanted {
        text(fields, "Hashes").map(|value| parse_hashes(&value)).transpose()
    } else {
        Ok(None)
    }
}


fn process_fields(kind: &Kind, fields: &Fields) -> Result<Option<ProcessFields>, SysmonError> {
    let prefix = kind.subject;
    let image = text(fields, &format!("{prefix}Image"));
    let parent = ParentFields {
        pid: number(fields, "ParentProcessId")?,
        entity_id: text(fields, "ParentProcessGuid"),
        executable: text(fields, "ParentImage"),
        command_line: text(fields, "ParentCommandLine"),
    };
    Ok(non_empty(ProcessFields {
        pid: number(fields, &format!("{prefix}ProcessId"))?,
        name: image.as_deref().map(|path| base_name(path).to_string()),
        executable: image,
        command_line: text(fields, "CommandLine"),
        working_directory: text(fields, "CurrentDirectory"),
        entity_id: text(fields, &format!("{prefix}ProcessGuid")),
        hash: hashes(fields, kind.hashes == HashTarget::Process)?,
        pe: non_empty(PeFields {
            original_file_name: text(fields, "OriginalFileName"),
        }),
        parent: non_empty(parent),
        ..ProcessFields::default()
    }))
}


fn file_fields(kind: &Kind, fields: &Fields) -> Result<Option<FileFields>, SysmonError> {
    let path = text(fields, "TargetFilename").or_else(|| text(fields, "ImageLoaded"));
    Ok(non_empty(FileFields {
        name: path.as_deref().map(|found| base_name(found).to_string()),
        path,
        size: None,
        hash: hashes(fields, kind.hashes == HashTarget::File)?,
    }))
}


fn user_fields(fields: &Fields) -> Option<UserFields> {
    let user = text(fields, "User");
    let (domain, name) = match user.as_deref().and_then(|full| full.rsplit_once('\\')) {
        Some((found_domain, found_name)) => (Some(found_domain.to_string()), Some(found_name.to_string())),
        None => (None, user),
    };
    non_empty(UserFields { name, domain, id: None })
}


fn network_fields(fields: &Fields) -> Option<NetworkFields> {
    non_empty(NetworkFields {
        transport: text(fields, "Protocol").map(|protocol| protocol.to_lowercase()),
        direction: text(fields, "Initiated").map(|initiated| if initiated == "true" { "egress" } else { "ingress" }.to_string()),
    })
}


fn dns_fields(fields: &Fields) -> Option<DnsFields> {
    text(fields, "QueryName").map(|name| DnsFields {
        question: DnsQuestion { name: Some(name) },
        resolved_ip: text(fields, "QueryResults")
            .iter()
            .flat_map(|results| results.split(';'))
            .filter(|entry| entry.parse::<IpAddr>().is_ok())
            .map(String::from)
            .collect(),
    })
}


fn registry_type(kind: &Kind, fields: &Fields) -> &'static str {
    match (kind.category, fields.get("EventType").map(String::as_str)) {
        (REGISTRY_CATEGORY, Some("CreateKey")) => "creation",
        (REGISTRY_CATEGORY, Some("DeleteKey" | "DeleteValue")) => "deletion",
        _ => kind.kind_type,
    }
}


fn event_time(raw: &RawEvent) -> Result<OffsetDateTime, SysmonError> {
    match (text(&raw.fields, "UtcTime"), &raw.system_time) {
        (Some(utc), _) => PrimitiveDateTime::parse(&utc, UTC_TIME_FORMAT)
            .map(PrimitiveDateTime::assume_utc)
            .map_err(SysmonError::BadTime),
        (None, Some(system)) => OffsetDateTime::parse(system, &Rfc3339).map_err(SysmonError::BadTime),
        (None, None) => Err(SysmonError::MissingField("UtcTime")),
    }
}


fn base_event(raw: &RawEvent, time: OffsetDateTime) -> EcsEvent {
    EcsEvent {
        event: EventFields {
            kind: Some("event".to_string()),
            code: Some(raw.event_id.to_string()),
            module: Some(SYSMON_MODULE.to_string()),
            ..EventFields::default()
        },
        host: Some(HostFields {
            name: raw.computer.clone().filter(|name| !name.is_empty()),
            os: Some(OsFields {
                kind: Some(WINDOWS_OS_TYPE.to_string()),
            }),
            ..HostFields::default()
        }),
        ..blank_event(time)
    }
}


fn known_event(base: EcsEvent, kind: &Kind, fields: &Fields) -> Result<EcsEvent, SysmonError> {
    Ok(EcsEvent {
        event: EventFields {
            category: vec![kind.category.to_string()],
            types: vec![registry_type(kind, fields).to_string()],
            action: Some(kind.action.to_string()),
            dataset: Some(format!("{SYSMON_MODULE}.{}", kind.category)),
            ..base.event.clone()
        },
        user: user_fields(fields),
        source: non_empty(EndpointFields {
            ip: text(fields, "SourceIp"),
            port: number(fields, "SourcePort")?,
            domain: None,
        }),
        destination: non_empty(EndpointFields {
            ip: text(fields, "DestinationIp"),
            port: number(fields, "DestinationPort")?,
            domain: text(fields, "DestinationHostname"),
        }),
        network: network_fields(fields),
        process: process_fields(kind, fields)?,
        file: file_fields(kind, fields)?,
        registry: text(fields, "TargetObject").map(|path| RegistryFields { path: Some(path) }),
        dns: dns_fields(fields),
        sysmon: kind
            .extras
            .iter()
            .filter_map(|name| text(fields, name).map(|value| ((*name).to_string(), value)))
            .collect(),
        ..base
    })
}


fn unknown_event(base: EcsEvent, raw: RawEvent, seen: &mut SeenIds) -> EcsEvent {
    if seen.insert(raw.event_id) {
        warn!(event_id = raw.event_id, "unmapped Sysmon event id");
    }
    EcsEvent {
        event: EventFields {
            dataset: Some(format!("{SYSMON_MODULE}.unknown")),
            ..base.event.clone()
        },
        sysmon: raw.fields,
        ..base
    }
}


/// Normalises one rendered Sysmon event (XML or JSON) to ECS; an unmapped id yields a minimal event and is logged once per id in `seen`.
pub fn normalise_sysmon(text_input: &str, seen: &mut SeenIds) -> Result<EcsEvent, SysmonError> {
    let raw = parse_event(text_input)?;
    let base = base_event(&raw, event_time(&raw)?);
    let id = raw.event_id.to_string();
    match KINDS.iter().find(|kind| kind.id == id) {
        Some(kind) => known_event(base, kind, &raw.fields),
        None => Ok(unknown_event(base, raw, seen)),
    }
}
