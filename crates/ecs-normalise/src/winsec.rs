use crate::error::{SysmonError, WinSecError};
use crate::suricata::{clean, clean_identity, non_empty};
use crate::sysmon::WINDOWS_OS_TYPE;
use crate::sysmon_input::{parse_event, RawEvent};
use crate::types::Fields;
use core_export::ecs::{blank_event, EcsEvent, EndpointFields, EventFields, HostFields, OsFields, UserFields};
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::warn;


pub const SECURITY_PROVIDER: &str = "Microsoft-Windows-Security-Auditing";


pub const SECURITY_CHANNEL: &str = "Security";


pub const WINSEC_MODULE: &str = "windows";


pub const WINSEC_DATASET: &str = "windows.security";


const NO_VALUE: &str = "-";


const MAX_STATUS_DIGITS: usize = 8;


const HEX_RADIX: u32 = 16;


const SUCCESS: &str = "success";


const FAILURE: &str = "failure";


const AUTHENTICATION: &str = "authentication";


const IAM: &str = "iam";


/// How the `event.outcome` of an id is decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeRule {
    Success,
    Failure,
    FromStatus,
}


/// One supported Security event id: its ECS classification.
#[derive(Debug, Clone, Copy)]
pub struct WinKind {
    pub id: &'static str,
    pub action: &'static str,
    pub categories: &'static [&'static str],
    pub kind_type: &'static str,
    pub outcome: OutcomeRule,
}


pub const WIN_KINDS: &[WinKind] = &[
    WinKind {
        id: "4624",
        action: "logged-in",
        categories: &[AUTHENTICATION],
        kind_type: "start",
        outcome: OutcomeRule::Success,
    },
    WinKind {
        id: "4625",
        action: "logon-failed",
        categories: &[AUTHENTICATION],
        kind_type: "start",
        outcome: OutcomeRule::Failure,
    },
    WinKind {
        id: "4634",
        action: "logged-out",
        categories: &[AUTHENTICATION],
        kind_type: "end",
        outcome: OutcomeRule::Success,
    },
    WinKind {
        id: "4647",
        action: "logged-out",
        categories: &[AUTHENTICATION],
        kind_type: "end",
        outcome: OutcomeRule::Success,
    },
    WinKind {
        id: "4648",
        action: "explicit-credentials-logon",
        categories: &[AUTHENTICATION],
        kind_type: "info",
        outcome: OutcomeRule::Success,
    },
    WinKind {
        id: "4672",
        action: "special-privileges-assigned",
        categories: &[AUTHENTICATION],
        kind_type: "info",
        outcome: OutcomeRule::Success,
    },
    WinKind {
        id: "4720",
        action: "added-user-account",
        categories: &[AUTHENTICATION, IAM],
        kind_type: "creation",
        outcome: OutcomeRule::Success,
    },
    WinKind {
        id: "4726",
        action: "deleted-user-account",
        categories: &[AUTHENTICATION, IAM],
        kind_type: "deletion",
        outcome: OutcomeRule::Success,
    },
    WinKind {
        id: "4740",
        action: "locked-out-user-account",
        categories: &[AUTHENTICATION, IAM],
        kind_type: "info",
        outcome: OutcomeRule::Success,
    },
    WinKind {
        id: "4768",
        action: "kerberos-tgt-requested",
        categories: &[AUTHENTICATION],
        kind_type: "info",
        outcome: OutcomeRule::FromStatus,
    },
    WinKind {
        id: "4769",
        action: "kerberos-service-ticket-requested",
        categories: &[AUTHENTICATION],
        kind_type: "info",
        outcome: OutcomeRule::FromStatus,
    },
    WinKind {
        id: "4771",
        action: "kerberos-preauth-failed",
        categories: &[AUTHENTICATION],
        kind_type: "info",
        outcome: OutcomeRule::Failure,
    },
    WinKind {
        id: "4776",
        action: "ntlm-credential-validation",
        categories: &[AUTHENTICATION],
        kind_type: "info",
        outcome: OutcomeRule::FromStatus,
    },
];


fn text(fields: &Fields, name: &str) -> Option<String> {
    fields.get(name).filter(|value| !value.is_empty() && value.as_str() != NO_VALUE).cloned()
}


fn first_text(fields: &Fields, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| text(fields, name))
}


fn hex_value(value: &str) -> Option<u32> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .filter(|digits| (1..=MAX_STATUS_DIGITS).contains(&digits.len()))
        .and_then(|digits| {
            digits.chars().try_fold(u32::default(), |total, digit| {
                digit.to_digit(HEX_RADIX).map(|part| total * HEX_RADIX + part)
            })
        })
}


fn status(fields: &Fields, name: &str) -> Option<(String, u32)> {
    text(fields, name).and_then(|value| {
        let number = hex_value(&value);
        if number.is_none() {
            warn!(field = name, "not a hexadecimal status");
        }
        number.map(|found| (clean(&value), found))
    })
}


fn small_number(fields: &Fields, name: &str) -> Option<u16> {
    text(fields, name).and_then(|value| match value.parse::<u16>() {
        Ok(found) => Some(found),
        Err(error) => {
            let reason = error.to_string();
            warn!(field = name, reason, "not a small number");
            None
        }
    })
}


fn source_address(fields: &Fields) -> Option<String> {
    text(fields, "IpAddress").and_then(|value| match value.parse::<IpAddr>() {
        Ok(address) => Some(address.to_string()),
        Err(error) => {
            let reason = error.to_string();
            warn!(reason, "IpAddress is not an address");
            None
        }
    })
}


fn outcome_of(kind: &WinKind, fields: &Fields) -> Option<&'static str> {
    match kind.outcome {
        OutcomeRule::Success => Some(SUCCESS),
        OutcomeRule::Failure => Some(FAILURE),
        OutcomeRule::FromStatus => status(fields, "Status").map(|(_, number)| if number == 0 { SUCCESS } else { FAILURE }),
    }
}


fn user_fields(fields: &Fields) -> Option<UserFields> {
    non_empty(UserFields {
        name: first_text(fields, &["TargetUserName", "SubjectUserName"]).map(|name| clean_identity(&name)),
        domain: first_text(fields, &["TargetDomainName", "SubjectDomainName"]).map(|domain| clean_identity(&domain)),
        id: None,
    })
}


fn labels(fields: &Fields, failed: bool) -> Vec<(String, String)> {
    let logon_type = small_number(fields, "LogonType").map(|found| ("logon_type".to_string(), found.to_string()));
    let failure_status = status(fields, "Status")
        .filter(|_| failed)
        .map(|(shown, _)| ("failure_status".to_string(), shown));
    let sub_status = status(fields, "SubStatus")
        .filter(|_| failed)
        .map(|(shown, _)| ("sub_status".to_string(), shown));
    [logon_type, failure_status, sub_status].into_iter().flatten().collect()
}


fn event_time(raw: &RawEvent) -> Result<OffsetDateTime, WinSecError> {
    let system = raw
        .system_time
        .as_deref()
        .ok_or_else(|| WinSecError::from(SysmonError::MissingField("SystemTime")))?;
    OffsetDateTime::parse(system, &Rfc3339).map_err(|error| WinSecError::from(SysmonError::BadTime(error)))
}


fn check_origin(raw: &RawEvent) -> Result<(), WinSecError> {
    let provider = raw.provider.as_deref().unwrap_or("");
    let channel = raw.channel.as_deref().unwrap_or("");
    if provider != SECURITY_PROVIDER {
        Err(WinSecError::Provider(clean(provider)))
    } else if channel != SECURITY_CHANNEL {
        Err(WinSecError::Channel(clean(channel)))
    } else {
        Ok(())
    }
}


fn build(raw: &RawEvent, kind: &WinKind, time: OffsetDateTime) -> EcsEvent {
    let outcome = outcome_of(kind, &raw.fields);
    let failed = outcome == Some(FAILURE);
    EcsEvent {
        event: EventFields {
            kind: Some("event".to_string()),
            code: Some(raw.event_id.to_string()),
            category: kind.categories.iter().map(|category| (*category).to_string()).collect(),
            types: vec![kind.kind_type.to_string()],
            action: Some(kind.action.to_string()),
            outcome: outcome.map(String::from),
            dataset: Some(WINSEC_DATASET.to_string()),
            module: Some(WINSEC_MODULE.to_string()),
            provider: Some(SECURITY_PROVIDER.to_string()),
            ..EventFields::default()
        },
        host: Some(HostFields {
            name: raw.computer.as_ref().filter(|name| !name.is_empty()).map(|name| clean_identity(name)),
            os: Some(OsFields {
                kind: Some(WINDOWS_OS_TYPE.to_string()),
            }),
            ..HostFields::default()
        }),
        user: user_fields(&raw.fields),
        source: non_empty(EndpointFields {
            ip: source_address(&raw.fields),
            port: small_number(&raw.fields, "IpPort"),
            ..EndpointFields::default()
        }),
        labels: labels(&raw.fields, failed).into_iter().collect(),
        ..blank_event(time)
    }
}


/// Normalises one rendered Windows Security event (XML or JSON) to an ECS authentication event; an unmapped id is `WinSecError::Unknown`.
pub fn normalise_security(text_input: &str) -> Result<EcsEvent, WinSecError> {
    let raw = parse_event(text_input)?;
    check_origin(&raw)?;
    let id = raw.event_id.to_string();
    let kind = WIN_KINDS.iter().find(|found| found.id == id).ok_or(WinSecError::Unknown(raw.event_id))?;
    Ok(build(&raw, kind, event_time(&raw)?))
}
