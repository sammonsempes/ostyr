//! Fetches the Redfish documents of one declared BMC with GET requests only and assesses them.

use crate::error::{transport_kind, DiscoverError, FetchError, GetError};
use crate::limits::{
    ACCOUNTS_COLLECTION, ADMINISTRATOR_ROLE, AUTH_CAPACITY, CHASSIS_COLLECTION, HTTP_OK, MAX_CA_BYTES, MAX_ID_BYTES, MAX_MEMBERS, MAX_NESTING_DEPTH,
    SYSTEMS_COLLECTION,
};
use crate::model::{BlindReason, DeviceReport, FetchSession, Health, RedfishDevice, RedfishLimits, RoleCheck};
use crate::redfish::{nesting_depth, parse_redfish};
use crate::redfish_assess::assess_redfish;
use crate::redfish_devices::{base_of, check_device};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use core_pg::password::{read_limited, read_password};
use core_pg::scope::{tenant_of, TenantScope};
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;
use zeroize::Zeroizing;


const BASIC_PREFIX: &str = "Basic ";


const SEGMENT_EXTRA: &str = "._-";


const DOCUMENT_REFUSED: &str = "document refused";


const ADMIN_REFUSED: &str = "administrator credential";


#[derive(Deserialize)]
struct Collection<'a> {
    #[serde(borrow, rename = "Members")]
    members: Option<&'a RawValue>,
}


#[derive(Deserialize)]
struct Reference {
    #[serde(rename = "@odata.id")]
    id: Option<String>,
}


#[derive(Deserialize)]
struct Account {
    #[serde(rename = "UserName")]
    user_name: Option<String>,
    #[serde(rename = "RoleId")]
    role_id: Option<String>,
}


/// `username:password` as Basic, built in buffers that are zeroed on drop.
pub fn basic_header(username: &str, password: &[u8]) -> Zeroizing<String> {
    let mut pair = Zeroizing::new(Vec::with_capacity(AUTH_CAPACITY));
    pair.extend_from_slice(username.as_bytes());
    pair.push(b':');
    pair.extend_from_slice(password);
    let mut header = Zeroizing::new(String::with_capacity(AUTH_CAPACITY));
    header.push_str(BASIC_PREFIX);
    STANDARD.encode_string(&*pair, &mut header);
    header
}


/// Verification is on unless the device says `insecure_skip_verify`; with a CA file only that CA is trusted. No redirect, no proxy, https only.
pub fn build_agent(device: &RedfishDevice) -> Result<Agent, FetchError> {
    let builder = Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .https_only(true)
        .proxy(None);
    let tls = match device.ca_file.as_deref() {
        Some(path) => {
            let pem = read_limited(Path::new(path), MAX_CA_BYTES).map_err(FetchError::CaFile)?;
            let certificate = Certificate::from_pem(&pem).map_err(FetchError::CaInvalid)?;
            TlsConfig::builder().root_certs(RootCerts::Specific(Arc::new(vec![certificate]))).build()
        }
        None => TlsConfig::builder().disable_verification(device.insecure_skip_verify).build(),
    };
    Ok(Agent::new_with_config(builder.tls_config(tls).build()))
}


pub fn get_body(session: &FetchSession, url: &str, left: Duration) -> Result<Vec<u8>, GetError> {
    let mut response = session
        .agent
        .get(url)
        .header("Authorization", session.auth.as_str())
        .config()
        .timeout_global(Some(left))
        .build()
        .call()
        .map_err(|error| GetError::Transport(transport_kind(&error)))?;
    let status = response.status().as_u16();
    if status == HTTP_OK {
        let limit = session.max_bytes.saturating_add(1);
        let mut bytes = Vec::new();
        response
            .body_mut()
            .with_config()
            .limit(limit)
            .reader()
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(GetError::Body)?;
        if bytes.len() as u64 > session.max_bytes {
            Err(GetError::Oversized)
        } else {
            Ok(bytes)
        }
    } else {
        Err(GetError::Status(status))
    }
}


/// A failure gives `None` (a blind spot for the caller); only the document name and the reason class are logged, never a body or a header.
pub fn fetch_document(session: &FetchSession, path: &str, document: &'static str) -> Option<Vec<u8>> {
    let left = session.deadline.checked_duration_since(Instant::now()).unwrap_or(Duration::ZERO);
    let outcome = if left.is_zero() {
        Err(GetError::Expired)
    } else {
        get_body(session, &format!("{}{path}", session.base), left)
    };
    match outcome {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            let reason = error.to_string();
            warn!(document, reason, "redfish document not fetched");
            None
        }
    }
}


pub fn parse_document<'a, Target: Deserialize<'a>>(bytes: &'a [u8]) -> Result<Target, DiscoverError> {
    if nesting_depth(bytes) > MAX_NESTING_DEPTH {
        Err(DiscoverError::TooDeep)
    } else {
        serde_json::from_slice(bytes).map_err(|error| DiscoverError::Malformed { category: error.classify() })
    }
}


/// `prefix` ends with `/`; the rest of the id is one ASCII segment, never `.` or `..`.
pub fn is_member_path(id: &str, prefix: &str) -> bool {
    let segment = id.strip_prefix(prefix).unwrap_or("");
    let clean = segment
        .chars()
        .all(|letter| letter.is_ascii_alphanumeric() || SEGMENT_EXTRA.contains(letter));
    [id.len() <= MAX_ID_BYTES, !segment.is_empty(), segment != ".", segment != "..", clean]
        .iter()
        .all(|accepted| *accepted)
}


/// The members are counted before any is built, and every id must pass `is_member_path`.
pub fn member_paths(body: &[u8], prefix: &str) -> Result<Vec<String>, DiscoverError> {
    let collection: Collection = parse_document(body)?;
    let members = collection.members.ok_or(DiscoverError::NoMembers)?;
    let count = serde_json::from_str::<Vec<IgnoredAny>>(members.get())
        .map_err(|error| DiscoverError::Malformed { category: error.classify() })?
        .len();
    if count > MAX_MEMBERS {
        Err(DiscoverError::TooMany { limit: MAX_MEMBERS })
    } else {
        let references: Vec<Reference> =
            serde_json::from_str(members.get()).map_err(|error| DiscoverError::Malformed { category: error.classify() })?;
        references
            .into_iter()
            .map(|reference| reference.id.filter(|id| is_member_path(id, prefix)).ok_or(DiscoverError::BadId))
            .collect()
    }
}


pub fn collection_paths(session: &FetchSession, collection: &'static str, document: &'static str) -> Vec<String> {
    let prefix = format!("{collection}/");
    let listed = fetch_document(session, collection, document).map(|body| member_paths(&body, &prefix));
    match listed {
        Some(Ok(paths)) => paths,
        Some(Err(error)) => {
            let reason = error.to_string();
            warn!(document, reason, "redfish collection refused");
            Vec::new()
        }
        None => Vec::new(),
    }
}


pub fn role_in(body: &[u8], username: &str) -> Result<Option<RoleCheck>, DiscoverError> {
    let account: Account = parse_document(body)?;
    let role = match account.role_id.as_deref() {
        Some(ADMINISTRATOR_ROLE) => RoleCheck::Administrator,
        Some(_) => RoleCheck::NotAdministrator,
        None => RoleCheck::Unknown,
    };
    Ok((account.user_name.as_deref() == Some(username)).then_some(role))
}


pub fn account_role(session: &FetchSession, path: &str, username: &str) -> Option<RoleCheck> {
    let body = fetch_document(session, path, "account");
    match body.map(|bytes| role_in(&bytes, username)) {
        Some(Ok(found)) => found,
        Some(Err(error)) => {
            let reason = error.to_string();
            warn!(reason, "redfish account refused");
            None
        }
        None => None,
    }
}


/// The role of the configured user as the BMC reports it; `Unknown` when the accounts cannot be read or the user is not found.
pub fn role_of(session: &FetchSession, username: &str) -> RoleCheck {
    collection_paths(session, ACCOUNTS_COLLECTION, "accounts")
        .iter()
        .find_map(|path| account_role(session, path, username))
        .unwrap_or(RoleCheck::Unknown)
}


pub fn reader_of(bytes: &Option<Vec<u8>>) -> Option<Cursor<&[u8]>> {
    bytes.as_deref().map(Cursor::new)
}


pub fn as_dyn<'a>(cursor: &'a mut Option<Cursor<&[u8]>>) -> Option<&'a mut dyn Read> {
    cursor.as_mut().map(|inner| inner as &mut dyn Read)
}


pub fn blind(field: &str) -> Health {
    Health::BlindSpot(BlindReason::UnreadableHealthField(field.to_string()))
}


/// The first Chassis and the first System are read; a missing or refused id leaves its documents missing, which is a blind spot.
pub fn health_of(session: &FetchSession, limits: &RedfishLimits) -> Health {
    let chassis_path = collection_paths(session, CHASSIS_COLLECTION, "chassis collection").into_iter().next();
    let system_path = collection_paths(session, SYSTEMS_COLLECTION, "systems collection").into_iter().next();
    let chassis = chassis_path.as_deref().and_then(|path| fetch_document(session, path, "chassis"));
    let thermal = chassis_path
        .as_deref()
        .and_then(|path| fetch_document(session, &format!("{path}/Thermal"), "thermal"));
    let power = chassis_path
        .as_deref()
        .and_then(|path| fetch_document(session, &format!("{path}/Power"), "power"));
    let system = system_path.as_deref().and_then(|path| fetch_document(session, path, "system"));
    let mut chassis_reader = reader_of(&chassis);
    let mut thermal_reader = reader_of(&thermal);
    let mut power_reader = reader_of(&power);
    let mut system_reader = reader_of(&system);
    let parsed = parse_redfish(
        as_dyn(&mut chassis_reader),
        as_dyn(&mut thermal_reader),
        as_dyn(&mut power_reader),
        as_dyn(&mut system_reader),
        limits,
    );
    match parsed {
        Ok(report) => assess_redfish(&report),
        Err(error) => {
            let reason = error.to_string();
            warn!(reason, "redfish documents refused");
            blind(DOCUMENT_REFUSED)
        }
    }
}


pub fn poll_device(device: &RedfishDevice, tenant: &TenantScope, limits: &RedfishLimits) -> Result<DeviceReport, FetchError> {
    check_device(0, device)?;
    if device.insecure_skip_verify {
        let name = device.name.as_str();
        warn!(name, "redfish device read without certificate verification");
    }
    let password = read_password(Path::new(&device.password_file)).map_err(FetchError::Password)?;
    let session = FetchSession {
        agent: build_agent(device)?,
        auth: basic_header(&device.username, &password),
        base: base_of(device).to_owned(),
        deadline: Instant::now() + Duration::from_millis(device.timeout_ms),
        max_bytes: limits.max_bytes,
    };
    let role = role_of(&session, &device.username);
    let health = match role {
        RoleCheck::Administrator => blind(ADMIN_REFUSED),
        RoleCheck::NotAdministrator | RoleCheck::Unknown => health_of(&session, limits),
    };
    Ok(DeviceReport {
        device: device.name.clone(),
        tenant: tenant_of(tenant).to_owned(),
        health,
        unverified_tls: device.insecure_skip_verify,
        role,
    })
}
