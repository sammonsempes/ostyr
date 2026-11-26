use crate::error::FetchError;
use crate::inventory::{build_inventory, inventory_degraded_nodes, Inventory};
use crate::proxmox::{parse_permissions, parse_resources};
use crate::readonly::check_read_only;
use crate::settings::{validate_settings, FetchSettings};
#[cfg(unix)]
use crate::trusted::read_trusted_text;
use core_config::error::ConfigError;
use core_pg::password::read_password;
use siem_ingest::clickhouse::{classify_transport, new_agent};
use siem_ingest::error::InsertClass;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};
use tracing::warn;
use ureq::Agent;
use zeroize::Zeroizing;


pub const AUTH_HEADER: &str = "Authorization";


pub const AUTH_SCHEME: &str = "PVEAPIToken=";


pub const PERMISSIONS_PATH: &str = "/api2/json/access/permissions";


pub const RESOURCES_PATH: &str = "/api2/json/cluster/resources";


pub const STATUS_OK: u16 = 200;


pub const MAX_CA_BYTES: u64 = 65_536;


pub const TOKEN_PUNCTUATION: &str = "@!=._-";


/// `Authorization: PVEAPIToken=USER@REALM!TOKENID=UUID` (pve.proxmox.com, Proxmox VE API); the token is an ASCII allowlist, so it cannot inject a header line.
pub fn token_header(token: &[u8]) -> Result<Zeroizing<String>, FetchError> {
    let text = std::str::from_utf8(token).map_err(|_| FetchError::TokenShape)?;
    let sound = [
        text.chars()
            .all(|character| character.is_ascii_alphanumeric() || TOKEN_PUNCTUATION.contains(character)),
        text.contains('!'),
        text.contains('='),
    ];
    if sound.iter().all(|check| *check) {
        Ok(Zeroizing::new(format!("{AUTH_SCHEME}{text}")))
    } else {
        Err(FetchError::TokenShape)
    }
}


/// At most `max + 1` bytes are ever buffered; a longer body is refused, never cut.
pub fn read_body(reader: &mut dyn Read, max: u64) -> Result<Vec<u8>, FetchError> {
    let mut bytes = Vec::new();
    Read::take(reader, max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(FetchError::Body)?;
    if bytes.len() as u64 > max {
        Err(FetchError::TooLarge { max })
    } else {
        Ok(bytes)
    }
}


/// One GET under `remaining`; a spent deadline sends nothing, only status 200 is read, and no body of another status is ever read.
pub fn get_body(agent: &Agent, url: &str, header: &str, max: u64, remaining: Duration) -> Result<Vec<u8>, FetchError> {
    if remaining.is_zero() {
        Err(FetchError::Transport(InsertClass::Timeout))
    } else {
        let response = agent
            .get(url)
            .header(AUTH_HEADER, header)
            .config()
            .timeout_global(Some(remaining))
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|error| transport_error(&error))?;
        if response.status().as_u16() == STATUS_OK {
            read_body(&mut response.into_body().into_reader(), max)
        } else {
            Err(FetchError::Status(response.status().as_u16()))
        }
    }
}


#[cfg(unix)]
pub fn read_ca(path: &Path) -> Result<Vec<u8>, ConfigError> {
    read_trusted_text(path, MAX_CA_BYTES).map(String::into_bytes)
}


#[cfg(not(unix))]
pub fn read_ca(path: &Path) -> Result<Vec<u8>, ConfigError> {
    core_config::parse::read_bytes_capped(path, MAX_CA_BYTES)
}


/// A handshake or certificate failure (rustls reports it as an `InvalidData` I/O error that wraps its own error) is told apart from a host that is down.
pub fn is_handshake_failure(error: &ureq::Error) -> bool {
    match error {
        ureq::Error::Rustls(_) | ureq::Error::Tls(_) => true,
        ureq::Error::Io(source) => source.kind() == std::io::ErrorKind::InvalidData && source.get_ref().is_some(),
        _ => false,
    }
}


pub fn transport_error(error: &ureq::Error) -> FetchError {
    if is_handshake_failure(error) {
        FetchError::Certificate
    } else {
        FetchError::Transport(classify_transport(error))
    }
}


/// The CA is read through a judged handle at every run; only that CA is trusted, https only, no redirect, no proxy.
pub fn build_agent(settings: &FetchSettings) -> Result<Agent, FetchError> {
    let pem = read_ca(&settings.ca_file).map_err(FetchError::CaFile)?;
    Ok(new_agent(Some(pem.as_slice()), true)?)
}


pub fn endpoint(settings: &FetchSettings, path: &str) -> String {
    format!("{}{path}", settings.api_url.trim_end_matches('/'))
}


pub fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}


/// Permissions first, then the read-only verdict; the resources are only requested once the token is known to be read-only.
pub fn run_fetch(settings: &FetchSettings) -> Result<Inventory, FetchError> {
    validate_settings(settings)?;
    let agent = build_agent(settings)?;
    let token = read_password(&settings.token_file).map_err(FetchError::TokenFile)?;
    let header = token_header(&token)?;
    let deadline = Instant::now() + Duration::from_millis(settings.timeout_ms);
    let max = settings.limits.max_bytes;
    let permissions_body = get_body(&agent, &endpoint(settings, PERMISSIONS_PATH), &header, max, remaining(deadline))?;
    let permissions = parse_permissions(permissions_body.as_slice(), &settings.limits).map_err(FetchError::Permissions)?;
    check_read_only(&permissions).map_err(FetchError::WritableCredential)?;
    let resources_body = get_body(&agent, &endpoint(settings, RESOURCES_PATH), &header, max, remaining(deadline))?;
    let parsed = parse_resources(resources_body.as_slice(), &settings.limits).map_err(FetchError::Resources)?;
    Ok(build_inventory(&settings.tenant, &settings.cluster, parsed)?)
}


/// No inventory on any error; a failure is logged with its fixed text, a degraded read with the node names.
pub fn fetch_inventory(settings: &FetchSettings) -> Result<Inventory, FetchError> {
    let outcome = run_fetch(settings);
    match &outcome {
        Ok(inventory) => {
            let nodes = inventory_degraded_nodes(inventory).join(",");
            if !nodes.is_empty() {
                warn!("degraded read, every guest unknown on: {nodes}");
            }
        }
        Err(error) => {
            let text = error.to_string();
            warn!("proxmox fetch refused: {text}");
        }
    }
    outcome
}
