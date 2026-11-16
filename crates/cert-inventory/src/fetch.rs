use crate::ct::{json_error, parse_entries};
use crate::error::{FetchError, TransportKind};
use crate::model::{CtLimits, CtOutcome};
use serde::Deserialize;
use siem_ingest::clickhouse::new_agent;
use siem_ingest::settings::{check_url, is_loopback_http};
use std::io::{ErrorKind, Read};
use std::time::Duration;
use ureq::Agent;


pub const MAX_RANGE: u64 = 256;


pub const MAX_STH_BYTES: usize = 16_384;


const STATUS_OK: u16 = 200;


const STATUS_BAD_REQUEST: u16 = 400;


const STATUS_TOO_MANY: u16 = 429;


const STATUS_SERVER_MIN: u16 = 500;


const STATUS_SERVER_MAX: u16 = 599;


/// One log: its base URL (checked by `check_url`), the HTTP agent and the deadline of one whole request, body included.
#[derive(Debug, Clone)]
pub struct CtLog {
    pub agent: Agent,
    pub url: String,
    pub timeout: Duration,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Sth {
    pub tree_size: u64,
    pub timestamp: u64,
}


/// The range asked: `start <= end < tree_size`, at most `MAX_RANGE` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeRequest {
    pub start: u64,
    pub end: u64,
    pub tree_size: u64,
}


/// What the log returned for a range (entries counted with the skipped ones) and where the caller continues.
#[derive(Debug)]
pub struct Fetched {
    pub outcome: CtOutcome,
    pub returned: u64,
    pub next_start: u64,
}


/// The URL must pass `check_url`; the agent follows no redirect, ignores the environment proxy and speaks https unless the URL is loopback http.
pub fn open_log(url: &str, ca_pem: Option<&[u8]>, timeout: Duration) -> Result<CtLog, FetchError> {
    check_url(url).map_err(FetchError::Url)?;
    let agent = new_agent(ca_pem, !is_loopback_http(url)).map_err(FetchError::Agent)?;
    Ok(CtLog {
        agent,
        url: url.trim_end_matches('/').to_string(),
        timeout,
    })
}


pub fn get_sth(log: &CtLog) -> Result<Sth, FetchError> {
    let bytes = get_body(log, "get-sth", MAX_STH_BYTES)?;
    if bytes.len() > MAX_STH_BYTES {
        Err(FetchError::SthTooLarge { max: MAX_STH_BYTES })
    } else {
        Ok(serde_json::from_slice(&bytes).map_err(|error| json_error(&error))?)
    }
}


/// Checks the range before any request, refuses an answer holding more entries than asked, and reports the next start.
pub fn get_range(log: &CtLog, request: &RangeRequest, limits: &CtLimits) -> Result<Fetched, FetchError> {
    check_range(request)?;
    let asked = request.end - request.start + 1;
    let bounded = CtLimits {
        max_entries: limits.max_entries.min(usize::try_from(asked).unwrap_or(usize::MAX)),
        ..*limits
    };
    let query = format!("get-entries?start={}&end={}", request.start, request.end);
    let bytes = get_body(log, &query, limits.max_json_bytes)?;
    let outcome = parse_entries(&bytes, &bounded)?;
    let returned = (outcome.entries.len() + outcome.skipped_malformed + outcome.skipped_unsupported) as u64;
    if returned == 0 {
        Err(FetchError::Empty)
    } else {
        Ok(Fetched {
            outcome,
            returned,
            next_start: request.start + returned,
        })
    }
}


fn check_range(request: &RangeRequest) -> Result<(), FetchError> {
    if request.start > request.end {
        Err(FetchError::StartAfterEnd)
    } else if request.end >= request.tree_size {
        Err(FetchError::BeyondTree {
            end: request.end,
            tree_size: request.tree_size,
        })
    } else if request.end - request.start >= MAX_RANGE {
        Err(FetchError::RangeTooWide { max: MAX_RANGE })
    } else {
        Ok(())
    }
}


/// At most `max + 1` bytes are read, so the caller can tell an oversized body from one exactly at the cap.
fn get_body(log: &CtLog, operation: &str, max: usize) -> Result<Vec<u8>, FetchError> {
    check_url(&log.url).map_err(FetchError::Url)?;
    let mut response = log
        .agent
        .get(format!("{}/ct/v1/{operation}", log.url))
        .config()
        .timeout_global(Some(log.timeout))
        .build()
        .call()
        .map_err(|error| FetchError::Transport(transport_kind(&error)))?;
    let status = response.status().as_u16();
    if status == STATUS_OK {
        let limit = (max as u64).saturating_add(1);
        let mut bytes = Vec::new();
        response
            .body_mut()
            .with_config()
            .limit(limit)
            .reader()
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|_| FetchError::Body)?;
        Ok(bytes)
    } else {
        Err(status_error(status))
    }
}


pub fn status_error(status: u16) -> FetchError {
    match status {
        STATUS_BAD_REQUEST => FetchError::RangeRefused,
        STATUS_TOO_MANY => FetchError::RateLimited,
        STATUS_SERVER_MIN..=STATUS_SERVER_MAX => FetchError::Server,
        other => FetchError::Status(other),
    }
}


/// A TLS refusal (unknown issuer, bad name) surfaces from ureq as an `Io` error of kind `InvalidData`.
fn transport_kind(error: &ureq::Error) -> TransportKind {
    match error {
        ureq::Error::Timeout(_) => TransportKind::Timeout,
        ureq::Error::Io(source) if source.kind() == ErrorKind::InvalidData => TransportKind::Tls,
        _ => TransportKind::Other,
    }
}
