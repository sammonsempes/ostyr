use crate::config::OtlpConfig;
use crate::ecs::{to_json, EcsEvent};
use crate::error::ExportError;
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use ureq::http::Uri;


pub const MAX_TOKEN_BYTES: usize = 4096;


pub const TOKEN_READ_LIMIT: u64 = 4097;


pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024;


pub const SERVICE_NAME_KEY: &str = "service.name";


pub const TENANT_KEY: &str = "tenant.id";


pub const SCOPE_NAME: &str = "ostyr";


#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Count {
    Number(u64),
    Text(String),
}


#[derive(Debug, Default, Deserialize)]
pub struct PartialSuccess {
    #[serde(rename = "rejectedLogRecords")]
    pub rejected: Option<Count>,
}


#[derive(Debug, Default, Deserialize)]
pub struct LogsResponse {
    #[serde(rename = "partialSuccess")]
    pub partial_success: Option<PartialSuccess>,
}


/// Reads the bearer token: at most `MAX_TOKEN_BYTES`, surrounding whitespace removed, never echoed in an error.
pub fn read_token(path: &Path) -> Result<String, ExportError> {
    let shown = path.display().to_string();
    let io_error = |source: std::io::Error| ExportError::Io {
        context: format!("read token file {shown}"),
        source,
    };
    let mut text = String::new();
    File::open(path)
        .map_err(io_error)?
        .take(TOKEN_READ_LIMIT)
        .read_to_string(&mut text)
        .map_err(io_error)?;
    let token = text.trim();
    if text.len() > MAX_TOKEN_BYTES {
        Err(ExportError::TokenTooLarge {
            path: shown,
            max: MAX_TOKEN_BYTES,
        })
    } else if token.is_empty() {
        Err(ExportError::TokenEmpty(shown))
    } else if token.chars().any(char::is_control) {
        Err(ExportError::TokenInvalid(shown))
    } else {
        Ok(token.to_string())
    }
}


pub fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok_and(|address| address.is_loopback())
}


/// `https://` always; `http://` only for a loopback host, with `allow_insecure_loopback` and without a token.
pub fn check_endpoint(config: &OtlpConfig) -> Result<(), ExportError> {
    let uri = config
        .endpoint
        .parse::<Uri>()
        .map_err(|_invalid| ExportError::Invalid("endpoint is not a valid URL"))?;
    match uri.scheme_str() {
        Some("https") => Ok(()),
        Some("http") if !config.allow_insecure_loopback => Err(ExportError::Invalid("endpoint must use https")),
        Some("http") if config.token_file.is_some() => Err(ExportError::Invalid("a token is never sent over http")),
        Some("http") if !uri.host().is_some_and(is_loopback_host) => Err(ExportError::Invalid("http is allowed for a loopback host only")),
        Some("http") => Ok(()),
        _ => Err(ExportError::Invalid("endpoint must start with https://")),
    }
}


/// Checks the settings and reads the token once; the returned token is the one that was checked.
pub fn prepare_otlp(config: &OtlpConfig) -> Result<Option<String>, ExportError> {
    check_endpoint(config)?;
    if config.batch_size == 0 {
        Err(ExportError::Invalid("batch_size must be at least 1"))
    } else {
        config.token_file.as_deref().map(|path| read_token(Path::new(path))).transpose()
    }
}


/// Error category and position only: the message of a serde error quotes the receiver's text.
pub fn describe_response_error(error: &serde_json::Error) -> String {
    format!("{:?} at line {} column {}", error.classify(), error.line(), error.column())
}


pub fn string_attribute(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}


/// One OTLP log record: the ECS JSON is the body, `@timestamp` is `timeUnixNano` (a decimal string, as OTLP JSON encodes fixed64).
pub fn log_record(event: &EcsEvent) -> Result<Value, ExportError> {
    let nanos = event.timestamp.unix_timestamp_nanos().max(0);
    Ok(json!({ "timeUnixNano": nanos.to_string(), "body": { "stringValue": to_json(event)? } }))
}


/// The `ExportLogsServiceRequest` JSON for already built records.
pub fn request_body(records: Vec<Value>, config: &OtlpConfig) -> String {
    let attributes: Vec<Value> = [
        Some(string_attribute(SERVICE_NAME_KEY, &config.service_name)),
        config.tenant.as_deref().map(|tenant| string_attribute(TENANT_KEY, tenant)),
    ]
    .into_iter()
    .flatten()
    .collect();
    json!({
        "resourceLogs": [{
            "resource": { "attributes": attributes },
            "scopeLogs": [{ "scope": { "name": SCOPE_NAME }, "logRecords": records }]
        }]
    })
    .to_string()
}


/// Chunks of at most `batch_size` events (at least one), each with its event count and request body.
pub fn otlp_batches(events: &[EcsEvent], config: &OtlpConfig) -> Result<Vec<(usize, String)>, ExportError> {
    events
        .chunks(config.batch_size.max(1))
        .map(|chunk| {
            let records = chunk.iter().map(log_record).collect::<Result<Vec<_>, _>>()?;
            Ok((chunk.len(), request_body(records, config)))
        })
        .collect()
}


/// The `rejectedLogRecords` of a response body (a number or a decimal string); 0 when absent or unreadable, which is logged.
pub fn rejected_records(body: &str) -> u64 {
    if body.trim().is_empty() {
        0
    } else {
        serde_json::from_str::<LogsResponse>(body).map_or_else(
            |error| {
                let detail = describe_response_error(&error);
                tracing::warn!(%detail, "OTLP response is not a valid ExportLogsServiceResponse");
                0
            },
            |response| match response.partial_success.and_then(|partial| partial.rejected) {
                Some(Count::Number(count)) => count,
                Some(Count::Text(text)) => text.parse::<u64>().unwrap_or_else(|error| {
                    tracing::warn!(%error, "OTLP rejectedLogRecords is not a number");
                    0
                }),
                None => 0,
            },
        )
    }
}
