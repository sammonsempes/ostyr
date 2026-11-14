use crate::error::shown_id;
use crate::model::{HuntPack, Source};
use chrono::{DateTime, Datelike, Utc};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope};
use metric_alerts::fetch::{class_text, escape_param, FetchSettings, FORMAT_SUFFIX, PARAM_PREFIX};
use siem_ingest::clickhouse::{classify_reply, classify_transport, exception_code, KEY_HEADER, USER_HEADER};
use siem_ingest::error::InsertClass;
use std::io::{self, Read};
use std::time::Duration;
use thiserror::Error;
use tracing::warn;
use ureq::Agent;


pub const MAX_COUNT_BYTES: u64 = 64;


pub const READONLY_VALUE: &str = "1";


pub const MAX_RESULT_ROWS: &str = "1";


pub const OVERFLOW_MODE: &str = "throw";


pub const WINDOW_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.3f";


pub const MIN_YEAR: i32 = 0;


pub const MAX_YEAR: i32 = 9999;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HuntOutcome {
    pub matches: u64,
    pub finding: bool,
}


/// Every text is fixed: the server's message, the query, the password and the URL never reach an error.
#[derive(Debug, Error)]
pub enum RunError {
    #[error("only a clickhouse pack can run here")]
    UnsupportedSource,
    #[error("the tenant is not valid")]
    Tenant(#[source] PgError),
    #[error("the pack sets no byte limit")]
    NoByteLimit,
    #[error("the window leaves the supported date range")]
    Window,
    #[error("run refused: {}", class_text(*.0))]
    Failed(InsertClass),
    #[error("the reply body could not be read")]
    Body(#[source] io::Error),
    #[error("the reply is not one unsigned count")]
    Malformed,
}


/// The window bound as ClickHouse `DateTime64(3)` text in UTC; a time outside years 0 to 9999 is refused.
pub fn window_text(seconds: u64) -> Result<String, RunError> {
    i64::try_from(seconds)
        .ok()
        .and_then(|value| DateTime::<Utc>::from_timestamp(value, 0))
        .filter(|moment| (MIN_YEAR..=MAX_YEAR).contains(&moment.year()))
        .map(|moment| moment.format(WINDOW_FORMAT).to_string())
        .ok_or(RunError::Window)
}


/// One unsigned decimal count, optionally followed by one newline; nothing else.
pub fn parse_count(bytes: &[u8]) -> Result<u64, RunError> {
    let text = std::str::from_utf8(bytes).map_err(|_| RunError::Malformed)?;
    let digits = text.strip_suffix('\n').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        Err(RunError::Malformed)
    } else {
        digits.parse::<u64>().map_err(|_| RunError::Malformed)
    }
}


/// At most `MAX_COUNT_BYTES + 1` bytes are ever buffered; a longer body is malformed.
pub fn read_count<Source: Read>(reader: Source) -> Result<u64, RunError> {
    let mut bytes = Vec::new();
    reader.take(MAX_COUNT_BYTES + 1).read_to_end(&mut bytes).map_err(RunError::Body)?;
    if bytes.len() as u64 > MAX_COUNT_BYTES {
        Err(RunError::Malformed)
    } else {
        parse_count(&bytes)
    }
}


/// The pack query wrapped in a count; a newline before the closing parenthesis keeps a trailing line comment from eating it.
pub fn count_statement(query: &str) -> String {
    let body = query.trim_end().trim_end_matches(';').trim_end();
    format!("SELECT count() FROM (\n{body}\n){FORMAT_SUFFIX}")
}


/// ClickHouse's own read-only and cost settings, sent as URL parameters on every run.
pub fn server_settings(pack: &HuntPack) -> Result<Vec<(&'static str, String)>, RunError> {
    let bytes = pack.cost.max_bytes_read.ok_or(RunError::NoByteLimit)?;
    Ok(vec![
        ("readonly", READONLY_VALUE.to_string()),
        ("max_execution_time", pack.cost.max_seconds.to_string()),
        ("max_rows_to_read", pack.cost.max_rows.to_string()),
        ("max_bytes_to_read", bytes.to_string()),
        ("max_result_rows", MAX_RESULT_ROWS.to_string()),
        ("result_overflow_mode", OVERFLOW_MODE.to_string()),
    ])
}


/// Nothing is sent for an osquery pack, a bad tenant, a bad window or a spent deadline. The tenant always comes from the caller.
pub fn execute_pack(
    agent: &Agent,
    settings: &FetchSettings,
    password: &str,
    pack: &HuntPack,
    tenant: &str,
    now: u64,
    remaining: Duration,
) -> Result<HuntOutcome, RunError> {
    (pack.source == Source::Clickhouse).then_some(()).ok_or(RunError::UnsupportedSource)?;
    let scope = tenant_scope(tenant).map_err(RunError::Tenant)?;
    let window_end = window_text(now)?;
    let window_start = window_text(now.checked_sub(pack.window_seconds).ok_or(RunError::Window)?)?;
    let server = server_settings(pack)?;
    (!remaining.is_zero()).then_some(()).ok_or(RunError::Failed(InsertClass::Timeout))?;
    let params = [
        ("tenant", tenant_of(&scope)),
        ("window_start", &window_start),
        ("window_end", &window_end),
    ];
    let with_server = server
        .iter()
        .fold(agent.post(&settings.url), |builder, (name, value)| builder.query(*name, value));
    let builder = params.iter().fold(with_server, |builder, (name, value)| {
        builder.query(format!("{PARAM_PREFIX}{name}"), escape_param(value))
    });
    let response = builder
        .header(USER_HEADER, &settings.user)
        .header(KEY_HEADER, password)
        .config()
        .timeout_global(Some(remaining))
        .http_status_as_error(false)
        .build()
        .send(count_statement(&pack.query))
        .map_err(|error| RunError::Failed(classify_transport(&error)))?;
    match classify_reply(response.status(), exception_code(response.headers())) {
        Some(class) => Err(RunError::Failed(class)),
        None => {
            let matches = read_count(response.into_body().into_reader())?;
            Ok(HuntOutcome {
                matches,
                finding: matches > pack.baseline.max_matches,
            })
        }
    }
}


/// Runs one clickhouse pack once for one tenant and window; one `warn!` with the pack id and the fixed text per failed run.
pub fn run_pack(
    agent: &Agent,
    settings: &FetchSettings,
    password: &str,
    pack: &HuntPack,
    tenant: &str,
    now: u64,
    remaining: Duration,
) -> Result<HuntOutcome, RunError> {
    let outcome = execute_pack(agent, settings, password, pack, tenant, now, remaining);
    if let Err(error) = &outcome {
        let text = error.to_string();
        let id = shown_id(&pack.id);
        warn!("hunt run failed: pack {id}: {text}");
    }
    outcome
}
