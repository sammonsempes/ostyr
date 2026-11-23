use crate::error::shown_id;
use crate::model::{HuntPack, Source};
use chrono::{DateTime, Datelike, Utc};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope};
use metric_alerts::fetch::{class_text, escape_param, FetchSettings, FORMAT_SUFFIX, PARAM_PREFIX};
use siem_ingest::clickhouse::{classify_reply, classify_transport, exception_code, KEY_HEADER, USER_HEADER};
use siem_ingest::error::InsertClass;
use siem_ingest::reader_profile::{changed_statement, pin_clause, profile_refused, read_changed_bytes, url_settings, violations};
use std::io::{self, Read};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::warn;
use ureq::http::Response;
use ureq::{Agent, Body};


pub const MAX_COUNT_BYTES: u64 = 64;


pub const COUNT_ROWS: u64 = 1;


pub const WINDOW_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.3f";


pub const MIN_YEAR: i32 = 0;


pub const MAX_YEAR: i32 = 9999;


pub const COST_CODES: [u32; 4] = [158, 159, 307, 396];


pub const SETTINGS_WORD: &str = "settings";


pub const READONLY_CODE: u32 = 164;


pub const QUERY_CODES: [u32; 2] = [62, 47];


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackRefusal {
    Cost,
    ReadOnly,
    Query,
}


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
    #[error("pack refused: the query names SETTINGS")]
    PackSettings,
    #[error("the window leaves the supported date range")]
    Window,
    #[error("run refused: {}", class_text(*.0))]
    Failed(InsertClass),
    #[error("{}", refusal_text(*.0))]
    PackRefused(PackRefusal),
    #[error("reader_profile_changed: {0} setting(s) outside the allowed list")]
    ReaderProfileChanged(usize),
    #[error("the reply body could not be read")]
    Body(#[source] io::Error),
    #[error("the reply is not one unsigned count")]
    Malformed,
}


/// Fixed text per refusal class; a scheduler must not retry these as an outage.
pub fn refusal_text(refusal: PackRefusal) -> &'static str {
    match refusal {
        PackRefusal::Cost => "pack refused: over its cost limit",
        PackRefusal::ReadOnly => "pack refused: it writes under a read-only run",
        PackRefusal::Query => "pack refused: the query is not valid",
    }
}


/// The pack-specific class of an error reply, decided on the ClickHouse exception code only.
pub fn pack_refusal(code: Option<u32>) -> Option<PackRefusal> {
    code.and_then(|found| {
        if COST_CODES.contains(&found) {
            Some(PackRefusal::Cost)
        } else if found == READONLY_CODE {
            Some(PackRefusal::ReadOnly)
        } else {
            QUERY_CODES.contains(&found).then_some(PackRefusal::Query)
        }
    })
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


/// True when the text holds the word `settings` in any case, comments and string literals included: a pack's own `SETTINGS` clause could lift a cost pin.
pub fn mentions_settings(query: &str) -> bool {
    let bytes = query.as_bytes();
    let is_word = |position: Option<usize>| {
        position
            .and_then(|index| bytes.get(index))
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    };
    query
        .to_ascii_lowercase()
        .match_indices(SETTINGS_WORD)
        .any(|(start, found)| !is_word(start.checked_sub(1)) && !is_word(Some(start + found.len())))
}


/// The pack query wrapped in a count, with the pins in the outer `SETTINGS` clause; a newline before the closing parenthesis keeps a trailing line comment from eating it.
pub fn count_statement(query: &str, limits: &[(&'static str, String)]) -> String {
    let body = query.trim_end().trim_end_matches(';').trim_end();
    let pins = pin_clause(limits, COUNT_ROWS);
    format!("SELECT count() FROM (\n{body}\n){pins}{FORMAT_SUFFIX}")
}


/// The pack's own cost limits: pinned in each statement's clause, never in the URL, so a profile cannot override them.
pub fn pack_limits(pack: &HuntPack) -> Result<Vec<(&'static str, String)>, RunError> {
    let bytes = pack.cost.max_bytes_read.ok_or(RunError::NoByteLimit)?;
    Ok(vec![
        ("max_execution_time", pack.cost.max_seconds.to_string()),
        ("max_rows_to_read", pack.cost.max_rows.to_string()),
        ("max_bytes_to_read", bytes.to_string()),
    ])
}


/// The time left of the one deadline (`budget` reads it now); a spent budget sends nothing.
pub fn left_of(budget: &dyn Fn() -> Duration) -> Result<Duration, RunError> {
    let left = budget();
    if left.is_zero() {
        Err(RunError::Failed(InsertClass::Timeout))
    } else {
        Ok(left)
    }
}


/// One POST: the two URL settings, the parameters (escaped) as query values, the statement as body; only a transport failure is an error here.
pub fn send_statement(
    agent: &Agent,
    settings: &FetchSettings,
    password: &str,
    statement: &str,
    params: &[(&str, &str)],
    remaining: Duration,
) -> Result<Response<Body>, RunError> {
    let with_url = url_settings(settings.database.as_deref())
        .iter()
        .fold(agent.post(&settings.url), |builder, (name, value)| builder.query(*name, value));
    let builder = params.iter().fold(with_url, |builder, (name, value)| {
        builder.query(format!("{PARAM_PREFIX}{name}"), escape_param(value))
    });
    builder
        .header(USER_HEADER, &settings.user)
        .header(KEY_HEADER, password)
        .config()
        .timeout_global(Some(remaining))
        .http_status_as_error(false)
        .build()
        .send(statement)
        .map_err(|error| RunError::Failed(classify_transport(&error)))
}


/// The settings check before the pack runs: a profile that changes anything outside the pins is `ReaderProfileChanged`, never a pack refusal.
pub fn check_profile(
    agent: &Agent,
    settings: &FetchSettings,
    password: &str,
    limits: &[(&'static str, String)],
    remaining: Duration,
) -> Result<(), RunError> {
    let response = send_statement(agent, settings, password, &changed_statement(), &[], remaining)?;
    let code = exception_code(response.headers());
    match classify_reply(response.status(), code) {
        Some(_) if profile_refused(code) => Err(RunError::ReaderProfileChanged(1)),
        Some(class) => Err(RunError::Failed(class)),
        None => {
            let bytes = read_changed_bytes(response.into_body().into_reader()).map_err(RunError::Body)?;
            let found = violations(&bytes, limits, settings.database.as_deref());
            if found > 0 {
                Err(RunError::ReaderProfileChanged(found))
            } else {
                Ok(())
            }
        }
    }
}


/// Nothing is sent for an osquery pack, a bad tenant, a bad window or a spent deadline. The tenant always comes from the caller. Settings check first, then the count, under one deadline.
pub fn execute_pack_timed(
    agent: &Agent,
    settings: &FetchSettings,
    password: &str,
    pack: &HuntPack,
    tenant: &str,
    now: u64,
    budget: &dyn Fn() -> Duration,
) -> Result<HuntOutcome, RunError> {
    (pack.source == Source::Clickhouse).then_some(()).ok_or(RunError::UnsupportedSource)?;
    let scope = tenant_scope(tenant).map_err(RunError::Tenant)?;
    let window_end = window_text(now)?;
    let window_start = window_text(now.checked_sub(pack.window_seconds).ok_or(RunError::Window)?)?;
    let limits = pack_limits(pack)?;
    (!mentions_settings(&pack.query)).then_some(()).ok_or(RunError::PackSettings)?;
    check_profile(agent, settings, password, &limits, left_of(budget)?)?;
    let params = [
        ("tenant", tenant_of(&scope)),
        ("window_start", &window_start),
        ("window_end", &window_end),
    ];
    let response = send_statement(
        agent,
        settings,
        password,
        &count_statement(&pack.query, &limits),
        &params,
        left_of(budget)?,
    )?;
    let code = exception_code(response.headers());
    let refusal = pack_refusal(code).filter(|_| !response.status().is_success());
    match (refusal, classify_reply(response.status(), code)) {
        (Some(refused), _) => Err(RunError::PackRefused(refused)),
        (None, Some(class)) => Err(RunError::Failed(class)),
        (None, None) => {
            let matches = read_count(response.into_body().into_reader())?;
            Ok(HuntOutcome {
                matches,
                finding: matches > pack.baseline.max_matches,
            })
        }
    }
}


pub fn execute_pack(
    agent: &Agent,
    settings: &FetchSettings,
    password: &str,
    pack: &HuntPack,
    tenant: &str,
    now: u64,
    remaining: Duration,
) -> Result<HuntOutcome, RunError> {
    let started = Instant::now();
    execute_pack_timed(agent, settings, password, pack, tenant, now, &|| {
        remaining.saturating_sub(started.elapsed())
    })
}


/// The shown tenant: only a tenant `tenant_scope` accepts is named, anything else is `#`.
pub fn shown_tenant(tenant: &str) -> String {
    tenant_scope(tenant).map_or_else(|_| "#".to_owned(), |scope| tenant_of(&scope).to_owned())
}


/// The one log line of a failed run: pack, shown tenant and the fixed error text.
pub fn failure_line(pack: &HuntPack, tenant: &str, error: &RunError) -> String {
    let id = shown_id(&pack.id);
    let shown = shown_tenant(tenant);
    format!("hunt run failed: pack {id} tenant {shown}: {error}")
}


/// Runs one clickhouse pack once for one tenant and window; one `warn!` with the pack id, the tenant and the fixed text per failed run.
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
        let line = failure_line(pack, tenant, error);
        warn!("{line}");
    }
    outcome
}
