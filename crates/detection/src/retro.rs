//! Retro read: the event ids one compiled Sigma rule matches in a past window of one tenant's events in ClickHouse.

use crate::error::RetroError;
use crate::types::{ElapsedFn, RetroSendFn};
use alerts::store::{check_text, MAX_EVENT_ID_CHARS};
use core_pg::password::{read_limited, read_password};
use core_pg::scope::tenant_scope;
use serde::Deserialize;
use siem_ingest::clickhouse::{classify_reply, classify_transport, exception_code, new_agent, KEY_HEADER, USER_HEADER};
use siem_ingest::error::InsertClass;
use siem_ingest::reader_profile::{changed_statement, is_database_name, pin_clause, profile_refused, read_changed_bytes, url_settings, violations};
use siem_ingest::settings::{check_url, is_loopback_http};
use sigma_sql::compile::{compile_rule, SqlOptions};
use sigma_sql::mapping::FieldMapping;
use std::io::{self, BufRead, BufReader, Read};
use std::path::PathBuf;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::{info, warn};
use ureq::http::StatusCode;
use ureq::Agent;
use zeroize::Zeroizing;


pub const MAX_RETRO_DAYS: i64 = 7;


pub const SECONDS_PER_DAY: i64 = 86_400;


pub const MAX_RETRO_ROWS: usize = 10_000;


pub const MAX_RETRO_BYTES: u64 = 4_194_304;


pub const MAX_TIMEOUT_MS: u64 = 300_000;


pub const MAX_CA_BYTES: u64 = 65_536;


pub const MAX_USER_BYTES: usize = 128;


pub const MAX_EXECUTION_SECONDS: u32 = 300;


pub const MAX_ROWS_TO_READ: u64 = 10_000_000_000;


pub const PARAM_PREFIX: &str = "param_";


pub const EVENTS_TABLE: &str = "events";


pub const ID_COLUMN: &str = "event.id";


pub const TIMEOUT_CODES: [u32; 2] = [159, 160];


pub const READ_LIMIT_CODES: [u32; 2] = [158, 396];


pub const WINDOW_FILTER: &str =
    "`tenant` = {tenant:String} AND `@timestamp` >= toDateTime({start:UInt32}, 'UTC') AND `@timestamp` < toDateTime({end:UInt32}, 'UTC')";


/// The reader identity (`SELECT` on the events table, never the ingest writer) and the budget of one read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetroSettings {
    pub url: String,
    pub user: String,
    pub password_file: PathBuf,
    pub ca_file: Option<PathBuf>,
    pub database: String,
    pub timeout_ms: u64,
    pub max_rows: usize,
    pub max_execution_seconds: u32,
    pub max_rows_to_read: u64,
}


/// One request: the statement in the body, server settings and `param_` values in the URL, under what is left of the deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetroRequest {
    pub statement: String,
    pub settings: Vec<(&'static str, String)>,
    pub params: Vec<(&'static str, String)>,
    pub remaining: Duration,
}


/// The status, the exception code header and the unread body.
pub struct RetroReply {
    pub status: StatusCode,
    pub code: Option<u32>,
    pub body: Box<dyn Read>,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdRow {
    #[serde(rename = "event.id")]
    pub event_id: String,
}


/// The ids that passed the grammar, how many event ids were refused alone, and how many rows were read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetroIds {
    pub ids: Vec<String>,
    pub refused: usize,
    pub rows: usize,
}


/// `Complete` holds every match; `RowCap` means more matched than `cap`, the ids are the first ones in time order and the rest is unread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetroOutcome {
    Complete(RetroIds),
    RowCap { found: RetroIds, cap: usize },
}


/// What to read: one rule text, one tenant, one window `[start, end)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetroQuery {
    pub rule_text: String,
    pub tenant: String,
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,
}


/// Checks the URL, the user, the database name and every bound before any I/O.
pub fn validate_retro(settings: &RetroSettings) -> Result<(), RetroError> {
    check_url(&settings.url).map_err(RetroError::Url)?;
    let user_ok =
        !settings.user.is_empty() && settings.user.len() <= MAX_USER_BYTES && settings.user.chars().all(|character| character.is_ascii_graphic());
    if !user_ok {
        Err(RetroError::Settings("user"))
    } else if !is_database_name(&settings.database) {
        Err(RetroError::Settings("database"))
    } else if settings.timeout_ms == 0 || settings.timeout_ms > MAX_TIMEOUT_MS {
        Err(RetroError::Settings("timeout_ms"))
    } else if settings.max_rows == 0 || settings.max_rows > MAX_RETRO_ROWS {
        Err(RetroError::Settings("max_rows"))
    } else if settings.max_execution_seconds == 0 || settings.max_execution_seconds > MAX_EXECUTION_SECONDS {
        Err(RetroError::Settings("max_execution_seconds"))
    } else if settings.max_rows_to_read == 0 || settings.max_rows_to_read > MAX_ROWS_TO_READ {
        Err(RetroError::Settings("max_rows_to_read"))
    } else {
        Ok(())
    }
}


/// Both ends as epoch seconds in `u32`; an empty, reversed or over-long window is refused.
pub fn window_epochs(start: OffsetDateTime, end: OffsetDateTime) -> Result<(u32, u32), RetroError> {
    let first = u32::try_from(start.unix_timestamp()).map_err(|_| RetroError::Window)?;
    let last = u32::try_from(end.unix_timestamp()).map_err(|_| RetroError::Window)?;
    if first >= last {
        Err(RetroError::Window)
    } else if i64::from(last) - i64::from(first) > MAX_RETRO_DAYS * SECONDS_PER_DAY {
        Err(RetroError::WindowTooLong(MAX_RETRO_DAYS))
    } else {
        Ok((first, last))
    }
}


/// The reader's own limits (never `max_result_rows`, which the statement sets itself).
pub fn retro_limits(settings: &RetroSettings) -> Vec<(&'static str, String)> {
    vec![
        ("max_execution_time", settings.max_execution_seconds.to_string()),
        ("max_rows_to_read", settings.max_rows_to_read.to_string()),
    ]
}


/// The compiled rule, then tenant and window as `param_` values, a stable order, `max_rows + 1` rows at most and every pin in its own `SETTINGS` clause.
pub fn retro_statement(rule_text: &str, mapping: &FieldMapping, settings: &RetroSettings) -> Result<String, RetroError> {
    let options = SqlOptions {
        table: EVENTS_TABLE.to_owned(),
        id_column: ID_COLUMN.to_owned(),
    };
    let compiled = compile_rule(rule_text, mapping, &options).map_err(RetroError::Rule)?;
    let pins = pin_clause(&retro_limits(settings), settings.max_rows as u64 + 1);
    Ok(format!(
        "{compiled} AND {WINDOW_FILTER} ORDER BY `@timestamp`, `event.id` LIMIT {{limit:UInt64}}{pins} FORMAT JSONEachRow"
    ))
}


/// Only the status and the numeric exception code are read, never the server's text.
pub fn refusal(status: StatusCode, code: Option<u32>) -> Option<RetroError> {
    classify_reply(status, code).map(|class| match code {
        Some(found) if TIMEOUT_CODES.contains(&found) => RetroError::Timeout,
        Some(found) if READ_LIMIT_CODES.contains(&found) => RetroError::ReadLimit,
        _ => RetroError::Refused(class),
    })
}


/// The refusal of the settings check: an error the profile caused is `ReaderProfileChanged`, never a data error.
pub fn check_refusal(status: StatusCode, code: Option<u32>) -> Option<RetroError> {
    refusal(status, code).map(|error| {
        if profile_refused(code) {
            RetroError::ReaderProfileChanged(1)
        } else {
            error
        }
    })
}


/// One request under what is left of the deadline; a spent deadline sends nothing.
pub fn fetch_with(
    send: &RetroSendFn<'_>,
    settings: &RetroSettings,
    elapsed: &ElapsedFn<'_>,
    statement: &str,
    params: Vec<(&'static str, String)>,
    refuse: fn(StatusCode, Option<u32>) -> Option<RetroError>,
) -> Result<RetroReply, RetroError> {
    let remaining = Duration::from_millis(settings.timeout_ms).saturating_sub(elapsed());
    if remaining.is_zero() {
        Err(RetroError::Timeout)
    } else {
        let reply = send(&RetroRequest {
            statement: statement.to_owned(),
            settings: url_settings(Some(&settings.database)),
            params,
            remaining,
        })
        .map_err(RetroError::Refused)?;
        refuse(reply.status, reply.code).map_or(Ok(reply), Err)
    }
}


/// A read error maps to a fixed variant: the `io::Error` of a body reader may carry transport text.
pub fn body_failure(error: &io::Error) -> RetroError {
    if error.kind() == io::ErrorKind::TimedOut {
        RetroError::Timeout
    } else {
        RetroError::Body(error.kind())
    }
}


/// The reader's changed settings: a name outside the pins, a pinned name missing or a reply over the cap refuses, counted and never named.
pub fn read_changed(reply: RetroReply, settings: &RetroSettings) -> Result<(), RetroError> {
    let bytes = read_changed_bytes(reply.body).map_err(|error| body_failure(&error))?;
    let found = violations(&bytes, &retro_limits(settings), Some(&settings.database));
    if found > 0 {
        Err(RetroError::ReaderProfileChanged(found))
    } else {
        Ok(())
    }
}


/// A control character in an id is refused too: the ids go into alerts and logs.
pub fn id_allowed(event_id: &str) -> bool {
    check_text("event_id", event_id, MAX_EVENT_ID_CHARS).is_ok() && !event_id.chars().any(char::is_control)
}


/// A line that does not parse is an error (a fixed query with JSON-escaped fields: a bad line is a server abnormality); a bad id is refused alone.
pub fn absorb(mut found: RetroIds, line: io::Result<String>, cap: usize) -> Result<RetroIds, RetroError> {
    let text = line.map_err(|error| body_failure(&error))?;
    let row = serde_json::from_str::<IdRow>(&text).map_err(|_| RetroError::MalformedReply)?;
    found.rows += 1;
    if found.rows > cap + 1 {
        Err(RetroError::TooManyRows(cap))
    } else if found.rows > cap {
        Ok(found)
    } else if id_allowed(&row.event_id) {
        found.ids.push(row.event_id);
        Ok(found)
    } else {
        found.refused += 1;
        Ok(found)
    }
}


/// The body is read through `take(MAX_RETRO_BYTES + 1)`: more bytes, or a cut reply, is an error and nothing is returned.
pub fn read_ids(reply: RetroReply, cap: usize) -> Result<RetroOutcome, RetroError> {
    let mut reader = BufReader::new(reply.body.take(MAX_RETRO_BYTES + 1));
    let collected = reader
        .by_ref()
        .lines()
        .try_fold(RetroIds::default(), |found, line| absorb(found, line, cap));
    let over_cap = reader.get_ref().limit() == 0;
    let found = if over_cap {
        Err(RetroError::TooManyBytes(MAX_RETRO_BYTES))
    } else {
        collected
    }?;
    if found.rows > cap {
        Ok(RetroOutcome::RowCap { found, cap })
    } else {
        Ok(RetroOutcome::Complete(found))
    }
}


/// Settings check first, then the read, all under the one deadline `timeout_ms`.
pub fn retro_run(
    settings: &RetroSettings,
    mapping: &FieldMapping,
    query: &RetroQuery,
    elapsed: &ElapsedFn<'_>,
    send: &RetroSendFn<'_>,
) -> Result<RetroOutcome, RetroError> {
    validate_retro(settings)?;
    tenant_scope(&query.tenant).map_err(|_| RetroError::Tenant)?;
    let (first, last) = window_epochs(query.start, query.end)?;
    let statement = retro_statement(&query.rule_text, mapping, settings)?;
    fetch_with(send, settings, elapsed, &changed_statement(), Vec::new(), check_refusal).and_then(|reply| read_changed(reply, settings))?;
    let params = vec![
        ("tenant", query.tenant.clone()),
        ("start", first.to_string()),
        ("end", last.to_string()),
        ("limit", (settings.max_rows + 1).to_string()),
    ];
    let outcome = fetch_with(send, settings, elapsed, &statement, params, refusal).and_then(|reply| read_ids(reply, settings.max_rows))?;
    let capped = matches!(outcome, RetroOutcome::RowCap { .. });
    info!(capped, "retro read done");
    Ok(outcome)
}


/// The real sender: one POST, the statement as body, no redirect, the server's text never read.
pub fn send_request(agent: &Agent, settings: &RetroSettings, password: &str, request: &RetroRequest) -> Result<RetroReply, InsertClass> {
    let base = agent.post(&settings.url).header(USER_HEADER, &settings.user).header(KEY_HEADER, password);
    let with_settings = request.settings.iter().fold(base, |builder, (name, value)| builder.query(*name, value));
    let with_params = request.params.iter().fold(with_settings, |builder, (name, value)| {
        builder.query(format!("{PARAM_PREFIX}{name}"), value)
    });
    with_params
        .config()
        .timeout_global(Some(request.remaining))
        .http_status_as_error(false)
        .build()
        .send(request.statement.as_str())
        .map(|response| RetroReply {
            status: response.status(),
            code: exception_code(response.headers()),
            body: Box::new(response.into_body().into_reader()),
        })
        .map_err(|error| classify_transport(&error))
}


/// Settings validated first, then the password and CA are read through checked handles, then the run goes through `send_request`.
pub fn run_retro(settings: &RetroSettings, mapping: &FieldMapping, query: &RetroQuery, elapsed: &ElapsedFn<'_>) -> Result<RetroOutcome, RetroError> {
    validate_retro(settings)?;
    let password_bytes = read_password(&settings.password_file).map_err(RetroError::Password)?;
    let password = Zeroizing::new(std::str::from_utf8(&password_bytes).map_err(RetroError::PasswordEncoding)?.to_owned());
    let pem = settings
        .ca_file
        .as_deref()
        .map(|path| read_limited(path, MAX_CA_BYTES).map_err(RetroError::CaFile))
        .transpose()?;
    let agent = new_agent(pem.as_deref().map(Vec::as_slice), !is_loopback_http(&settings.url)).map_err(RetroError::Agent)?;
    let result = retro_run(settings, mapping, query, elapsed, &|request| {
        send_request(&agent, settings, &password, request)
    });
    if result.is_err() {
        warn!("retro read failed");
    }
    result
}
