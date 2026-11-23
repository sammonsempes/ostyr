//! Retro-match of IP indicators against stored events: one tenant, one window, match groups and a run summary; nothing is written.

use crate::config::{validate_clickhouse, ClickhouseConfig};
use crate::error::EntryError;
use crate::limits::{
    MAX_RETRO_BYTES, MAX_RETRO_MATCHES, MAX_RETRO_ROWS_TO_GROUP, MAX_RETRO_ROWS_TO_READ, MAX_RETRO_SCALAR_BYTES, MAX_RETRO_SECONDS, RETRO_HOST_CHARS,
};
use crate::lines::numbered_lines;
use crate::load::{agent_for, LoadError};
use crate::store::{qualified, quote_identifier, StoreError};
use crate::types::{ElapsedFn, RefusalFn, RetroSendFn};
use core_pg::password::read_password;
use serde::{Deserialize, Serialize};
use siem_ingest::clickhouse::{classify_reply, classify_transport, exception_code, KEY_HEADER, USER_HEADER};
use siem_ingest::error::InsertClass;
use siem_ingest::reader_profile::{changed_statement, pin_clause, profile_refused, read_changed_bytes, url_settings, violations};
use std::io::{self, BufRead, BufReader, Read};
use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;
use time::macros::format_description;
use time::{Date, OffsetDateTime};
use tracing::{info, warn};
use ureq::http::StatusCode;
use ureq::Agent;


pub const PARAM_PREFIX: &str = "param_";


/// 159 `TIMEOUT_EXCEEDED` and 160 `TOO_SLOW` (the estimate already exceeds `max_execution_time`; live on a slow view).
pub const TIMEOUT_CODES: [u32; 2] = [159, 160];


pub const ROWS_OR_GROUPS_CODES: [u32; 2] = [158, 396];


pub const BAD_ARGUMENTS_CODE: u32 = 36;


pub const SCALAR_RESULT_ROWS: u64 = 1;


pub const WINDOW_FILTER: &str =
    "`tenant` = {tenant:String} AND `@timestamp` >= toDateTime({start:UInt32}, 'UTC') AND `@timestamp` < toDateTime({end:UInt32}, 'UTC')";


/// The reader identity (`SELECT` on the events and IOC tables, `dictGet` on the dictionary; never the loader), the events table and the budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetroSettings {
    pub reader: ClickhouseConfig,
    pub events_database: String,
    pub events_table: String,
    pub max_matches: usize,
    pub max_execution_seconds: u32,
    pub max_rows_to_read: u64,
    pub max_rows_to_group_by: u64,
}


#[derive(Debug, Error)]
pub enum RetroError {
    #[error(transparent)]
    Setup(#[from] LoadError),
    #[error(transparent)]
    Statement(#[from] StoreError),
    #[error("retro setting out of range: {0}")]
    Settings(&'static str),
    #[error("the window is empty or outside the supported range")]
    Window,
    #[error("the read was refused: {0:?}")]
    Refused(InsertClass),
    #[error("timeout")]
    Timeout,
    #[error("too_many_rows_or_groups")]
    TooManyRowsOrGroups,
    #[error("dictionary_outdated_or_bad_query")]
    DictionaryOutdatedOrBadQuery,
    #[error("foreign_dictionary")]
    ForeignDictionary,
    #[error("the reply body could not be read: {0:?}")]
    Body(io::ErrorKind),
    #[error("reply larger than {0} bytes")]
    TooManyBytes(u64),
    #[error("more than {0} rows")]
    TooManyRows(usize),
    #[error("a count reply is not a number")]
    Malformed,
    #[error("malformed_reply")]
    MalformedReply,
    #[error("reader_profile_changed: {0} setting(s) outside the allowed list")]
    ReaderProfileChanged(usize),
}


/// One request: the statement goes in the body, server settings and `param_` values in the URL, under what is left of the deadline.
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


/// The four statements of a run, all with `tenant`, `start`, `end` (and `limit`) as `param_` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statements {
    pub changed: String,
    pub foreign: String,
    pub not_an_ip: String,
    pub matches: String,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Source,
    Destination,
}


/// One `JSONEachRow` line of the match statement.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetroRow {
    pub indicator: String,
    pub matched_ip: String,
    pub direction: Direction,
    pub host: String,
    pub host_was_cut: u8,
    pub event_day: String,
    pub foreign: u8,
    pub matches: u32,
    pub first_time: u32,
    pub last_time: u32,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatchGroup {
    pub tenant: String,
    pub indicator: String,
    pub matched_ip: String,
    pub direction: Direction,
    pub host: String,
    pub host_cut: bool,
    pub event_day: Date,
    pub matches: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub first_time: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_time: OffsetDateTime,
}


/// The span between the previous successful window's end and this window's start, never searched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Gap {
    #[serde(with = "time::serde::rfc3339")]
    pub from: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub to: OffsetDateTime,
}


/// `groups` are returned, `truncated` means more matched than were kept, and `more_than` then holds the cap: the query stops at `max_matches + 1`, so no larger count is known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetroSummary {
    pub tenant: String,
    #[serde(with = "time::serde::rfc3339")]
    pub window_start: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub window_end: OffsetDateTime,
    pub groups: usize,
    pub more_than: Option<usize>,
    pub truncated: bool,
    pub not_an_ip: u64,
    pub gap: Option<Gap>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetroRun {
    pub groups: Vec<MatchGroup>,
    pub summary: RetroSummary,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Collected {
    pub groups: Vec<MatchGroup>,
    pub rows: usize,
    pub foreign: bool,
}


pub fn validate_retro(settings: &RetroSettings) -> Result<(), RetroError> {
    validate_clickhouse(&settings.reader).map_err(LoadError::Settings)?;
    quote_identifier(&settings.events_database)?;
    quote_identifier(&settings.events_table)?;
    if settings.max_matches == 0 || settings.max_matches > MAX_RETRO_MATCHES {
        Err(RetroError::Settings("max_matches"))
    } else if settings.max_execution_seconds == 0 || settings.max_execution_seconds > MAX_RETRO_SECONDS {
        Err(RetroError::Settings("max_execution_seconds"))
    } else if settings.max_rows_to_read == 0 || settings.max_rows_to_read > MAX_RETRO_ROWS_TO_READ {
        Err(RetroError::Settings("max_rows_to_read"))
    } else if settings.max_rows_to_group_by == 0 || settings.max_rows_to_group_by > MAX_RETRO_ROWS_TO_GROUP {
        Err(RetroError::Settings("max_rows_to_group_by"))
    } else {
        Ok(())
    }
}


/// Both ends as epoch seconds in `u32`; an empty or reversed window is refused.
pub fn window_epochs(start: OffsetDateTime, end: OffsetDateTime) -> Result<(u32, u32), RetroError> {
    let first = u32::try_from(start.unix_timestamp()).map_err(|_| RetroError::Window)?;
    let last = u32::try_from(end.unix_timestamp()).map_err(|_| RetroError::Window)?;
    if first < last {
        Ok((first, last))
    } else {
        Err(RetroError::Window)
    }
}


/// The one definition of "is an IP": `toIPv6OrNull` gives NULL for any other text (empty included), never `::` as an `OrDefault` would.
pub fn ip_or_null(column: &str) -> String {
    format!("toIPv6OrNull(`{column}`)")
}


/// One direction of the events, keyed as IPv6 (IPv4 becomes `::ffff:a.b.c.d`); a non-IP value is filtered out before the key is used.
pub fn direction_select(events: &str, direction: &str, column: &str) -> String {
    format!(
        "SELECT '{direction}' AS `direction`, assumeNotNull({0}) AS `key`, `host.name` AS `event_host`, `@timestamp` AS `ts` \
         FROM {events} WHERE {WINDOW_FILTER} AND isNotNull({0})",
        ip_or_null(column)
    )
}


pub fn not_an_ip_count(column: &str) -> String {
    format!("countIf(`{column}` != '' AND isNull({}))", ip_or_null(column))
}


pub fn statements(settings: &RetroSettings) -> Result<Statements, StoreError> {
    let reader = &settings.reader;
    let events = qualified(&settings.events_database, &settings.events_table)?;
    let source = qualified(&reader.database, &reader.table)?;
    quote_identifier(&reader.dictionary)?;
    let dictionary = format!("{}.{}", reader.database, reader.dictionary);
    let scalar_pins = settings_clause(settings, SCALAR_RESULT_ROWS);
    let match_pins = settings_clause(settings, settings.max_matches as u64 + 1);
    Ok(Statements {
        changed: changed_statement(),
        foreign: format!(
            "SELECT count() FROM (SELECT 1 FROM {source} WHERE `tenant` != {{tenant:String}} AND `checked` = 1 LIMIT 1){scalar_pins} FORMAT TabSeparated"
        ),
        not_an_ip: format!(
            "SELECT {} + {} FROM {events} WHERE {WINDOW_FILTER}{scalar_pins} FORMAT TabSeparated",
            not_an_ip_count("source.ip"),
            not_an_ip_count("destination.ip")
        ),
        matches: format!(
            "SELECT dictGet('{dictionary}', 'indicator', `key`) AS `indicator`, IPv6NumToString(`key`) AS `matched_ip`, `direction`, \
             substringUTF8(`event_host`, 1, {RETRO_HOST_CHARS}) AS `host`, toUInt8(lengthUTF8(`event_host`) > {RETRO_HOST_CHARS}) AS `host_was_cut`, \
             toString(toDate(`ts`, 'UTC')) AS `event_day`, toUInt8(dictGet('{dictionary}', 'tenant', `key`) != {{tenant:String}}) AS `foreign`, \
             toUInt32(count()) AS `matches`, toUInt32(toUnixTimestamp(min(`ts`))) AS `first_time`, toUInt32(toUnixTimestamp(max(`ts`))) AS `last_time` \
             FROM ({} UNION ALL {}) WHERE dictHas('{dictionary}', `key`) \
             GROUP BY `indicator`, `matched_ip`, `direction`, `host`, `host_was_cut`, `event_day`, `foreign` \
             ORDER BY `foreign` DESC, `first_time`, `indicator`, `matched_ip`, `direction`, `host` LIMIT {{limit:UInt64}}{match_pins} FORMAT JSONEachRow",
            direction_select(&events, "source", "source.ip"),
            direction_select(&events, "destination", "destination.ip")
        ),
    })
}


/// The reader's own limits (never `max_result_rows`, which each statement sets itself).
pub fn retro_limits(settings: &RetroSettings) -> Vec<(&'static str, String)> {
    vec![
        ("max_execution_time", settings.max_execution_seconds.to_string()),
        ("max_rows_to_read", settings.max_rows_to_read.to_string()),
        ("max_rows_to_group_by", settings.max_rows_to_group_by.to_string()),
    ]
}


/// The pins of one statement as a `SETTINGS` clause (siem-ingest `reader_profile`, shared with the other ClickHouse readers).
pub fn settings_clause(settings: &RetroSettings, result_rows: u64) -> String {
    pin_clause(&retro_limits(settings), result_rows)
}


/// The URL keeps only the settings a statement cannot carry: `readonly` (changing it in a query is refused) and the exception format.
pub fn server_settings() -> Vec<(&'static str, String)> {
    url_settings(None)
}


/// Only the status and the numeric exception code are read, never the server's text.
pub fn refusal(status: StatusCode, code: Option<u32>) -> Option<RetroError> {
    classify_reply(status, code).map(|class| match code {
        Some(found) if TIMEOUT_CODES.contains(&found) => RetroError::Timeout,
        Some(found) if ROWS_OR_GROUPS_CODES.contains(&found) => RetroError::TooManyRowsOrGroups,
        Some(BAD_ARGUMENTS_CODE) => RetroError::DictionaryOutdatedOrBadQuery,
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


/// One request under what is left of the deadline; a spent deadline sends nothing. `refuse` maps an error reply.
pub fn fetch_with(
    send: &RetroSendFn,
    settings: &RetroSettings,
    elapsed: &ElapsedFn,
    statement: &str,
    params: Vec<(&'static str, String)>,
    refuse: RefusalFn,
) -> Result<RetroReply, RetroError> {
    let remaining = Duration::from_millis(settings.reader.timeout_ms).saturating_sub(elapsed());
    if remaining.is_zero() {
        Err(RetroError::Timeout)
    } else {
        let reply = send(&RetroRequest {
            statement: statement.to_owned(),
            settings: server_settings(),
            params,
            remaining,
        })
        .map_err(RetroError::Refused)?;
        refuse(reply.status, reply.code).map_or(Ok(reply), Err)
    }
}


pub fn fetch(
    send: &RetroSendFn,
    settings: &RetroSettings,
    elapsed: &ElapsedFn,
    statement: &str,
    params: Vec<(&'static str, String)>,
) -> Result<RetroReply, RetroError> {
    fetch_with(send, settings, elapsed, statement, params, refusal)
}


/// A read error maps to a fixed variant: the `io::Error` of a body reader may carry transport text.
pub fn body_failure(error: &io::Error) -> RetroError {
    if error.kind() == io::ErrorKind::TimedOut {
        RetroError::Timeout
    } else {
        RetroError::Body(error.kind())
    }
}


/// The reader's changed settings, one name per line: a name outside the pins, a pinned name missing (a filtered or empty `system.settings`) or a reply over the cap refuses, counted and never named.
pub fn read_changed(reply: RetroReply, settings: &RetroSettings) -> Result<(), RetroError> {
    let bytes = read_changed_bytes(reply.body).map_err(|error| body_failure(&error))?;
    let found = violations(&bytes, &retro_limits(settings), None);
    if found > 0 {
        Err(RetroError::ReaderProfileChanged(found))
    } else {
        Ok(())
    }
}


pub fn parse_scalar(bytes: &[u8]) -> Result<u64, RetroError> {
    let text = std::str::from_utf8(bytes).map_err(|_| RetroError::Malformed)?;
    let digits = text.trim_end_matches('\n');
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        Err(RetroError::Malformed)
    } else {
        digits.parse::<u64>().map_err(|_| RetroError::Malformed)
    }
}


/// At most `MAX_RETRO_SCALAR_BYTES + 1` bytes are ever buffered.
pub fn read_scalar(reply: RetroReply) -> Result<u64, RetroError> {
    let mut bytes = Vec::new();
    reply
        .body
        .take(MAX_RETRO_SCALAR_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| body_failure(&error))?;
    if bytes.len() as u64 > MAX_RETRO_SCALAR_BYTES {
        Err(RetroError::Malformed)
    } else {
        parse_scalar(&bytes)
    }
}


/// The unix seconds of a `u32` always fit; the saturating add never reaches its bound.
pub fn time_of(seconds: u32) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH.saturating_add(time::Duration::seconds(i64::from(seconds)))
}


pub fn group_of(row: RetroRow, tenant: &str) -> Result<MatchGroup, RetroError> {
    let event_day = Date::parse(&row.event_day, format_description!("[year]-[month]-[day]")).map_err(|_| RetroError::MalformedReply)?;
    row.matched_ip.parse::<IpAddr>().map_err(|_| RetroError::MalformedReply)?;
    Ok(MatchGroup {
        tenant: tenant.to_owned(),
        indicator: row.indicator,
        matched_ip: row.matched_ip,
        direction: row.direction,
        host: row.host,
        host_cut: row.host_was_cut != 0,
        event_day,
        matches: row.matches,
        first_time: time_of(row.first_time),
        last_time: time_of(row.last_time),
    })
}


/// A line that does not parse is an error: the lines come from a fixed query with JSON-escaped fields, so a bad one is a server abnormality.
pub fn absorb(mut collected: Collected, text: Result<String, EntryError>, tenant: &str) -> Result<Collected, RetroError> {
    let line = text.map_err(|_| RetroError::MalformedReply)?;
    let found = serde_json::from_str::<RetroRow>(&line).map_err(|_| RetroError::MalformedReply)?;
    collected.rows += 1;
    collected.foreign = collected.foreign || found.foreign != 0;
    collected.groups.push(group_of(found, tenant)?);
    Ok(collected)
}


/// Stops at the first line over `max_rows`; the query's own `LIMIT` makes that an error.
pub fn collect(reader: &mut dyn BufRead, tenant: &str, max_rows: usize) -> Result<Collected, RetroError> {
    numbered_lines(reader).try_fold(Collected::default(), |collected, line| {
        let numbered = line.map_err(|error| body_failure(&error))?;
        let next = absorb(collected, numbered.text, tenant)?;
        if next.rows > max_rows {
            Err(RetroError::TooManyRows(max_rows))
        } else {
            Ok(next)
        }
    })
}


/// The body is read through `take(MAX_RETRO_BYTES + 1)`: more bytes, or a cut reply, is an error and nothing is returned.
pub fn read_groups(reply: RetroReply, tenant: &str, max_rows: usize) -> Result<Collected, RetroError> {
    let mut reader = BufReader::new(reply.body.take(MAX_RETRO_BYTES + 1));
    let collected = collect(&mut reader, tenant, max_rows);
    let over_cap = reader.get_ref().limit() == 0;
    let found = if over_cap {
        Err(RetroError::TooManyBytes(MAX_RETRO_BYTES))
    } else {
        collected
    };
    found.and_then(|rows| if rows.foreign { Err(RetroError::ForeignDictionary) } else { Ok(rows) })
}


pub fn gap_of(previous_end: Option<OffsetDateTime>, start: OffsetDateTime) -> Option<Gap> {
    previous_end
        .filter(|previous| *previous < start)
        .map(|previous| Gap { from: previous, to: start })
}


/// Settings check, foreign check on the source table, then the non-IP count, then the match query, all under the one deadline `reader.timeout_ms`.
pub fn retro_run(
    settings: &RetroSettings,
    start: OffsetDateTime,
    end: OffsetDateTime,
    previous_end: Option<OffsetDateTime>,
    elapsed: &ElapsedFn,
    send: &RetroSendFn,
) -> Result<RetroRun, RetroError> {
    validate_retro(settings)?;
    let (first, last) = window_epochs(start, end)?;
    let text = statements(settings)?;
    let tenant = settings.reader.tenant.as_str();
    let tenant_param = || ("tenant", tenant.to_owned());
    let window_params = || vec![tenant_param(), ("start", first.to_string()), ("end", last.to_string())];
    fetch_with(send, settings, elapsed, &text.changed, Vec::new(), check_refusal).and_then(|reply| read_changed(reply, settings))?;
    let foreign_rows = fetch(send, settings, elapsed, &text.foreign, vec![tenant_param()]).and_then(read_scalar)?;
    if foreign_rows > 0 {
        Err(RetroError::ForeignDictionary)
    } else {
        let not_an_ip = fetch(send, settings, elapsed, &text.not_an_ip, window_params()).and_then(read_scalar)?;
        let limit = settings.max_matches + 1;
        let mut match_params = window_params();
        match_params.push(("limit", limit.to_string()));
        let collected = fetch(send, settings, elapsed, &text.matches, match_params).and_then(|reply| read_groups(reply, tenant, limit))?;
        let truncated = collected.groups.len() > settings.max_matches;
        let mut groups = collected.groups;
        groups.truncate(settings.max_matches);
        let summary = RetroSummary {
            tenant: tenant.to_owned(),
            window_start: start,
            window_end: end,
            groups: groups.len(),
            more_than: truncated.then_some(settings.max_matches),
            truncated,
            not_an_ip,
            gap: gap_of(previous_end, start),
        };
        let returned = summary.groups;
        info!(returned, truncated, not_an_ip, "retro match done");
        Ok(RetroRun { groups, summary })
    }
}


/// The real sender: one POST, the statement as body, no redirect, the server's text never read.
pub fn send_request(agent: &Agent, config: &ClickhouseConfig, password: &str, request: &RetroRequest) -> Result<RetroReply, InsertClass> {
    let base = agent.post(&config.url).header(USER_HEADER, &config.user).header(KEY_HEADER, password);
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


/// Settings validated first, then the password and CA are read, then the run goes through `send_request`.
pub fn run_retro(
    settings: &RetroSettings,
    start: OffsetDateTime,
    end: OffsetDateTime,
    previous_end: Option<OffsetDateTime>,
    elapsed: &ElapsedFn,
) -> Result<RetroRun, RetroError> {
    validate_retro(settings)?;
    let password = read_password(&settings.reader.password_file).map_err(LoadError::Password)?;
    let key = std::str::from_utf8(&password).map_err(LoadError::PasswordEncoding)?;
    let agent = agent_for(&settings.reader)?;
    let result = retro_run(settings, start, end, previous_end, elapsed, &|request| {
        send_request(&agent, &settings.reader, key, request)
    });
    if result.is_err() {
        warn!("retro match failed");
    }
    result
}
