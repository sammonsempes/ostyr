//! Retro read: the event ids one compiled Sigma rule matches in a past window of one tenant's events in ClickHouse.

use crate::error::RetroError;
use crate::id::MAX_EVENT_ID_CHARS;
use crate::pg::event_time_text;
use crate::types::{ElapsedFn, RetroSendFn};
use alerts::store::MAX_ENTITY_CHARS;
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
use unicode_general_category::{get_general_category, GeneralCategory};
use ureq::http::StatusCode;
use ureq::Agent;
use zeroize::Zeroizing;


pub const MAX_RETRO_DAYS: i64 = 7;


pub const SECONDS_PER_DAY: i64 = 86_400;


pub const MAX_RETRO_ROWS: usize = 10_000;


pub const MAX_RETRO_BYTES: u64 = 67_108_864;


/// Worst case bytes of one reply row: 64 id characters and 2 x 257 entity characters at 6 bytes each, the hash, the numbers and the keys.
pub const MAX_ROW_BYTES: u64 = 4_096;


/// Characters of `event.id` the server returns; the identity keeps `MAX_EVENT_ID_CHARS` of them.
pub const ID_KEEP_CHARS: usize = 64;


/// Characters of `host.name` and `user.name` the server returns: one more than the alert store keeps.
pub const ENTITY_KEEP_CHARS: usize = MAX_ENTITY_CHARS + 1;


pub const HASH_HEX_CHARS: usize = 64;


pub const MILLIS_COLUMN: &str = "@timestamp";


pub const MILLIS_EXPRESSION: &str = "toUnixTimestamp64Milli(`@timestamp`)";


pub const MAX_TIMEOUT_MS: u64 = 300_000;


pub const MAX_CA_BYTES: u64 = 65_536;


pub const MAX_USER_BYTES: usize = 128;


pub const MAX_EXECUTION_SECONDS: u32 = 300;


pub const MAX_ROWS_TO_READ: u64 = 10_000_000_000;


pub const PARAM_PREFIX: &str = "param_";


pub const EVENTS_TABLE: &str = "events";


pub const ID_COLUMN: &str = "event.id";


pub const HASH_ALIAS: &str = "ret_hash";


/// How a column enters the content hash: a string is length-prefixed, a number is decimal then `;`, an array is count-prefixed with each element length-prefixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Text,
    Number,
    TextArray,
}


/// The ordered content columns of an event row. Changing this list changes every retro identity: append only after a coordinator call.
pub const HASH_COLUMNS: [(&str, HashKind); 40] = [
    ("ecs.version", HashKind::Text),
    ("event.id", HashKind::Text),
    ("event.kind", HashKind::Text),
    ("event.category", HashKind::TextArray),
    ("event.type", HashKind::TextArray),
    ("event.action", HashKind::Text),
    ("event.outcome", HashKind::Text),
    ("event.dataset", HashKind::Text),
    ("event.module", HashKind::Text),
    ("event.severity", HashKind::Number),
    ("event.sequence", HashKind::Number),
    ("message", HashKind::Text),
    ("host.name", HashKind::Text),
    ("host.id", HashKind::Text),
    ("host.ip", HashKind::TextArray),
    ("host.os.type", HashKind::Text),
    ("user.name", HashKind::Text),
    ("user.id", HashKind::Text),
    ("user.domain", HashKind::Text),
    ("source.ip", HashKind::Text),
    ("source.port", HashKind::Number),
    ("source.domain", HashKind::Text),
    ("destination.ip", HashKind::Text),
    ("destination.port", HashKind::Number),
    ("destination.domain", HashKind::Text),
    ("network.transport", HashKind::Text),
    ("network.direction", HashKind::Text),
    ("process.pid", HashKind::Number),
    ("process.name", HashKind::Text),
    ("process.executable", HashKind::Text),
    ("process.command_line", HashKind::Text),
    ("process.args", HashKind::TextArray),
    ("process.working_directory", HashKind::Text),
    ("process.parent.pid", HashKind::Number),
    ("process.parent.executable", HashKind::Text),
    ("process.parent.command_line", HashKind::Text),
    ("file.path", HashKind::Text),
    ("file.size", HashKind::Number),
    ("event.code", HashKind::Text),
    ("event.provider", HashKind::Text),
];


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


/// One reply line; 64-bit integers are sent as text by ClickHouse JSON output, so the time is `toString` of the milliseconds.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRow {
    pub ret_ms: String,
    pub ret_hash: String,
    pub ret_id: String,
    pub ret_id_chars: u32,
    pub ret_id_valid: u8,
    pub ret_host: String,
    pub ret_host_chars: u32,
    pub ret_user: String,
    pub ret_user_chars: u32,
}


/// One matching event: its identity (`<event.id cut to 63>:<content hash>`, or the hash alone), its time and the entities the alert shows, each already cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetroEvent {
    pub identity: String,
    pub event_ms: i64,
    pub event_time: String,
    pub id_chars: u32,
    pub host_name: Option<String>,
    pub host_chars: u32,
    pub user_name: Option<String>,
    pub user_chars: u32,
}


/// The events that passed the grammar, how many were refused alone, and how many rows were read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetroIds {
    pub events: Vec<RetroEvent>,
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


/// The compiled rule over `retro_projection`, then tenant and window as `param_` values, a stable order, `max_rows + 1` rows at most and every pin in its own `SETTINGS` clause.
fn quoted(column: &str) -> String {
    format!("`{column}`")
}


/// One column of the hash input: self-delimiting, so no two different rows give the same bytes.
pub fn hash_part(column: &str, kind: HashKind) -> String {
    let name = quoted(column);
    match kind {
        HashKind::Text => format!("concat(toString(length({name})), ':', {name})"),
        HashKind::Number => format!("concat(toString({name}), ';')"),
        HashKind::TextArray => format!(
            "concat(toString(length({name})), '[', arrayStringConcat(arrayMap(element -> concat(toString(length(element)), ':', element), {name}), ''), ']')"
        ),
    }
}


/// `lower(hex(SHA256(..)))` over the time in milliseconds then `HASH_COLUMNS` in order.
pub fn hash_expression() -> String {
    let time = format!("concat(toString({MILLIS_EXPRESSION}), ';')");
    let parts: Vec<String> = std::iter::once(time)
        .chain(HASH_COLUMNS.iter().map(|(column, kind)| hash_part(column, *kind)))
        .collect();
    format!("lower(hex(SHA256(concat({}))))", parts.join(", "))
}


fn valid_cut(column: &str, keep: usize) -> String {
    let name = quoted(column);
    format!("if(isValidUTF8({name}), leftUTF8({name}, {keep}), '')")
}


/// The columns of a retro row, cut on the server: an invalid UTF-8 text is blanked (its validity is reported for the id) so the reply stays valid UTF-8.
pub fn retro_projection() -> String {
    let id = quoted(ID_COLUMN);
    let host = quoted("host.name");
    let user = quoted("user.name");
    [
        format!("toString({MILLIS_EXPRESSION}) AS `ret_ms`"),
        format!("{} AS `{HASH_ALIAS}`", hash_expression()),
        format!("{} AS `ret_id`", valid_cut(ID_COLUMN, ID_KEEP_CHARS)),
        format!("lengthUTF8({id}) AS `ret_id_chars`"),
        format!("isValidUTF8({id}) AS `ret_id_valid`"),
        format!("{} AS `ret_host`", valid_cut("host.name", ENTITY_KEEP_CHARS)),
        format!("lengthUTF8({host}) AS `ret_host_chars`"),
        format!("{} AS `ret_user`", valid_cut("user.name", ENTITY_KEEP_CHARS)),
        format!("lengthUTF8({user}) AS `ret_user_chars`"),
    ]
    .join(", ")
}


pub fn retro_statement(rule_text: &str, mapping: &FieldMapping, settings: &RetroSettings) -> Result<String, RetroError> {
    let options = SqlOptions {
        table: EVENTS_TABLE.to_owned(),
        id_column: ID_COLUMN.to_owned(),
        projection: Some(retro_projection()),
    };
    let compiled = compile_rule(rule_text, mapping, &options).map_err(RetroError::Rule)?;
    let pins = pin_clause(&retro_limits(settings), settings.max_rows as u64 + 1);
    Ok(format!(
        "{compiled} AND {WINDOW_FILTER} ORDER BY `{MILLIS_COLUMN}`, `{HASH_ALIAS}` LIMIT {{limit:UInt64}}{pins} FORMAT JSONEachRow"
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


/// A read error maps to a fixed variant (a body that is not UTF-8 is a malformed reply): the `io::Error` of a body reader may carry transport text.
pub fn body_failure(error: &io::Error) -> RetroError {
    match error.kind() {
        io::ErrorKind::TimedOut => RetroError::Timeout,
        io::ErrorKind::InvalidData => RetroError::MalformedReply,
        kind => RetroError::Body(kind),
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


/// A control (Cc) or format (Cf) character is refused: the identity goes into alerts, logs and the UI.
pub fn refused_character(character: char) -> bool {
    character.is_control() || get_general_category(character) == GeneralCategory::Format
}


/// The cut id of an event, empty included, has no refused character.
pub fn id_allowed(prefix: &str) -> bool {
    !prefix.chars().any(refused_character)
}


/// The identity of a row: the id cut to 63 characters then `:` and the hash, or the hash alone for an empty id.
pub fn retro_identity(prefix: &str, hash: &str) -> String {
    if prefix.is_empty() {
        hash.to_owned()
    } else {
        format!("{prefix}:{hash}")
    }
}


/// The entity cut to the store's limit; an empty text, a blanked invalid one or one with a refused character is no entity, never a refused row.
pub fn entity_of(text: &str) -> Option<String> {
    let cut: String = text.chars().take(MAX_ENTITY_CHARS).collect();
    Some(cut).filter(|found| !found.is_empty() && id_allowed(found))
}


fn is_hash(text: &str) -> bool {
    text.len() == HASH_HEX_CHARS && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}


/// An event from a row, `None` when its id is refused alone (invalid UTF-8, Cc or Cf); a field out of form is a malformed reply.
pub fn event_of(row: EventRow) -> Result<Option<RetroEvent>, RetroError> {
    let event_ms = row.ret_ms.parse::<i64>().map_err(|_| RetroError::MalformedReply)?;
    let prefix: String = row.ret_id.chars().take(MAX_EVENT_ID_CHARS).collect();
    if !is_hash(&row.ret_hash) || row.ret_id_valid > 1 {
        Err(RetroError::MalformedReply)
    } else if row.ret_id_valid == 0 || !id_allowed(&prefix) {
        Ok(None)
    } else {
        Ok(Some(RetroEvent {
            identity: retro_identity(&prefix, &row.ret_hash),
            event_ms,
            event_time: event_time_text(event_ms)?,
            id_chars: row.ret_id_chars,
            host_name: entity_of(&row.ret_host),
            host_chars: row.ret_host_chars,
            user_name: entity_of(&row.ret_user),
            user_chars: row.ret_user_chars,
        }))
    }
}


/// A line that does not parse is an error (a fixed query with JSON-escaped fields: a bad line is a server abnormality); a bad id is refused alone.
pub fn absorb(mut found: RetroIds, line: io::Result<String>, cap: usize) -> Result<RetroIds, RetroError> {
    let text = line.map_err(|error| body_failure(&error))?;
    let row = serde_json::from_str::<EventRow>(&text).map_err(|_| RetroError::MalformedReply)?;
    found.rows += 1;
    if found.rows > cap + 1 {
        Err(RetroError::TooManyRows(cap))
    } else if found.rows > cap {
        Ok(found)
    } else {
        match event_of(row)? {
            Some(event) => found.events.push(event),
            None => found.refused += 1,
        }
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
