//! What the tenant's table already holds, read by the writer before a round so a round never takes the table past what the RPZ read can return.

use crate::config::{validate_clickhouse, ClickhouseConfig};
use crate::limits::{MAX_LOGGED_FEED_NAMES, MAX_READER_SKEW_SECONDS, MAX_READ_BYTES, MAX_READ_ROWS};
use crate::lines::numbered_lines;
use crate::load::{agent_for, ensure_schema, LoadError};
use crate::model::IocType;
use crate::read::{check_profile, remaining_of, row_params, send_statement, ReadError, EXCEPTION_PREFIX};
use crate::store::{bytes_statement, count_statement, keys_statement, top_statement};
use crate::types::{ElapsedFn, IocKey};
use core_pg::password::read_password;
use serde::Deserialize;
use siem_ingest::clickhouse::{classify_reply, exception_code};
use std::collections::BTreeSet;
use std::io::{BufReader, Read};
use std::time::Instant;
use time::{Duration, OffsetDateTime};


pub const CODE_RESULT_ROWS: u32 = 396;


/// The tenant's live rows: the read-type keys (empty when `exceeded`), the count of every type, and the feeds holding the most.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Stored {
    pub keys: BTreeSet<IocKey>,
    pub live: usize,
    pub bytes: u64,
    pub exceeded: bool,
    pub top: Vec<(String, u64)>,
}


#[derive(Deserialize)]
pub struct KeyRow {
    pub ioc_type: IocType,
    pub value: String,
}


#[derive(Deserialize)]
pub struct CountRow {
    pub live: usize,
}


#[derive(Deserialize)]
pub struct BytesRow {
    pub bytes: u64,
}


#[derive(Deserialize)]
pub struct TopRow {
    pub feed: String,
    pub live: u64,
}


/// Reads at most `max_rows` lines of one reply under what is left of the deadline; more rows, or the exception code 396, is `TooManyRows`.
pub fn fetch_lines(
    agent: &ureq::Agent,
    config: &ClickhouseConfig,
    password: &str,
    statement: &str,
    now: OffsetDateTime,
    max_rows: usize,
    elapsed: &ElapsedFn,
) -> Result<Vec<String>, ReadError> {
    let params = row_params(config, now, max_rows);
    let response = send_statement(agent, config, password, statement, &params, remaining_of(config, elapsed)?)?;
    let code = exception_code(response.headers());
    if code == Some(CODE_RESULT_ROWS) {
        Err(ReadError::TooManyRows(max_rows))
    } else if let Some(class) = classify_reply(response.status(), code) {
        Err(ReadError::Refused(class))
    } else {
        let mut reader = BufReader::new(response.into_body().into_reader().take(MAX_READ_BYTES + 1));
        let lines = reply_lines(&mut reader, max_rows);
        if reader.get_ref().limit() == 0 {
            Err(ReadError::TooManyBytes(MAX_READ_BYTES))
        } else {
            lines
        }
    }
}


/// Every line of the reply; a line that is too long, not UTF-8 or an exception is an error, never a skipped row.
pub fn reply_lines(reader: &mut dyn std::io::BufRead, max_rows: usize) -> Result<Vec<String>, ReadError> {
    numbered_lines(reader).try_fold(Vec::new(), |mut lines, line| {
        let text = line.map_err(ReadError::Body)?.text.map_err(|_unusable| ReadError::MalformedReply)?;
        if text.starts_with(EXCEPTION_PREFIX) {
            Err(ReadError::ExceptionInBody)
        } else if lines.len() >= max_rows {
            Err(ReadError::TooManyRows(max_rows))
        } else {
            lines.push(text);
            Ok(lines)
        }
    })
}


pub fn key_row(line: &str) -> Result<IocKey, ReadError> {
    serde_json::from_str::<KeyRow>(line)
        .map(|row| (row.ioc_type, row.value))
        .map_err(|_malformed| ReadError::MalformedReply)
}


pub fn count_row(lines: &[String]) -> Result<usize, ReadError> {
    lines
        .first()
        .ok_or(ReadError::MalformedReply)
        .and_then(|line| serde_json::from_str::<CountRow>(line).map_err(|_malformed| ReadError::MalformedReply))
        .map(|row| row.live)
}


pub fn bytes_row(lines: &[String]) -> Result<u64, ReadError> {
    lines
        .first()
        .ok_or(ReadError::MalformedReply)
        .and_then(|line| serde_json::from_str::<BytesRow>(line).map_err(|_malformed| ReadError::MalformedReply))
        .map(|row| row.bytes)
}


pub fn top_row(line: &str) -> Result<(String, u64), ReadError> {
    serde_json::from_str::<TopRow>(line)
        .map(|row| (row.feed, row.live))
        .map_err(|_malformed| ReadError::MalformedReply)
}


/// The key query: `exceeded` when the table already holds more read-type rows than the read can return.
pub fn read_keys(
    agent: &ureq::Agent,
    config: &ClickhouseConfig,
    password: &str,
    now: OffsetDateTime,
    elapsed: &ElapsedFn,
) -> Result<(BTreeSet<IocKey>, bool), ReadError> {
    let statement = keys_statement(&config.database, &config.table)?;
    match fetch_lines(agent, config, password, &statement, now, MAX_READ_ROWS, elapsed) {
        Err(ReadError::TooManyRows(_) | ReadError::TooManyBytes(_)) => Ok((BTreeSet::new(), true)),
        other => other
            .and_then(|lines| lines.iter().map(|line| key_row(line)).collect::<Result<BTreeSet<_>, _>>())
            .map(|keys| (keys, false)),
    }
}


/// The count of the tenant's live rows of every type.
pub fn read_live(
    agent: &ureq::Agent,
    config: &ClickhouseConfig,
    password: &str,
    now: OffsetDateTime,
    elapsed: &ElapsedFn,
) -> Result<usize, ReadError> {
    let statement = count_statement(&config.database, &config.table)?;
    fetch_lines(agent, config, password, &statement, now, 1, elapsed).and_then(|lines| count_row(&lines))
}


/// The bytes the RPZ read would return for the live read-type rows (`store::row_bytes` counted by the server).
pub fn read_bytes(
    agent: &ureq::Agent,
    config: &ClickhouseConfig,
    password: &str,
    now: OffsetDateTime,
    elapsed: &ElapsedFn,
) -> Result<u64, ReadError> {
    let statement = bytes_statement(&config.database, &config.table)?;
    fetch_lines(agent, config, password, &statement, now, 1, elapsed).and_then(|lines| bytes_row(&lines))
}


/// The feeds holding the most live rows, at most `MAX_LOGGED_FEED_NAMES`.
pub fn read_top(
    agent: &ureq::Agent,
    config: &ClickhouseConfig,
    password: &str,
    now: OffsetDateTime,
    elapsed: &ElapsedFn,
) -> Result<Vec<(String, u64)>, ReadError> {
    let statement = top_statement(&config.database, &config.table)?;
    fetch_lines(agent, config, password, &statement, now, MAX_LOGGED_FEED_NAMES, elapsed)
        .and_then(|lines| lines.iter().map(|line| top_row(line)).collect())
}


/// The settings check, the key query, the count of every type and the biggest feeds, under one deadline, after the schema exists.
pub fn read_stored_timed(config: &ClickhouseConfig, now: OffsetDateTime, elapsed: &ElapsedFn) -> Result<Stored, ReadError> {
    validate_clickhouse(config).map_err(LoadError::Settings)?;
    let password = read_password(&config.password_file).map_err(LoadError::Password)?;
    let key = std::str::from_utf8(&password).map_err(LoadError::PasswordEncoding)?;
    let agent = agent_for(config)?;
    ensure_schema(&agent, config, key, elapsed)?;
    check_profile(&agent, config, key, remaining_of(config, elapsed)?)?;
    let skewed = now.saturating_sub(Duration::seconds(MAX_READER_SKEW_SECONDS));
    let (keys, exceeded) = read_keys(&agent, config, key, skewed, elapsed)?;
    let live = read_live(&agent, config, key, skewed, elapsed)?;
    let top = read_top(&agent, config, key, skewed, elapsed)?;
    let bytes = read_bytes(&agent, config, key, skewed, elapsed)?;
    Ok(Stored {
        keys,
        live,
        bytes,
        exceeded,
        top,
    })
}


pub fn read_stored(config: &ClickhouseConfig, now: OffsetDateTime) -> Result<Stored, ReadError> {
    let started = Instant::now();
    read_stored_timed(config, now, &|| started.elapsed())
}
