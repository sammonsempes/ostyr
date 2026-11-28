use crate::canon::canonicalise;
use crate::config::{validate_clickhouse, ClickhouseConfig};
use crate::error::{CanonError, EntryError};
use crate::limits::{MAX_READ_BYTES, MAX_READ_ROWS};
use crate::lines::numbered_lines;
use crate::load::{agent_for, LoadError};
use crate::model::{Ioc, IocType, Source, Tags, Tlp};
use crate::store::{epoch_u32, read_statement, StoreError};
use crate::types::ElapsedFn;
use core_pg::password::read_password;
use serde::{Deserialize, Deserializer};
use siem_ingest::clickhouse::{classify_reply, classify_transport, exception_code, KEY_HEADER, USER_HEADER};
use siem_ingest::error::InsertClass;
use siem_ingest::reader_profile::{changed_statement, profile_refused, read_changed_bytes, url_settings, violations};
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::time::{Duration, Instant};
use thiserror::Error;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};
use tracing::{info, warn};
use ureq::http::Response;
use ureq::{Agent, Body};


#[derive(Debug, Error)]
pub enum ReadError {
    #[error(transparent)]
    Setup(#[from] LoadError),
    #[error(transparent)]
    Statement(#[from] StoreError),
    #[error("the read was refused: {0:?}")]
    Refused(InsertClass),
    #[error("the reply body could not be read")]
    Body(#[source] io::Error),
    #[error("more than {0} rows: the list would be truncated")]
    TooManyRows(usize),
    #[error("reply larger than {0} bytes: the list would be truncated")]
    TooManyBytes(u64),
    #[error("the reply carries a ClickHouse exception line: the list would be truncated")]
    ExceptionInBody,
    #[error("a reply line is not a row of the expected shape: the list would be truncated")]
    MalformedReply,
    #[error("reader_profile_changed: {0} setting(s) outside the allowed list")]
    ReaderProfileChanged(usize),
    #[error("the IOC lines could not be written")]
    Output(#[source] io::Error),
}


/// A row that is counted and left out.
#[derive(Debug, Error)]
pub enum RowError {
    #[error("unusable line")]
    Line(#[from] EntryError),
    #[error("unusable row")]
    Json(#[from] serde_json::Error),
    #[error("row too broad")]
    TooBroad,
    #[error("row not canonical")]
    NotCanonical,
}


/// Why a row was left out; the text is a fixed key, never the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadReason {
    UnknownTlp,
    UnknownType,
    BadTime,
    BadJson,
    TooBroad,
    NotCanonical,
}


pub const FIELD_REASONS: [BadReason; 3] = [BadReason::UnknownTlp, BadReason::UnknownType, BadReason::BadTime];


impl fmt::Display for BadReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownTlp => "unknown_tlp",
            Self::UnknownType => "unknown_type",
            Self::BadTime => "bad_time",
            Self::BadJson => "bad_json",
            Self::TooBroad => "too_broad",
            Self::NotCanonical => "not_canonical",
        })
    }
}


/// Counted rows per reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BadRows {
    pub unknown_tlp: u64,
    pub unknown_type: u64,
    pub bad_time: u64,
    pub bad_json: u64,
    pub too_broad: u64,
    pub not_canonical: u64,
}


pub fn total_bad(bad: &BadRows) -> u64 {
    bad.unknown_tlp + bad.unknown_type + bad.bad_time + bad.bad_json + bad.too_broad + bad.not_canonical
}


pub fn count_bad(bad: BadRows, reason: BadReason) -> BadRows {
    match reason {
        BadReason::UnknownTlp => BadRows {
            unknown_tlp: bad.unknown_tlp + 1,
            ..bad
        },
        BadReason::UnknownType => BadRows {
            unknown_type: bad.unknown_type + 1,
            ..bad
        },
        BadReason::BadTime => BadRows {
            bad_time: bad.bad_time + 1,
            ..bad
        },
        BadReason::BadJson => BadRows {
            bad_json: bad.bad_json + 1,
            ..bad
        },
        BadReason::TooBroad => BadRows {
            too_broad: bad.too_broad + 1,
            ..bad
        },
        BadReason::NotCanonical => BadRows {
            not_canonical: bad.not_canonical + 1,
            ..bad
        },
    }
}


/// The reason of a failed row: a field's own fixed key, else bad JSON.
pub fn reason_of(error: &RowError) -> BadReason {
    match error {
        RowError::Line(_) => BadReason::BadJson,
        RowError::TooBroad => BadReason::TooBroad,
        RowError::NotCanonical => BadReason::NotCanonical,
        RowError::Json(source) => {
            let text = source.to_string();
            FIELD_REASONS
                .into_iter()
                .find(|reason| text.starts_with(&reason.to_string()))
                .unwrap_or(BadReason::BadJson)
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadSummary {
    pub rows: usize,
    pub bad: BadRows,
}


/// The caps of one read: rows and reply bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadCaps {
    pub rows: usize,
    pub bytes: u64,
}


pub const DEFAULT_CAPS: ReadCaps = ReadCaps {
    rows: MAX_READ_ROWS,
    bytes: MAX_READ_BYTES,
};


/// The IOC lines read so far, held until the whole reply is known to be complete.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Collected {
    pub lines: Vec<String>,
    pub bad: BadRows,
}


pub fn clickhouse_time<'de, Input: Deserializer<'de>>(deserializer: Input) -> Result<OffsetDateTime, Input::Error> {
    String::deserialize(deserializer).and_then(|text| {
        PrimitiveDateTime::parse(&text, format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"))
            .map(PrimitiveDateTime::assume_utc)
            .map_err(|_| serde::de::Error::custom(BadReason::BadTime))
    })
}


pub fn known_tlp<'de, Input: Deserializer<'de>>(deserializer: Input) -> Result<Tlp, Input::Error> {
    Tlp::deserialize(deserializer).map_err(|_| serde::de::Error::custom(BadReason::UnknownTlp))
}


pub fn known_type<'de, Input: Deserializer<'de>>(deserializer: Input) -> Result<IocType, Input::Error> {
    IocType::deserialize(deserializer).map_err(|_| serde::de::Error::custom(BadReason::UnknownType))
}


/// One `JSONEachRow` line of the read statement; DateTime columns arrive as `YYYY-MM-DD HH:MM:SS` in UTC.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StoredRow {
    #[serde(deserialize_with = "known_type")]
    pub ioc_type: IocType,
    pub value: String,
    pub feed: String,
    pub feed_version: String,
    pub confidence: u8,
    #[serde(deserialize_with = "known_tlp")]
    pub tlp: Tlp,
    #[serde(deserialize_with = "clickhouse_time")]
    pub first_seen: OffsetDateTime,
    #[serde(deserialize_with = "clickhouse_time")]
    pub last_seen: OffsetDateTime,
    #[serde(deserialize_with = "clickhouse_time")]
    pub expires_at: OffsetDateTime,
}


impl From<StoredRow> for Ioc {
    fn from(row: StoredRow) -> Self {
        Self {
            ioc_type: row.ioc_type,
            value: row.value,
            sources: vec![Source {
                feed: row.feed,
                version: row.feed_version,
            }],
            first_seen: row.first_seen,
            last_seen: row.last_seen,
            confidence: row.confidence,
            tlp: row.tlp,
            expires_at: Some(row.expires_at),
            tags: Tags::default(),
        }
    }
}


/// A stored row that is too broad, fails `canonicalise` or differs from its canonical form is refused again here.
pub fn refuse_broad(row: StoredRow) -> Result<StoredRow, RowError> {
    match canonicalise(row.ioc_type, &row.value) {
        Err(CanonError::TooBroad) => Err(RowError::TooBroad),
        Err(_) => Err(RowError::NotCanonical),
        Ok(canonical) if canonical.value != row.value || canonical.ioc_type != row.ioc_type => Err(RowError::NotCanonical),
        Ok(_) => Ok(row),
    }
}


/// The start of the line ClickHouse writes in `JSONEachRow` for an exception, whatever the setting.
pub const EXCEPTION_PREFIX: &str = "{\"exception\"";


/// A row that does not parse (unknown TLP or type included) is an error, never a default.
pub fn ioc_line(text: Result<String, EntryError>) -> Result<String, RowError> {
    text.map_err(RowError::from)
        .and_then(|line| serde_json::from_str::<StoredRow>(&line).map_err(RowError::from))
        .and_then(refuse_broad)
        .and_then(|row| serde_json::to_string(&Ioc::from(row)).map_err(RowError::from))
}


/// The time left of the one deadline `timeout_ms`; a spent budget sends nothing.
pub fn remaining_of(config: &ClickhouseConfig, elapsed: &ElapsedFn) -> Result<Duration, ReadError> {
    let left = Duration::from_millis(config.timeout_ms).saturating_sub(elapsed());
    if left.is_zero() {
        Err(ReadError::Refused(InsertClass::Timeout))
    } else {
        Ok(left)
    }
}


/// One POST: the two URL settings, the statement and the parameters as query values (never in the statement text); only a transport failure is an error here.
pub fn send_statement(
    agent: &Agent,
    config: &ClickhouseConfig,
    password: &str,
    statement: &str,
    params: &[(&str, String)],
    remaining: Duration,
) -> Result<Response<Body>, ReadError> {
    let with_url = url_settings(None)
        .iter()
        .fold(agent.post(&config.url), |builder, (name, value)| builder.query(*name, value));
    let with_params = params
        .iter()
        .fold(with_url.query("query", statement), |builder, (name, value)| builder.query(*name, value));
    with_params
        .header(USER_HEADER, &config.user)
        .header(KEY_HEADER, password)
        .config()
        .timeout_global(Some(remaining))
        .http_status_as_error(false)
        .build()
        .send(String::new())
        .map_err(|error| ReadError::Refused(classify_transport(&error)))
}


/// The settings check: any changed setting outside the pins, a pinned name missing or a refusal the profile caused is `ReaderProfileChanged`, before the read is sent.
pub fn check_profile(agent: &Agent, config: &ClickhouseConfig, password: &str, remaining: Duration) -> Result<(), ReadError> {
    let response = send_statement(agent, config, password, &changed_statement(), &[], remaining)?;
    let code = exception_code(response.headers());
    match classify_reply(response.status(), code) {
        Some(_) if profile_refused(code) => Err(ReadError::ReaderProfileChanged(1)),
        Some(class) => Err(ReadError::Refused(class)),
        None => {
            let bytes = read_changed_bytes(response.into_body().into_reader()).map_err(ReadError::Body)?;
            let found = violations(&bytes, &[], None);
            if found > 0 {
                Err(ReadError::ReaderProfileChanged(found))
            } else {
                Ok(())
            }
        }
    }
}


pub const PARAM_COUNT: usize = 3;


/// Tenant, time and limit (one more than `max_rows`) as query values.
pub fn row_params(config: &ClickhouseConfig, now: OffsetDateTime, max_rows: usize) -> [(&'static str, String); PARAM_COUNT] {
    [
        ("param_tenant", config.tenant.clone()),
        ("param_now", epoch_u32(now.unix_timestamp()).to_string()),
        ("param_limit", (max_rows + 1).to_string()),
    ]
}


/// The read under what is left of the deadline; tenant, time and limit travel as query parameters.
pub fn request_rows(
    agent: &Agent,
    config: &ClickhouseConfig,
    password: &str,
    statement: &str,
    now: OffsetDateTime,
    max_rows: usize,
    remaining: Duration,
) -> Result<Response<Body>, ReadError> {
    let params = row_params(config, now, max_rows);
    let response = send_statement(agent, config, password, statement, &params, remaining)?;
    classify_reply(response.status(), exception_code(response.headers())).map_or(Ok(response), |class| Err(ReadError::Refused(class)))
}


/// A line that is not JSON of the row shape, or a time the server wrote unparsable, is a server abnormality: an error, not a counted skip.
pub fn valid_shape(error: &RowError) -> Result<BadReason, ReadError> {
    match reason_of(error) {
        BadReason::BadJson | BadReason::BadTime => Err(ReadError::MalformedReply),
        reason => Ok(reason),
    }
}


/// Stops at the first row over `MAX_READ_ROWS`; a refused value is counted and the read goes on, a malformed line is an error.
pub fn collect_rows(reader: &mut dyn BufRead, max_rows: usize) -> Result<Collected, ReadError> {
    numbered_lines(reader).try_fold(Collected::default(), |mut collected, line| {
        let numbered = line.map_err(ReadError::Body)?;
        let exception = numbered.text.as_ref().is_ok_and(|text| text.starts_with(EXCEPTION_PREFIX));
        (!exception).then_some(()).ok_or(ReadError::ExceptionInBody)?;
        match ioc_line(numbered.text) {
            Ok(json) => collected.lines.push(json),
            Err(error) => collected.bad = count_bad(collected.bad, valid_shape(&error)?),
        }
        if collected.lines.len() > max_rows {
            Err(ReadError::TooManyRows(max_rows))
        } else {
            Ok(collected)
        }
    })
}


/// The settings check, then the read, under one deadline measured by the injected `elapsed`.
pub fn collect_iocs_timed(config: &ClickhouseConfig, now: OffsetDateTime, caps: ReadCaps, elapsed: &ElapsedFn) -> Result<Collected, ReadError> {
    validate_clickhouse(config).map_err(LoadError::Settings)?;
    let statement = read_statement(&config.database, &config.table)?;
    let password = read_password(&config.password_file).map_err(LoadError::Password)?;
    let key = std::str::from_utf8(&password).map_err(LoadError::PasswordEncoding)?;
    let agent = agent_for(config)?;
    check_profile(&agent, config, key, remaining_of(config, elapsed)?)?;
    let response = request_rows(&agent, config, key, &statement, now, caps.rows, remaining_of(config, elapsed)?)?;
    let mut reader = BufReader::new(response.into_body().into_reader().take(caps.bytes + 1));
    let collected = collect_rows(&mut reader, caps.rows);
    if reader.get_ref().limit() == 0 {
        Err(ReadError::TooManyBytes(caps.bytes))
    } else {
        collected
    }
}


pub fn collect_iocs(config: &ClickhouseConfig, now: OffsetDateTime, caps: ReadCaps) -> Result<Collected, ReadError> {
    let started = Instant::now();
    collect_iocs_timed(config, now, caps, &|| started.elapsed())
}


/// Reads one tenant's live IOCs and writes them as JSON lines only when the reply was complete: a truncated list is an error, nothing is written.
pub fn read_iocs(config: &ClickhouseConfig, now: OffsetDateTime, out: &mut dyn Write) -> Result<ReadSummary, ReadError> {
    read_iocs_capped(config, now, out, DEFAULT_CAPS)
}


/// `read_iocs` with the caps as arguments, so tests can use small ones.
pub fn read_iocs_capped(config: &ClickhouseConfig, now: OffsetDateTime, out: &mut dyn Write, caps: ReadCaps) -> Result<ReadSummary, ReadError> {
    let result = collect_iocs(config, now, caps).and_then(|collected| {
        collected
            .lines
            .iter()
            .try_for_each(|line| writeln!(out, "{line}"))
            .map_err(ReadError::Output)
            .map(|()| ReadSummary {
                rows: collected.lines.len(),
                bad: collected.bad,
            })
    });
    match &result {
        Ok(summary) => {
            let (rows, bad) = (summary.rows, summary.bad);
            info!(rows, ?bad, "IOC read done");
        }
        Err(_) => warn!("IOC read failed"),
    }
    result
}
