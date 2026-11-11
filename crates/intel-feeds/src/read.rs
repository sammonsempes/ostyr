use crate::config::{validate_clickhouse, ClickhouseConfig};
use crate::error::EntryError;
use crate::limits::{MAX_READ_BYTES, MAX_READ_ROWS};
use crate::lines::numbered_lines;
use crate::load::{agent_for, LoadError};
use crate::model::{Ioc, IocType, Source, Tags, Tlp};
use crate::store::{epoch_u32, read_statement, StoreError};
use core_pg::password::read_password;
use serde::{Deserialize, Deserializer};
use siem_ingest::clickhouse::{classify_reply, classify_transport, exception_code, KEY_HEADER, USER_HEADER};
use siem_ingest::error::InsertClass;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::time::Duration;
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
    #[error("more than {MAX_READ_ROWS} rows: the list would be truncated")]
    TooManyRows,
    #[error("reply larger than {MAX_READ_BYTES} bytes: the list would be truncated")]
    TooManyBytes,
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
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadSummary {
    pub rows: usize,
    pub bad_rows: u64,
}


/// The IOC lines read so far, held until the whole reply is known to be complete.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Collected {
    pub lines: Vec<String>,
    pub bad_rows: u64,
}


pub fn clickhouse_time<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<OffsetDateTime, Source::Error> {
    String::deserialize(deserializer).and_then(|text| {
        PrimitiveDateTime::parse(&text, format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"))
            .map(PrimitiveDateTime::assume_utc)
            .map_err(serde::de::Error::custom)
    })
}


/// One `JSONEachRow` line of the read statement; DateTime columns arrive as `YYYY-MM-DD HH:MM:SS` in UTC.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StoredRow {
    pub ioc_type: IocType,
    pub value: String,
    pub feed: String,
    pub feed_version: String,
    pub confidence: u8,
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


/// A row that does not parse (unknown TLP or type included) is an error, never a default.
pub fn ioc_line(text: Result<String, EntryError>) -> Result<String, RowError> {
    text.map_err(RowError::from)
        .and_then(|line| serde_json::from_str::<StoredRow>(&line).map_err(RowError::from))
        .and_then(|row| serde_json::to_string(&Ioc::from(row)).map_err(RowError::from))
}


/// One request under the whole `timeout_ms`; tenant, time and limit travel as query parameters, never in the statement text.
pub fn request_rows(
    agent: &Agent,
    config: &ClickhouseConfig,
    password: &str,
    statement: &str,
    now: OffsetDateTime,
) -> Result<Response<Body>, ReadError> {
    let reply = agent
        .post(&config.url)
        .header(USER_HEADER, &config.user)
        .header(KEY_HEADER, password)
        .query("query", statement)
        .query("param_tenant", &config.tenant)
        .query("param_now", epoch_u32(now.unix_timestamp()).to_string())
        .query("param_limit", (MAX_READ_ROWS + 1).to_string())
        .config()
        .timeout_global(Some(Duration::from_millis(config.timeout_ms)))
        .http_status_as_error(false)
        .build()
        .send(String::new());
    match reply {
        Ok(response) => {
            classify_reply(response.status(), exception_code(response.headers())).map_or(Ok(response), |class| Err(ReadError::Refused(class)))
        }
        Err(error) => Err(ReadError::Refused(classify_transport(&error))),
    }
}


/// Stops at the first row over `MAX_READ_ROWS`; a bad line is counted and the read goes on.
pub fn collect_rows(reader: &mut dyn BufRead) -> Result<Collected, ReadError> {
    numbered_lines(reader).try_fold(Collected::default(), |mut collected, line| {
        let numbered = line.map_err(ReadError::Body)?;
        match ioc_line(numbered.text) {
            Ok(json) => collected.lines.push(json),
            Err(_) => collected.bad_rows += 1,
        }
        if collected.lines.len() > MAX_READ_ROWS {
            Err(ReadError::TooManyRows)
        } else {
            Ok(collected)
        }
    })
}


pub fn collect_iocs(config: &ClickhouseConfig, now: OffsetDateTime) -> Result<Collected, ReadError> {
    validate_clickhouse(config).map_err(LoadError::Settings)?;
    let statement = read_statement(&config.database, &config.table)?;
    let password = read_password(&config.password_file).map_err(LoadError::Password)?;
    let key = std::str::from_utf8(&password).map_err(LoadError::PasswordEncoding)?;
    let agent = agent_for(config)?;
    let response = request_rows(&agent, config, key, &statement, now)?;
    let mut reader = BufReader::new(response.into_body().into_reader().take(MAX_READ_BYTES + 1));
    let collected = collect_rows(&mut reader)?;
    if reader.get_ref().limit() == 0 {
        Err(ReadError::TooManyBytes)
    } else {
        Ok(collected)
    }
}


/// Reads one tenant's live IOCs and writes them as JSON lines only when the reply was complete: a truncated list is an error, nothing is written.
pub fn read_iocs(config: &ClickhouseConfig, now: OffsetDateTime, out: &mut dyn Write) -> Result<ReadSummary, ReadError> {
    let result = collect_iocs(config, now).and_then(|collected| {
        collected
            .lines
            .iter()
            .try_for_each(|line| writeln!(out, "{line}"))
            .map_err(ReadError::Output)
            .map(|()| ReadSummary {
                rows: collected.lines.len(),
                bad_rows: collected.bad_rows,
            })
    });
    match &result {
        Ok(summary) => {
            let (rows, bad_rows) = (summary.rows, summary.bad_rows);
            info!(rows, bad_rows, "IOC read done");
        }
        Err(_) => warn!("IOC read failed"),
    }
    result
}
