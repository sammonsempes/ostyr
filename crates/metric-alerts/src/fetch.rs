use crate::query::MetricQuery;
use crate::types::Point;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_pg::error::PgError;
use core_pg::password::{read_limited, read_password};
use serde::Deserialize;
use siem_ingest::clickhouse::{classify_reply, classify_transport, exception_code, new_agent, KEY_HEADER, USER_HEADER};
use siem_ingest::error::{InsertClass, InsertError, SettingsError as UrlError};
use siem_ingest::settings::{check_url, is_loopback_http};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::Utf8Error;
use std::time::Duration;
use thiserror::Error;
use tracing::warn;
use ureq::Agent;
use zeroize::Zeroizing;


pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;


pub const MAX_TIMEOUT_MS: u64 = 300_000;


pub const MAX_USER_BYTES: usize = 128;


pub const MAX_CA_BYTES: u64 = 65_536;


pub const MAX_FETCH_BYTES: u64 = 8_388_608;


pub const MAX_FETCH_POINTS: usize = 100_000;


pub const FORMAT_SUFFIX: &str = " FORMAT TabSeparated";


pub const PARAM_PREFIX: &str = "param_";


/// Lines refused in a reply, by kind; the whole fetch fails when any is non-zero and no line content is kept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LineFaults {
    pub columns: usize,
    pub timestamp: usize,
    pub value: usize,
    pub non_finite: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineFault {
    Columns,
    Timestamp,
    Value,
    NonFinite,
}


/// Read afresh at every use; the password is only a path here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchSettings {
    pub url: String,
    pub user: String,
    pub password_file: PathBuf,
    pub ca_file: Option<PathBuf>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}


pub fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}


/// Every text is fixed: the server's message, a row, a value, the SQL and the URL never reach an error.
#[derive(Debug, Error)]
pub enum FetchError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("url refused")]
    Url(#[from] UrlError),
    #[error("user must be 1 to {MAX_USER_BYTES} printable ASCII characters")]
    User,
    #[error("timeout_ms must be within 1..={MAX_TIMEOUT_MS}")]
    Timeout,
    #[error("the ClickHouse password file could not be used")]
    Password(#[source] PgError),
    #[error("the ClickHouse password is not valid UTF-8")]
    PasswordEncoding(#[source] Utf8Error),
    #[error("the ClickHouse CA file could not be used")]
    CaFile(#[source] PgError),
    #[error(transparent)]
    Agent(#[from] InsertError),
    #[error("fetch refused: {}", class_text(*.0))]
    Failed(InsertClass),
    #[error("the reply body could not be read")]
    Body(#[source] io::Error),
    #[error("the reply is larger than {MAX_FETCH_BYTES} bytes")]
    TooLarge,
    #[error("the reply holds more than {MAX_FETCH_POINTS} rows")]
    TooManyPoints,
    #[error(
        "the reply is malformed: {} wrong column count, {} bad timestamp, {} bad value, {} non-finite value",
        .0.columns, .0.timestamp, .0.value, .0.non_finite
    )]
    Malformed(LineFaults),
}


/// Fixed text per class: the server's message never reaches a log.
pub fn class_text(class: InsertClass) -> &'static str {
    match class {
        InsertClass::ParseError => "the server could not parse the query",
        InsertClass::Unavailable => "the server is unavailable",
        InsertClass::Timeout => "the deadline passed",
        InsertClass::Unauthorized => "the server refused the credentials",
        InsertClass::Rejected => "the server rejected the query",
    }
}


/// ClickHouse escaped-TSV form of an HTTP parameter value: backslash, tab, newline, carriage return and NUL; nothing else changes.
pub fn escape_param(value: &str) -> String {
    value.chars().fold(String::with_capacity(value.len()), |mut escaped, character| {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\t' => escaped.push_str("\\t"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\0' => escaped.push_str("\\0"),
            other => escaped.push(other),
        }
        escaped
    })
}


/// URL by siem-ingest's rule (https, or http on loopback), user and timeout bounded.
pub fn validate_fetch_settings(settings: &FetchSettings) -> Result<(), FetchError> {
    check_url(&settings.url)?;
    let user_ok =
        !settings.user.is_empty() && settings.user.len() <= MAX_USER_BYTES && settings.user.chars().all(|character| character.is_ascii_graphic());
    if !user_ok {
        Err(FetchError::User)
    } else if settings.timeout_ms == 0 || settings.timeout_ms > MAX_TIMEOUT_MS {
        Err(FetchError::Timeout)
    } else {
        Ok(())
    }
}


/// Strict YAML through core-config, then validated.
pub fn load_fetch_settings(path: &Path) -> Result<FetchSettings, FetchError> {
    let settings = load_file::<FetchSettings>(path)?;
    validate_fetch_settings(&settings)?;
    Ok(settings)
}


/// The CA is read through a checked handle at every call, so a swapped file applies from the next fetch.
pub fn agent_for(settings: &FetchSettings) -> Result<Agent, FetchError> {
    validate_fetch_settings(settings)?;
    let pem = settings
        .ca_file
        .as_deref()
        .map(|path| read_limited(path, MAX_CA_BYTES).map_err(FetchError::CaFile))
        .transpose()?;
    Ok(new_agent(pem.as_deref().map(Vec::as_slice), !is_loopback_http(&settings.url))?)
}


/// The password through core-pg's checked reader, held in `Zeroizing`.
pub fn read_key(settings: &FetchSettings) -> Result<Zeroizing<String>, FetchError> {
    let bytes = read_password(&settings.password_file).map_err(FetchError::Password)?;
    Ok(Zeroizing::new(
        std::str::from_utf8(&bytes).map_err(FetchError::PasswordEncoding)?.to_owned(),
    ))
}


/// One line is `ts<TAB>value`: an unsigned timestamp and a finite float.
pub fn parse_line(line: &str) -> Result<Point, LineFault> {
    let mut columns = line.split('\t');
    match (columns.next(), columns.next(), columns.next()) {
        (Some(timestamp), Some(value), None) => {
            let seconds = timestamp.parse::<u64>().map_err(|_| LineFault::Timestamp)?;
            let number = value.parse::<f64>().map_err(|_| LineFault::Value)?;
            if number.is_finite() {
                Ok((seconds, number))
            } else {
                Err(LineFault::NonFinite)
            }
        }
        _ => Err(LineFault::Columns),
    }
}


pub fn count_fault(faults: LineFaults, fault: LineFault) -> LineFaults {
    match fault {
        LineFault::Columns => LineFaults {
            columns: faults.columns + 1,
            ..faults
        },
        LineFault::Timestamp => LineFaults {
            timestamp: faults.timestamp + 1,
            ..faults
        },
        LineFault::Value => LineFaults {
            value: faults.value + 1,
            ..faults
        },
        LineFault::NonFinite => LineFaults {
            non_finite: faults.non_finite + 1,
            ..faults
        },
    }
}


/// Past `MAX_FETCH_POINTS` rows the fetch fails: a cut series would change a forecast. Every line is counted, then the fetch fails as a whole.
pub fn parse_points(text: &str) -> Result<Vec<Point>, FetchError> {
    if text.lines().count() > MAX_FETCH_POINTS {
        Err(FetchError::TooManyPoints)
    } else {
        let (points, faults) = text
            .lines()
            .map(parse_line)
            .fold((Vec::new(), LineFaults::default()), |(mut points, faults), parsed| match parsed {
                Ok(point) => {
                    points.push(point);
                    (points, faults)
                }
                Err(fault) => (points, count_fault(faults, fault)),
            });
        if faults == LineFaults::default() {
            Ok(points)
        } else {
            Err(FetchError::Malformed(faults))
        }
    }
}


/// At most `MAX_FETCH_BYTES + 1` bytes are ever buffered; a longer body is refused, never cut.
pub fn read_points<Source: Read>(reader: Source) -> Result<Vec<Point>, FetchError> {
    let mut bytes = Vec::new();
    reader.take(MAX_FETCH_BYTES + 1).read_to_end(&mut bytes).map_err(FetchError::Body)?;
    if bytes.len() as u64 > MAX_FETCH_BYTES {
        Err(FetchError::TooLarge)
    } else {
        parse_points(&String::from_utf8_lossy(&bytes))
    }
}


/// One request under `remaining`; a spent deadline sends nothing. The server's own message is never read.
pub fn request_points(
    agent: &Agent,
    settings: &FetchSettings,
    password: &str,
    query: &MetricQuery,
    remaining: Duration,
) -> Result<Vec<Point>, FetchError> {
    if remaining.is_zero() {
        Err(FetchError::Failed(InsertClass::Timeout))
    } else {
        let statement = format!("{}{FORMAT_SUFFIX}", query.sql.trim_end());
        let builder = query.params.iter().fold(agent.post(&settings.url), |builder, (name, value)| {
            builder.query(format!("{PARAM_PREFIX}{name}"), escape_param(value))
        });
        let response = builder
            .header(USER_HEADER, &settings.user)
            .header(KEY_HEADER, password)
            .config()
            .timeout_global(Some(remaining))
            .http_status_as_error(false)
            .build()
            .send(statement)
            .map_err(|error| FetchError::Failed(classify_transport(&error)))?;
        match classify_reply(response.status(), exception_code(response.headers())) {
            Some(class) => Err(FetchError::Failed(class)),
            None => read_points(response.into_body().into_reader()),
        }
    }
}


/// The query's own params, escaped and unchanged, so its `tenant` parameter is the only tenant filter; a failure is logged with its fixed text.
pub fn fetch_points(
    agent: &Agent,
    settings: &FetchSettings,
    password: &str,
    query: &MetricQuery,
    remaining: Duration,
) -> Result<Vec<Point>, FetchError> {
    let outcome = request_points(agent, settings, password, query, remaining);
    if let Err(error) = &outcome {
        let text = error.to_string();
        warn!("metric fetch failed: {text}");
    }
    outcome
}
