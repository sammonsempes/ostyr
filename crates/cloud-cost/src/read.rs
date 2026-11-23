use crate::budget::short_label;
use crate::focus::{in_date_range, parse_amount};
use crate::load::{agent_for, LoadError};
use crate::model::{DEFAULT_MAX_FIELD_BYTES, DIMENSION_ACCOUNT_SERVICE, DIMENSION_TAG, DIMENSION_TOTAL};
use crate::settings::{validate_config, CostLoadConfig, CostSettingsError};
use crate::store::{qualified, state_target, STATE_DONE, STATE_IN_PROGRESS};
use crate::types::ElapsedFn;
use core_pg::password::read_password;
use log::warn;
use rust_decimal::Decimal;
use serde::Deserialize;
use siem_ingest::clickhouse::{classify_reply, classify_transport, exception_code, KEY_HEADER, USER_HEADER};
use siem_ingest::error::InsertClass;
use siem_ingest::reader_profile::{changed_statement, pin_clause, profile_refused, read_changed_bytes, url_settings, violations};
use siem_schema::error::SchemaError;
use std::io::{self, BufRead, BufReader, Read};
use std::time::{Duration, Instant};
use thiserror::Error;
use time::format_description::well_known::Iso8601;
use time::Date;
use ureq::http::Response;
use ureq::{Agent, Body};


pub const MAX_READ_DAYS: i64 = 366;


pub const MAX_READ_ROWS: usize = 50_000;


pub const MAX_READ_BYTES: u64 = 67_108_864;


pub const MAX_LOAD_STATES: usize = 1024;


pub const MAX_STATE_BYTES: u64 = 1_048_576;


pub const EXCEPTION_PREFIX: &str = "{\"exception\"";


pub const FORMAT_SUFFIX: &str = " FORMAT JSONEachRow";


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


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dimension {
    Total,
    AccountService,
    Tag,
}


/// The days are inclusive; `account` is one billing account label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyQuery {
    pub from: Date,
    pub to: Date,
    pub dimension: Dimension,
    pub account: Option<String>,
}


/// One stored aggregate as read back; the cost is exact decimal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyCost {
    pub day: Date,
    pub account: String,
    pub source: String,
    pub dimension: String,
    pub key1: String,
    pub key2: String,
    pub cost: Decimal,
    pub currency: String,
}


/// One `JSONEachRow` line of the read statement.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRow {
    pub day_text: String,
    pub account: String,
    pub source: String,
    pub dimension: String,
    pub key1: String,
    pub key2: String,
    pub cost_text: String,
    pub currency: String,
    pub tenant: String,
}


/// One `JSONEachRow` line of the load-state statement.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredState {
    pub tenant: String,
    pub source: String,
    pub generation_text: String,
    pub state: String,
}


/// The agent, settings and password of one read.
#[derive(Debug, Clone, Copy)]
pub struct Session<'a> {
    pub agent: &'a Agent,
    pub config: &'a CostLoadConfig,
    pub password: &'a str,
}


/// The statements and their bound parameters, built and checked before any I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPlan {
    pub statement: String,
    pub params: Vec<(String, String)>,
    pub state_statement: String,
    pub state_params: Vec<(String, String)>,
}


/// Every text is fixed: the server's message, a row, a value, the SQL and the URL never reach an error.
#[derive(Debug, Error)]
pub enum ReadError {
    #[error(transparent)]
    Settings(#[from] CostSettingsError),
    #[error(transparent)]
    Setup(#[from] LoadError),
    #[error(transparent)]
    Statement(#[from] SchemaError),
    #[error("the tenant differs from the settings tenant")]
    TenantMismatch,
    #[error("a day is outside the ClickHouse date range")]
    DayOutOfRange,
    #[error("the first day is after the last day")]
    SpanOrder,
    #[error("the span is longer than {MAX_READ_DAYS} days")]
    SpanTooLong,
    #[error("the account is not a valid label of at most {DEFAULT_MAX_FIELD_BYTES} bytes")]
    BadAccount,
    #[error("the read was refused: {0:?}")]
    Refused(InsertClass),
    #[error("reader_profile_changed: {0} setting(s) outside the allowed list")]
    ReaderProfileChanged(usize),
    #[error("the reply body could not be read ({0:?})")]
    Body(io::ErrorKind),
    #[error("a load of this tenant is running or failed, or the load states changed during the read: the result may be partial")]
    LoadInProgress,
    #[error("more than {0} load states for the tenant")]
    TooManyStates(usize),
    #[error("more than {0} rows: the result would be truncated")]
    TooManyRows(usize),
    #[error("reply larger than {0} bytes: the result would be truncated")]
    TooManyBytes(u64),
    #[error("the reply carries a ClickHouse exception line: the result would be truncated")]
    ExceptionInBody,
    #[error("a reply line is not a row of the expected shape")]
    MalformedReply,
    #[error("a reply row belongs to another tenant")]
    ForeignTenant,
    #[error("a reply row is outside the requested days, dimension or account")]
    OutOfScope,
}


pub fn dimension_name(dimension: Dimension) -> &'static str {
    match dimension {
        Dimension::Total => DIMENSION_TOTAL,
        Dimension::AccountService => DIMENSION_ACCOUNT_SERVICE,
        Dimension::Tag => DIMENSION_TAG,
    }
}


/// The three readable dimensions by name; `other` and `tag_other` are not readable.
pub fn parse_dimension(text: &str) -> Option<Dimension> {
    [Dimension::Total, Dimension::AccountService, Dimension::Tag]
        .into_iter()
        .find(|dimension| dimension_name(*dimension) == text)
}


/// `YYYY-MM-DD` and nothing else: the parsed day must write back as the same text.
pub fn parse_day_text(text: &str) -> Option<Date> {
    Date::parse(text, &Iso8601::DATE).ok().filter(|parsed| parsed.to_string() == text)
}


/// Both days inside ClickHouse's `Date` range, in order, at most `MAX_READ_DAYS` days.
pub fn check_span(from: Date, to: Date) -> Result<(), ReadError> {
    let days = (to - from).whole_days();
    if !in_date_range(from) || !in_date_range(to) {
        Err(ReadError::DayOutOfRange)
    } else if days < 0 {
        Err(ReadError::SpanOrder)
    } else if days >= MAX_READ_DAYS {
        Err(ReadError::SpanTooLong)
    } else {
        Ok(())
    }
}


/// The table's own grammar for an account label.
pub fn check_account(account: Option<&str>) -> Result<(), ReadError> {
    if account.is_some_and(|text| !short_label(text, DEFAULT_MAX_FIELD_BYTES)) {
        Err(ReadError::BadAccount)
    } else {
        Ok(())
    }
}


/// `FINAL` read of one tenant, one dimension and the days; every value is a bound parameter and the pins close the statement.
pub fn read_statement(config: &CostLoadConfig, with_account: bool, max_rows: usize) -> Result<String, ReadError> {
    let target = qualified(&config.database, &config.table)?;
    let account_filter = if with_account { " AND `account` = {account:String}" } else { "" };
    let pins = pin_clause(&[], max_rows as u64 + 1);
    Ok(format!(
        "SELECT toString(`day`) AS `day_text`, `account`, `source`, `dimension`, `key1`, `key2`, toString(`cost`) AS `cost_text`, `currency`, `tenant` \
         FROM {target} FINAL WHERE `tenant` = {{tenant:String}} AND `day` >= {{from:Date}} AND `day` <= {{to:Date}} \
         AND `dimension` = {{dimension:String}}{account_filter} \
         ORDER BY `day`, `account`, `source`, `dimension`, `key1`, `key2` LIMIT {{limit:UInt64}}{pins}{FORMAT_SUFFIX}"
    ))
}


/// `FINAL` read of every load-state row of the tenant (one per export digest), under the same pins.
pub fn state_statement(config: &CostLoadConfig) -> Result<String, ReadError> {
    let pins = pin_clause(&[], MAX_LOAD_STATES as u64 + 1);
    Ok(format!(
        "SELECT `tenant`, `source`, toString(`generation`) AS `generation_text`, `state` FROM {} FINAL WHERE `tenant` = {{tenant:String}} \
         ORDER BY `source` LIMIT {{limit:UInt64}}{pins}{FORMAT_SUFFIX}",
        state_target(config)?
    ))
}


/// ClickHouse reads a `String` parameter in escaped form: a backslash is doubled (labels hold no other control character).
pub fn escape_param(value: &str) -> String {
    value.replace('\\', "\\\\")
}


/// Everything that can be refused without a request: settings (the URL is at most 2048 bytes), tenant, days and account (at most 1024 bytes), which keep every request URL far under ureq's limit.
pub fn plan_read(config: &CostLoadConfig, tenant: &str, query: &DailyQuery, caps: ReadCaps) -> Result<ReadPlan, ReadError> {
    validate_config(config)?;
    check_span(query.from, query.to)?;
    check_account(query.account.as_deref())?;
    if tenant != config.tenant {
        Err(ReadError::TenantMismatch)
    } else {
        let statement = read_statement(config, query.account.is_some(), caps.rows)?;
        let params: Vec<(String, String)> = [
            ("tenant", Some(tenant.to_owned())),
            ("from", Some(query.from.to_string())),
            ("to", Some(query.to.to_string())),
            ("dimension", Some(dimension_name(query.dimension).to_owned())),
            ("account", query.account.as_deref().map(escape_param)),
            ("limit", Some((caps.rows + 1).to_string())),
        ]
        .into_iter()
        .filter_map(|(name, value)| value.map(|found| (name.to_owned(), found)))
        .collect();
        let state_params = vec![
            ("tenant".to_owned(), tenant.to_owned()),
            ("limit".to_owned(), (MAX_LOAD_STATES + 1).to_string()),
        ];
        Ok(ReadPlan {
            statement,
            params,
            state_statement: state_statement(config)?,
            state_params,
        })
    }
}


/// The time left of the one deadline `timeout_ms`; a spent budget sends nothing.
pub fn remaining_of(config: &CostLoadConfig, elapsed: &ElapsedFn) -> Result<Duration, ReadError> {
    let left = Duration::from_millis(config.timeout_ms).saturating_sub(elapsed());
    if left.is_zero() {
        Err(ReadError::Refused(InsertClass::Timeout))
    } else {
        Ok(left)
    }
}


/// One POST: the URL settings, the statement and its parameters as query values, nothing in the body; only a transport failure is an error here.
pub fn send_statement(
    agent: &Agent,
    config: &CostLoadConfig,
    password: &str,
    statement: &str,
    params: &[(String, String)],
    remaining: Duration,
) -> Result<Response<Body>, ReadError> {
    let with_url = url_settings(None)
        .iter()
        .fold(agent.post(&config.url), |builder, (name, value)| builder.query(*name, value));
    let with_params = params.iter().fold(with_url.query("query", statement), |builder, (name, value)| {
        builder.query(format!("param_{name}"), value)
    });
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


/// The settings check: a changed setting outside the pins, a pinned name missing or a refusal the profile caused is `ReaderProfileChanged`, before the read.
pub fn check_profile(agent: &Agent, config: &CostLoadConfig, password: &str, remaining: Duration) -> Result<(), ReadError> {
    let response = send_statement(agent, config, password, &changed_statement(), &[], remaining)?;
    let code = exception_code(response.headers());
    match classify_reply(response.status(), code) {
        Some(_) if profile_refused(code) => Err(ReadError::ReaderProfileChanged(1)),
        Some(class) => Err(ReadError::Refused(class)),
        None => {
            let bytes = read_changed_bytes(response.into_body().into_reader()).map_err(|error| ReadError::Body(error.kind()))?;
            let found = violations(&bytes, &[], None);
            if found > 0 {
                Err(ReadError::ReaderProfileChanged(found))
            } else {
                Ok(())
            }
        }
    }
}


/// One reply line: a row of the exact shape, of this tenant, inside the requested days, dimension and account.
pub fn parse_row(line: &str, tenant: &str, query: &DailyQuery) -> Result<DailyCost, ReadError> {
    if line.starts_with(EXCEPTION_PREFIX) {
        Err(ReadError::ExceptionInBody)
    } else {
        let stored = serde_json::from_str::<StoredRow>(line).map_err(|_| ReadError::MalformedReply)?;
        let day = parse_day_text(&stored.day_text).ok_or(ReadError::MalformedReply)?;
        let cost = parse_amount(&stored.cost_text).ok_or(ReadError::MalformedReply)?;
        let in_scope = day >= query.from
            && day <= query.to
            && stored.dimension == dimension_name(query.dimension)
            && query.account.as_ref().is_none_or(|account| *account == stored.account);
        if stored.tenant != tenant {
            Err(ReadError::ForeignTenant)
        } else if in_scope {
            Ok(DailyCost {
                day,
                account: stored.account,
                source: stored.source,
                dimension: stored.dimension,
                key1: stored.key1,
                key2: stored.key2,
                cost,
                currency: stored.currency,
            })
        } else {
            Err(ReadError::OutOfScope)
        }
    }
}


/// Stops at the first row over `max_rows`; a line that is not a good row is an error, never a skip.
pub fn collect_rows(reader: &mut dyn BufRead, tenant: &str, query: &DailyQuery, max_rows: usize) -> Result<Vec<DailyCost>, ReadError> {
    reader.lines().try_fold(Vec::new(), |mut rows, line| {
        let text = line.map_err(|error| ReadError::Body(error.kind()))?;
        rows.push(parse_row(&text, tenant, query)?);
        if rows.len() > max_rows {
            Err(ReadError::TooManyRows(max_rows))
        } else {
            Ok(rows)
        }
    })
}


/// The state row's generation text: digits only, written back as the same text.
pub fn parse_generation(text: &str) -> Option<u64> {
    text.parse::<u64>().ok().filter(|generation| generation.to_string() == text)
}


/// One state line: this tenant's, `done`, as its digest and generation; a running or failed load is `LoadInProgress`.
pub fn parse_state(line: &str, tenant: &str) -> Result<(String, u64), ReadError> {
    if line.starts_with(EXCEPTION_PREFIX) {
        Err(ReadError::ExceptionInBody)
    } else {
        let stored = serde_json::from_str::<StoredState>(line).map_err(|_| ReadError::MalformedReply)?;
        let generation = parse_generation(&stored.generation_text).ok_or(ReadError::MalformedReply)?;
        if stored.tenant != tenant {
            Err(ReadError::ForeignTenant)
        } else if stored.state == STATE_IN_PROGRESS {
            Err(ReadError::LoadInProgress)
        } else if stored.state == STATE_DONE {
            Ok((stored.source, generation))
        } else {
            Err(ReadError::MalformedReply)
        }
    }
}


/// Every load state of the tenant as (digest, generation) pairs, in digest order; none means no load ever ran, a running or failed one is `LoadInProgress`.
pub fn read_state(session: Session, plan: &ReadPlan, tenant: &str, remaining: Duration) -> Result<Vec<(String, u64)>, ReadError> {
    let response = send_statement(
        session.agent,
        session.config,
        session.password,
        &plan.state_statement,
        &plan.state_params,
        remaining,
    )?;
    match classify_reply(response.status(), exception_code(response.headers())) {
        Some(class) => Err(ReadError::Refused(class)),
        None => {
            let mut reader = BufReader::new(response.into_body().into_reader().take(MAX_STATE_BYTES + 1));
            let lines = reader
                .by_ref()
                .lines()
                .take(MAX_LOAD_STATES + 1)
                .collect::<Result<Vec<String>, io::Error>>()
                .map_err(|error| ReadError::Body(error.kind()))?;
            if reader.get_ref().limit() == 0 {
                Err(ReadError::MalformedReply)
            } else if lines.len() > MAX_LOAD_STATES {
                Err(ReadError::TooManyStates(MAX_LOAD_STATES))
            } else {
                lines.iter().map(|line| parse_state(line, tenant)).collect()
            }
        }
    }
}


/// The statement's rows, read under the byte and row caps.
pub fn read_rows(
    session: Session,
    plan: &ReadPlan,
    tenant: &str,
    query: &DailyQuery,
    caps: ReadCaps,
    remaining: Duration,
) -> Result<Vec<DailyCost>, ReadError> {
    let response = send_statement(session.agent, session.config, session.password, &plan.statement, &plan.params, remaining)?;
    match classify_reply(response.status(), exception_code(response.headers())) {
        Some(class) => Err(ReadError::Refused(class)),
        None => {
            let mut reader = BufReader::new(response.into_body().into_reader().take(caps.bytes + 1));
            let collected = collect_rows(&mut reader, tenant, query, caps.rows);
            if reader.get_ref().limit() == 0 {
                Err(ReadError::TooManyBytes(caps.bytes))
            } else {
                collected
            }
        }
    }
}


/// Refusals first, then the settings check, the load states, the read and the load states again, under one deadline measured by the injected `elapsed`.
pub fn read_daily_timed(
    config: &CostLoadConfig,
    tenant: &str,
    query: &DailyQuery,
    caps: ReadCaps,
    elapsed: &ElapsedFn,
) -> Result<Vec<DailyCost>, ReadError> {
    let plan = plan_read(config, tenant, query, caps)?;
    let password = read_password(&config.password_file).map_err(LoadError::Password)?;
    let key = std::str::from_utf8(&password).map_err(LoadError::PasswordEncoding)?;
    let agent = agent_for(config)?;
    check_profile(&agent, config, key, remaining_of(config, elapsed)?)?;
    let session = Session {
        agent: &agent,
        config,
        password: key,
    };
    let before = read_state(session, &plan, tenant, remaining_of(config, elapsed)?)?;
    let rows = read_rows(session, &plan, tenant, query, caps, remaining_of(config, elapsed)?)?;
    let after = read_state(session, &plan, tenant, remaining_of(config, elapsed)?)?;
    if before == after {
        Ok(rows)
    } else {
        Err(ReadError::LoadInProgress)
    }
}


/// `read_daily_timed` with the caps as arguments, so tests can use small ones.
pub fn read_daily_capped(config: &CostLoadConfig, tenant: &str, query: &DailyQuery, caps: ReadCaps) -> Result<Vec<DailyCost>, ReadError> {
    let started = Instant::now();
    let outcome = read_daily_timed(config, tenant, query, caps, &|| started.elapsed());
    if let Err(error) = &outcome {
        let text = error.to_string();
        warn!("cost read failed: {text}");
    }
    outcome
}


/// The daily aggregates of one tenant over a bounded span: a refused, cut or foreign result is an error; so is a load running or failed (a `in_progress` state), or a state that changed between the checks around the read.
pub fn read_daily(config: &CostLoadConfig, tenant: &str, query: &DailyQuery) -> Result<Vec<DailyCost>, ReadError> {
    read_daily_capped(config, tenant, query, DEFAULT_CAPS)
}


/// Printable ASCII only, a backslash and everything else as `\u{..}`: a label never changes the operator's terminal.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|character| {
            if (character.is_ascii_graphic() || character == ' ') && character != '\\' {
                character.to_string()
            } else {
                character.escape_unicode().to_string()
            }
        })
        .collect()
}
