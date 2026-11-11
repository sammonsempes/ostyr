use crate::config::{validate_clickhouse, ClickhouseConfig, ClickhouseError, FeedConfig};
use crate::model::Ioc;
use crate::store::{dictionary_ddl, insert_plan, insert_statement, quote_identifier, settings_for, table_ddl, Batch, StoreError};
use core_pg::error::PgError;
use core_pg::password::{read_limited, read_password};
use serde::Serialize;
use siem_ingest::clickhouse::{classify_reply, classify_transport, exception_code, new_agent, KEY_HEADER, MAX_CA_BYTES, USER_HEADER};
use siem_ingest::error::{InsertClass, InsertError};
use siem_ingest::settings::is_loopback_http;
use std::str::Utf8Error;
use std::time::Duration;
use thiserror::Error;
use time::OffsetDateTime;
use ureq::Agent;


#[derive(Debug, Error)]
pub enum LoadError {
    #[error(transparent)]
    Settings(#[from] ClickhouseError),
    #[error("the ClickHouse password file could not be used")]
    Password(#[source] PgError),
    #[error("the ClickHouse password is not valid UTF-8")]
    PasswordEncoding(#[source] Utf8Error),
    #[error("the ClickHouse CA file could not be used")]
    CaFile(#[source] PgError),
    #[error(transparent)]
    Agent(#[from] InsertError),
    #[error(transparent)]
    Statement(#[from] StoreError),
    #[error("schema statement refused: {0:?}")]
    Schema(InsertClass),
}


/// The batch that stopped the load: its position, its row count and the failure class (the server's text is never read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchFailure {
    pub index: usize,
    pub rows: usize,
    pub class: InsertClass,
}


/// `rows_per_batch` lists the batches stored before any failure, in order; the rest of the plan was not sent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadOutcome {
    pub rows_per_batch: Vec<usize>,
    pub batches_planned: usize,
    pub failure: Option<BatchFailure>,
}


/// The `run` command's report line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadSummary {
    pub clickhouse_rows_sent: usize,
    pub clickhouse_batches_stored: usize,
    pub clickhouse_batches_failed: usize,
    pub failed_batch: Option<usize>,
    pub error: Option<String>,
}


pub fn summarise(result: &Result<LoadOutcome, LoadError>) -> LoadSummary {
    match result {
        Ok(outcome) => LoadSummary {
            clickhouse_rows_sent: outcome.rows_per_batch.iter().sum(),
            clickhouse_batches_stored: outcome.rows_per_batch.len(),
            clickhouse_batches_failed: outcome.batches_planned - outcome.rows_per_batch.len(),
            failed_batch: outcome.failure.map(|failure| failure.index),
            error: outcome.failure.map(|failure| format!("batch refused: {:?}", failure.class)),
        },
        Err(error) => LoadSummary {
            clickhouse_rows_sent: 0,
            clickhouse_batches_stored: 0,
            clickhouse_batches_failed: 0,
            failed_batch: None,
            error: Some(error.to_string()),
        },
    }
}


/// The CA file is read again at every load, through an `O_NONBLOCK` handle that must be a regular file, so a swapped CA applies at once.
pub fn agent_for(config: &ClickhouseConfig) -> Result<Agent, LoadError> {
    let pem = config
        .ca_file
        .as_deref()
        .map(|path| read_limited(path, MAX_CA_BYTES).map_err(LoadError::CaFile))
        .transpose()?;
    Ok(new_agent(pem.as_deref().map(Vec::as_slice), !is_loopback_http(&config.url))?)
}


/// One request under what is left of the global deadline; a spent deadline sends nothing. The server's own message is never read.
pub fn post(
    agent: &Agent,
    config: &ClickhouseConfig,
    password: &str,
    statement: Option<&str>,
    body: String,
    remaining: Duration,
) -> Option<InsertClass> {
    if remaining.is_zero() {
        Some(InsertClass::Timeout)
    } else {
        let base = agent.post(&config.url).header(USER_HEADER, &config.user).header(KEY_HEADER, password);
        let request = statement.iter().fold(base, |builder, text| builder.query("query", *text));
        let reply = request
            .config()
            .timeout_global(Some(remaining))
            .http_status_as_error(false)
            .build()
            .send(body);
        match reply {
            Ok(response) => classify_reply(response.status(), exception_code(response.headers())),
            Err(error) => Some(classify_transport(&error)),
        }
    }
}


/// Database, table and dictionary, each `IF NOT EXISTS`, so a rerun changes nothing.
pub fn schema_statements(config: &ClickhouseConfig) -> Result<Vec<String>, StoreError> {
    Ok(vec![
        format!("CREATE DATABASE IF NOT EXISTS {}", quote_identifier(&config.database)?),
        table_ddl(&config.database, &config.table)?,
        dictionary_ddl(
            &config.database,
            &config.table,
            &config.dictionary,
            &config.dictionary_user,
            config.dictionary_port,
        )?,
    ])
}


/// Runs the three statements in order and stops at the first refusal.
pub fn ensure_schema(agent: &Agent, config: &ClickhouseConfig, password: &str, elapsed: &dyn Fn() -> Duration) -> Result<(), LoadError> {
    let budget = Duration::from_millis(config.timeout_ms);
    schema_statements(config)?.into_iter().try_for_each(|statement| {
        post(agent, config, password, None, statement, budget.saturating_sub(elapsed())).map_or(Ok(()), |class| Err(LoadError::Schema(class)))
    })
}


/// A failed batch stops the load: the outcome lists the batches stored before it and the plan's size, never a silent partial success.
pub fn send_batches(
    agent: &Agent,
    config: &ClickhouseConfig,
    password: &str,
    batches: &[Batch],
    elapsed: &dyn Fn() -> Duration,
) -> Result<LoadOutcome, LoadError> {
    let statement = insert_statement(&config.database, &config.table)?;
    let budget = Duration::from_millis(config.timeout_ms);
    let mut stored = Vec::new();
    let failure = batches
        .iter()
        .enumerate()
        .try_for_each(|(index, batch)| {
            let reply = post(
                agent,
                config,
                password,
                Some(&statement),
                batch.body.clone(),
                budget.saturating_sub(elapsed()),
            );
            reply.map_or_else(
                || {
                    stored.push(batch.rows);
                    Ok(())
                },
                |class| {
                    Err(BatchFailure {
                        index,
                        rows: batch.rows,
                        class,
                    })
                },
            )
        })
        .err();
    Ok(LoadOutcome {
        rows_per_batch: stored,
        batches_planned: batches.len(),
        failure,
    })
}


/// Settings are validated first, then the password and CA are read, then the schema is ensured and the batches are posted under one deadline.
pub fn load_iocs(
    config: &ClickhouseConfig,
    iocs: &[Ioc],
    feeds: &[FeedConfig],
    now: OffsetDateTime,
    elapsed: &dyn Fn() -> Duration,
) -> Result<LoadOutcome, LoadError> {
    validate_clickhouse(config)?;
    let plan = insert_plan(iocs, &settings_for(&config.tenant, feeds), now);
    let password = read_password(&config.password_file).map_err(LoadError::Password)?;
    let key = std::str::from_utf8(&password).map_err(LoadError::PasswordEncoding)?;
    let agent = agent_for(config)?;
    ensure_schema(&agent, config, key, elapsed)?;
    send_batches(&agent, config, key, &plan.batches, elapsed)
}
