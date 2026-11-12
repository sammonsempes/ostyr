use crate::settings::{validate_config, CostLoadConfig, CostSettingsError};
use crate::source::Export;
use crate::store::{covered_days, database_ddl, delete_statement, insert_plan, insert_statement, plan_rows, table_ddl, Batch};
use core_pg::error::PgError;
use core_pg::password::{read_limited, read_password};
use core_pg::scope::tenant_of;
use siem_ingest::clickhouse::{classify_reply, classify_transport, exception_code, new_agent, KEY_HEADER, MAX_CA_BYTES, USER_HEADER};
use siem_ingest::error::{InsertClass, InsertError};
use siem_ingest::settings::is_loopback_http;
use siem_schema::error::SchemaError;
use std::str::Utf8Error;
use std::time::Duration;
use thiserror::Error;
use ureq::Agent;


#[derive(Debug, Error)]
pub enum LoadError {
    #[error(transparent)]
    Settings(#[from] CostSettingsError),
    #[error("the table's tenant differs from the settings tenant")]
    TenantMismatch,
    #[error("the ClickHouse password file could not be used")]
    Password(#[source] PgError),
    #[error("the ClickHouse password is not valid UTF-8")]
    PasswordEncoding(#[source] Utf8Error),
    #[error("the ClickHouse CA file could not be used")]
    CaFile(#[source] PgError),
    #[error(transparent)]
    Agent(#[from] InsertError),
    #[error(transparent)]
    Statement(#[from] SchemaError),
    #[error("schema statement refused: {0:?}")]
    Schema(InsertClass),
    #[error("replacing the covered days refused: {0:?}")]
    Replace(InsertClass),
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


/// One statement: its text (sent as the `query` parameter), its bound parameters (sent as `param_<name>`) and its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub text: String,
    pub params: Vec<(String, String)>,
    pub body: String,
}


/// The CA file is read again at every load, through a handle that must be a regular file, so a swapped CA applies at once.
pub fn agent_for(config: &CostLoadConfig) -> Result<Agent, LoadError> {
    let pem = config
        .ca_file
        .as_deref()
        .map(|path| read_limited(path, MAX_CA_BYTES).map_err(LoadError::CaFile))
        .transpose()?;
    Ok(new_agent(pem.as_deref().map(Vec::as_slice), !is_loopback_http(&config.url))?)
}


/// One request under what is left of the global deadline; a spent deadline sends nothing. The server's own message is never read.
pub fn post(agent: &Agent, config: &CostLoadConfig, password: &str, statement: &Statement, remaining: Duration) -> Option<InsertClass> {
    if remaining.is_zero() {
        Some(InsertClass::Timeout)
    } else {
        let base = agent
            .post(&config.url)
            .header(USER_HEADER, &config.user)
            .header(KEY_HEADER, password)
            .query("query", &statement.text);
        let request = statement
            .params
            .iter()
            .fold(base, |builder, (name, value)| builder.query(format!("param_{name}"), value));
        let reply = request
            .config()
            .timeout_global(Some(remaining))
            .http_status_as_error(false)
            .build()
            .send(statement.body.clone());
        match reply {
            Ok(response) => classify_reply(response.status(), exception_code(response.headers())),
            Err(error) => Some(classify_transport(&error)),
        }
    }
}


pub fn plain(text: String) -> Statement {
    Statement {
        text,
        params: Vec::new(),
        body: String::new(),
    }
}


/// Database then table, each `IF NOT EXISTS`, so a rerun changes nothing.
pub fn ensure_schema(agent: &Agent, config: &CostLoadConfig, password: &str, elapsed: &dyn Fn() -> Duration) -> Result<(), LoadError> {
    let budget = Duration::from_millis(config.timeout_ms);
    [database_ddl(config)?, table_ddl(config)?].into_iter().try_for_each(|text| {
        post(agent, config, password, &plain(text), budget.saturating_sub(elapsed())).map_or(Ok(()), |class| Err(LoadError::Schema(class)))
    })
}


/// Removes the tenant's rows of the days the export covers, so a corrected export of a period replaces the old one instead of adding to it.
pub fn replace_days(
    agent: &Agent,
    config: &CostLoadConfig,
    password: &str,
    days: (time::Date, time::Date),
    elapsed: &dyn Fn() -> Duration,
) -> Result<(), LoadError> {
    let budget = Duration::from_millis(config.timeout_ms);
    let statement = Statement {
        text: delete_statement(config)?,
        params: vec![
            ("tenant".to_owned(), config.tenant.clone()),
            ("first".to_owned(), days.0.to_string()),
            ("last".to_owned(), days.1.to_string()),
        ],
        body: String::new(),
    };
    post(agent, config, password, &statement, budget.saturating_sub(elapsed())).map_or(Ok(()), |class| Err(LoadError::Replace(class)))
}


/// A failed batch stops the load: the outcome lists the batches stored before it and the plan's size, never a silent partial success.
pub fn send_batches(
    agent: &Agent,
    config: &CostLoadConfig,
    password: &str,
    batches: &[Batch],
    elapsed: &dyn Fn() -> Duration,
) -> Result<LoadOutcome, LoadError> {
    let text = insert_statement(config)?;
    let budget = Duration::from_millis(config.timeout_ms);
    let mut stored = Vec::new();
    let failure = batches
        .iter()
        .enumerate()
        .try_for_each(|(index, batch)| {
            let statement = Statement {
                text: text.clone(),
                params: Vec::new(),
                body: batch.body.clone(),
            };
            post(agent, config, password, &statement, budget.saturating_sub(elapsed())).map_or_else(
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


/// Settings and tenant are checked first, then the password and CA are read, the schema is ensured, the covered days are replaced and the batches posted under one deadline.
pub fn load_table(config: &CostLoadConfig, export: &Export, version: u64, elapsed: &dyn Fn() -> Duration) -> Result<LoadOutcome, LoadError> {
    validate_config(config)?;
    if tenant_of(&export.table.tenant) != config.tenant {
        Err(LoadError::TenantMismatch)
    } else {
        let plan = insert_plan(&plan_rows(&export.table, &config.tenant, &export.source, version));
        match covered_days(&export.table) {
            None => Ok(LoadOutcome::default()),
            Some(days) => {
                let password = read_password(&config.password_file).map_err(LoadError::Password)?;
                let key = std::str::from_utf8(&password).map_err(LoadError::PasswordEncoding)?;
                let agent = agent_for(config)?;
                ensure_schema(&agent, config, key, elapsed)?;
                replace_days(&agent, config, key, days, elapsed)?;
                send_batches(&agent, config, key, &plan, elapsed)
            }
        }
    }
}
