use crate::settings::{validate_config, CostLoadConfig, CostSettingsError};
use crate::source::Export;
use crate::store::{
    account_set, array_literal, covered_days, database_ddl, delete_statement, generation_statement, insert_plan, insert_statement, next_generation,
    plan_rows, quote_item, state_ddl, state_insert_statement, state_row, table_ddl, Batch, STATE_DONE, STATE_IN_PROGRESS,
};
use crate::types::DayRange;
use core_pg::error::PgError;
use core_pg::password::{read_limited, read_password};
use core_pg::scope::tenant_of;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use siem_ingest::clickhouse::{classify_reply, classify_transport, exception_code, new_agent, KEY_HEADER, MAX_CA_BYTES, USER_HEADER};
use siem_ingest::error::{InsertClass, InsertError};
use siem_ingest::settings::is_loopback_http;
use siem_schema::error::SchemaError;
use std::io::Read;
use std::str::Utf8Error;
use std::time::Duration;
use thiserror::Error;
use ureq::Agent;


pub const MAX_REPLACE_ACCOUNTS: usize = 1001;


pub const MAX_URL_BYTES: usize = 60_000;


/// A comma between two array items, percent-encoded.
pub const COMMA_BYTES: usize = 3;


/// Characters ureq 3 percent-encodes in a query component (its `ENCODED_IN_QUERY`).
pub const ENCODED_IN_QUERY: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');


pub const MAX_GENERATION_BYTES: u64 = 64;


pub const MAX_TOTAL_ACCOUNTS: usize = 100_000;


#[derive(Debug, Error)]
pub enum LoadError {
    #[error(transparent)]
    Settings(#[from] CostSettingsError),
    #[error("the table's tenant differs from the settings tenant")]
    TenantMismatch,
    #[error("the export names more billing accounts than the total cap")]
    TooManyAccounts,
    #[error("a billing account name is too long for one request URL")]
    AccountTooLong,
    #[error("the settings make a request URL longer than the cap")]
    RequestTooLong,
    #[error("the export names billing accounts but no row has a readable day")]
    NoCoveredDay,
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
    #[error("the load state request refused ({0:?}): the tenant stays marked as loading until a rerun")]
    State(InsertClass),
    #[error("the previous load generation of the export could not be read")]
    GenerationReply,
    #[error("replacing the covered days refused ({class:?}) after {done} of {total} account batches")]
    Replace { done: usize, total: usize, class: InsertClass },
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
    [database_ddl(config)?, table_ddl(config)?, state_ddl(config)?]
        .into_iter()
        .try_for_each(|text| {
            post(agent, config, password, &plain(text), budget.saturating_sub(elapsed())).map_or(Ok(()), |class| Err(LoadError::Schema(class)))
        })
}


/// Length of `text` as ureq writes a query component (`.query`): percent-encoded, a space as `%20`.
pub fn encoded_len(text: &str) -> usize {
    utf8_percent_encode(text, ENCODED_IN_QUERY).map(str::len).sum()
}


/// Length of the URL ureq builds for the statement: the base URL, its path, `query` and every `param_` value, encoded.
pub fn request_url_len(config: &CostLoadConfig, statement: &Statement) -> usize {
    let params = statement.params.iter().map(|(name, value)| (format!("param_{name}"), value.as_str()));
    let query: usize = std::iter::once(("query".to_owned(), statement.text.as_str()))
        .chain(params)
        .map(|(key, value)| 1 + encoded_len(&key) + 1 + encoded_len(value))
        .sum();
    config.url.len() + 1 + query
}


/// What one account name adds to a delete URL: its quoted, escaped form and a comma, encoded.
pub fn item_cost(account: &str) -> usize {
    encoded_len(&quote_item(account)) + COMMA_BYTES
}


/// Account names cut in order into batches of at most `MAX_REPLACE_ACCOUNTS` names whose delete URL stays within `MAX_URL_BYTES`.
pub fn account_batches(skeleton_len: usize, accounts: &[String]) -> Result<Vec<Vec<String>>, LoadError> {
    accounts
        .iter()
        .try_fold(Vec::<(Vec<String>, usize)>::new(), |mut batches, account| {
            let cost = item_cost(account);
            let fits = batches
                .last()
                .is_some_and(|(names, bytes)| names.len() < MAX_REPLACE_ACCOUNTS && skeleton_len + bytes + cost <= MAX_URL_BYTES);
            if skeleton_len + cost > MAX_URL_BYTES {
                Err(LoadError::AccountTooLong)
            } else {
                if !fits {
                    batches.push((Vec::new(), 0));
                }
                batches.last_mut().into_iter().for_each(|(names, bytes)| {
                    names.push(account.clone());
                    *bytes += cost;
                });
                Ok(batches)
            }
        })
        .map(|batches| batches.into_iter().map(|(names, _)| names).collect())
}


/// The delete of the tenant's rows of `names` over the day range.
pub fn delete_request(config: &CostLoadConfig, text: &str, days: DayRange, names: &[String]) -> Statement {
    Statement {
        text: text.to_owned(),
        params: vec![
            ("tenant".to_owned(), config.tenant.clone()),
            ("accounts".to_owned(), array_literal(names)),
            ("first".to_owned(), days.0.to_string()),
            ("last".to_owned(), days.1.to_string()),
        ],
        body: String::new(),
    }
}


/// Every delete of the replace, built and checked against `MAX_URL_BYTES` before any request, the fixed statements' URLs included.
pub fn replace_statements(config: &CostLoadConfig, days: DayRange, accounts: &[String]) -> Result<Vec<Statement>, LoadError> {
    let text = delete_statement(config)?;
    let skeleton = delete_request(config, &text, days, &[]);
    let fixed = [
        database_ddl(config)?,
        table_ddl(config)?,
        state_ddl(config)?,
        insert_statement(config)?,
        state_insert_statement(config)?,
        generation_statement(config)?,
    ]
    .map(plain);
    let skeleton_len = request_url_len(config, &skeleton);
    let longest = fixed
        .iter()
        .map(|statement| request_url_len(config, statement))
        .chain([skeleton_len])
        .max()
        .unwrap_or(0);
    if longest > MAX_URL_BYTES {
        Err(LoadError::RequestTooLong)
    } else {
        Ok(account_batches(skeleton_len, accounts)?
            .iter()
            .map(|names| delete_request(config, &text, days, names))
            .collect())
    }
}


/// Sends the prepared deletes in order; a failure names the batches done.
pub fn replace_days(
    agent: &Agent,
    config: &CostLoadConfig,
    password: &str,
    deletes: &[Statement],
    elapsed: &dyn Fn() -> Duration,
) -> Result<(), LoadError> {
    let budget = Duration::from_millis(config.timeout_ms);
    let total = deletes.len();
    deletes.iter().enumerate().try_for_each(|(done, statement)| {
        post(agent, config, password, statement, budget.saturating_sub(elapsed()))
            .map_or(Ok(()), |class| Err(LoadError::Replace { done, total, class }))
    })
}


/// The highest generation written for the export digest, 0 for a digest never loaded; a reply that is not one number is `GenerationReply`.
pub fn previous_generation(
    agent: &Agent,
    config: &CostLoadConfig,
    password: &str,
    digest: &str,
    elapsed: &dyn Fn() -> Duration,
) -> Result<u64, LoadError> {
    let remaining = Duration::from_millis(config.timeout_ms).saturating_sub(elapsed());
    if remaining.is_zero() {
        Err(LoadError::State(InsertClass::Timeout))
    } else {
        let response = agent
            .post(&config.url)
            .header(USER_HEADER, &config.user)
            .header(KEY_HEADER, password)
            .query("query", generation_statement(config)?)
            .query("param_tenant", &config.tenant)
            .query("param_source", digest)
            .config()
            .timeout_global(Some(remaining))
            .http_status_as_error(false)
            .build()
            .send(String::new())
            .map_err(|error| LoadError::State(classify_transport(&error)))?;
        match classify_reply(response.status(), exception_code(response.headers())) {
            Some(class) => Err(LoadError::State(class)),
            None => {
                let mut text = String::new();
                let read = response
                    .into_body()
                    .into_reader()
                    .take(MAX_GENERATION_BYTES + 1)
                    .read_to_string(&mut text);
                read.ok()
                    .and_then(|_| text.trim_end_matches('\n').parse::<u64>().ok())
                    .ok_or(LoadError::GenerationReply)
            }
        }
    }
}


/// One state write of the export digest: `in_progress` before the first delete, `done` after the last batch, both with the load's generation.
pub fn write_state(
    agent: &Agent,
    config: &CostLoadConfig,
    password: &str,
    digest: &str,
    generation: u64,
    state: &str,
    elapsed: &dyn Fn() -> Duration,
) -> Result<(), LoadError> {
    let statement = Statement {
        text: state_insert_statement(config)?,
        params: Vec::new(),
        body: state_row(&config.tenant, digest, generation, state),
    };
    let budget = Duration::from_millis(config.timeout_ms);
    post(agent, config, password, &statement, budget.saturating_sub(elapsed())).map_or(Ok(()), |class| Err(LoadError::State(class)))
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


/// Password and CA are read, the schema is ensured, the export's state is marked `in_progress` under a generation above its previous one, the covered days of the export's accounts are replaced and the batches posted, then the state is marked `done` (only when every batch was stored), all under one deadline.
pub fn store_export(config: &CostLoadConfig, export: &Export, version: u64, elapsed: &dyn Fn() -> Duration) -> Result<LoadOutcome, LoadError> {
    let plan = insert_plan(&plan_rows(&export.table, &config.tenant, &export.source, version));
    match covered_days(&export.table) {
        None if export.table.seen_accounts.is_empty() => Ok(LoadOutcome::default()),
        None => Err(LoadError::NoCoveredDay),
        Some(days) => {
            let deletes = replace_statements(config, days, &account_set(&export.table))?;
            let password = read_password(&config.password_file).map_err(LoadError::Password)?;
            let key = std::str::from_utf8(&password).map_err(LoadError::PasswordEncoding)?;
            let agent = agent_for(config)?;
            ensure_schema(&agent, config, key, elapsed)?;
            let generation = next_generation(previous_generation(&agent, config, key, &export.source, elapsed)?, version);
            write_state(&agent, config, key, &export.source, generation, STATE_IN_PROGRESS, elapsed)?;
            replace_days(&agent, config, key, &deletes, elapsed)?;
            let outcome = send_batches(&agent, config, key, &plan, elapsed)?;
            if outcome.failure.is_none() {
                write_state(&agent, config, key, &export.source, generation, STATE_DONE, elapsed)?;
            }
            Ok(outcome)
        }
    }
}


/// Settings, tenant and the replace bounds are checked first, before any file or network I/O.
pub fn load_table(config: &CostLoadConfig, export: &Export, version: u64, elapsed: &dyn Fn() -> Duration) -> Result<LoadOutcome, LoadError> {
    validate_config(config)?;
    let total = export.table.seen_accounts.len();
    if tenant_of(&export.table.tenant) != config.tenant {
        Err(LoadError::TenantMismatch)
    } else if total > MAX_TOTAL_ACCOUNTS {
        Err(LoadError::TooManyAccounts)
    } else {
        store_export(config, export, version, elapsed)
    }
}
