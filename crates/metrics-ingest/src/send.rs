use crate::settings::{validated_statement, MetricsSettings, SettingsError, MAX_CA_BYTES};
use crate::types::ElapsedFn;
use core_pg::error::PgError;
use core_pg::password::{read_limited, read_password};
use siem_ingest::clickhouse::{classify_reply, classify_transport, exception_code, new_agent, KEY_HEADER, USER_HEADER};
use siem_ingest::error::{InsertClass, InsertError};
use siem_ingest::settings::is_loopback_http;
use std::str::Utf8Error;
use std::time::Duration;
use thiserror::Error;
use tracing::warn;
use ureq::Agent;
use zeroize::Zeroizing;


#[derive(Debug, Error)]
pub enum SendError {
    #[error(transparent)]
    Settings(#[from] SettingsError),
    #[error("the ClickHouse password file could not be used")]
    Password(#[source] PgError),
    #[error("the ClickHouse password is not valid UTF-8")]
    PasswordEncoding(#[source] Utf8Error),
    #[error("the ClickHouse CA file could not be used")]
    CaFile(#[source] PgError),
    #[error(transparent)]
    Agent(#[from] InsertError),
    #[error("batch refused: {}", class_text(*.0))]
    Failed(InsertClass),
}


/// Fixed text per class: the server's message, the URL and the body never reach a log.
pub fn class_text(class: InsertClass) -> &'static str {
    match class {
        InsertClass::ParseError => "the server could not parse the rows",
        InsertClass::Unavailable => "the server is unavailable",
        InsertClass::Timeout => "the deadline passed",
        InsertClass::Unauthorized => "the server refused the credentials",
        InsertClass::Rejected => "the server rejected the insert",
    }
}


/// One request under what is left of the global deadline; a spent deadline sends nothing. The server's own message is never read.
pub fn post_batch(
    agent: &Agent,
    settings: &MetricsSettings,
    statement: &str,
    password: &str,
    body: &[u8],
    remaining: Duration,
) -> Option<InsertClass> {
    if remaining.is_zero() {
        Some(InsertClass::Timeout)
    } else {
        let reply = agent
            .post(&settings.url)
            .query("query", statement)
            .header(USER_HEADER, &settings.user)
            .header(KEY_HEADER, password)
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


/// Reads the password and CA through checked handles; every call shares the one `timeout_ms` deadline; a failure is logged with its fixed text.
pub fn clickhouse_sender<'a>(
    settings: &'a MetricsSettings,
    elapsed: &'a ElapsedFn<'a>,
) -> Result<impl FnMut(&[u8]) -> Result<(), SendError> + 'a, SendError> {
    let statement = validated_statement(settings)?;
    let password = read_password(&settings.password_file).map_err(SendError::Password)?;
    let key = Zeroizing::new(std::str::from_utf8(&password).map_err(SendError::PasswordEncoding)?.to_owned());
    let pem = settings
        .ca_file
        .as_deref()
        .map(|path| read_limited(path, MAX_CA_BYTES).map_err(SendError::CaFile))
        .transpose()?;
    let agent = new_agent(pem.as_deref(), !is_loopback_http(&settings.url))?;
    let budget = Duration::from_millis(settings.timeout_ms);
    Ok(move |body: &[u8]| {
        let failure = post_batch(&agent, settings, &statement, &key, body, budget.saturating_sub(elapsed()));
        failure.map_or(Ok(()), |class| {
            let text = class_text(class);
            warn!("metrics insert failed: {text}");
            Err(SendError::Failed(class))
        })
    })
}
