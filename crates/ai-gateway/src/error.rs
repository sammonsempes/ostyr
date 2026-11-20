use core_pg::error::PgError;
use std::io;
use thiserror::Error;


/// Which part of the API key file was refused; never its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretClass {
    Unreadable,
    Refused,
    Format,
    TooLarge,
}


/// Fixed variants only: no peer text, no `ureq`, `serde_json` or `rustls` error is kept as a source.
#[derive(Debug, Error)]
pub enum AiError {
    #[error("the model endpoint answered status {status}")]
    Status { status: u16 },
    #[error("the model endpoint did not answer within the deadline")]
    Timeout,
    #[error("cannot connect to the model endpoint")]
    Connect,
    #[error("the TLS exchange with the model endpoint failed")]
    Tls,
    #[error("input or output failed with kind {kind}")]
    Io { kind: io::ErrorKind },
    #[error("the model endpoint broke the HTTP protocol")]
    Protocol,
    #[error("the CA file cannot be used")]
    CaFile,
    #[error("the answer is not the expected JSON at line {line} column {column}")]
    Malformed { line: usize, column: usize },
    #[error("the answer holds no choice")]
    NoChoice,
    #[error("the answer holds more than {cap} choices")]
    TooManyChoices { cap: usize },
    #[error("the answer holds more than {cap} arrays, objects and separators")]
    TooManyNodes { cap: usize },
    #[error("the answer is larger than {cap} bytes")]
    ResponseTooLarge { cap: usize },
    #[error("the request is {bytes} bytes, over the cap of {cap}")]
    RequestTooLarge { bytes: usize, cap: usize },
    #[error("the telemetry document has too many nodes or is nested too deep")]
    DataTooComplex,
    #[error("the telemetry document holds the closing delimiter")]
    DataHoldsDelimiter,
    #[error("setting {field} is refused")]
    Settings { field: &'static str },
    #[error("the API key file is refused: {class:?}")]
    Secret { class: SecretClass },
    #[error("no random bytes are available")]
    Random(#[from] getrandom::Error),
    #[error("the daily budget of calls or tokens is spent")]
    BudgetSpent,
    #[error("the request reserves {reserved} tokens, over the daily cap of {cap}")]
    RequestOverBudget { reserved: i64, cap: i64 },
    #[error("the daily budget has no room right now: reservations are in flight or too many wait on the store, retry later")]
    BudgetBusy,
    #[error("the budget store failed")]
    Store(#[from] PgError),
    #[error("the budget store answered with an unexpected number of rows")]
    BadReply,
    #[error("the wall clock is outside the supported dates")]
    Clock(#[from] time::error::ComponentRange),
}
