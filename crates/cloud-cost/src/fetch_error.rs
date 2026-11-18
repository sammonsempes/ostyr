use core_config::secret_file::SecretFileError;
use siem_ingest::error::InsertClass;
use std::io::ErrorKind;
use thiserror::Error;


/// What a failed request is reduced to: no URL, no peer text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpClass {
    Timeout,
    Io(ErrorKind),
    Ca,
    Other,
}


#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("http transport failed: {0:?}")]
pub struct HttpFailure(pub HttpClass);


/// The failure of one body fetch, before it becomes a source failure or an object refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFailure {
    Transport(HttpClass),
    Status(u16),
}


/// Why one source could not be fetched this round; no variant carries text from the peer.
#[derive(Debug, Error)]
pub enum FetchError {
    #[error("source settings refused: {0}")]
    Settings(&'static str),
    #[error("credentials file refused")]
    Credentials(#[source] SecretFileError),
    #[error("credentials file unreadable ({0:?})")]
    CredentialsRead(ErrorKind),
    #[error("credentials file must hold an access key line and a secret key line")]
    BadCredentials,
    #[error("endpoint or bucket refused")]
    Bucket,
    #[error("transport failed: {0:?}")]
    Transport(HttpClass),
    #[error("the server answered status {0}")]
    Status(u16),
    #[error("listing page larger than the cap")]
    ListTooLarge,
    #[error("listing page holds more keys than a page can")]
    ListTooManyKeys,
    #[error("listing page is not a valid answer")]
    ListMalformed,
    #[error("the ledger could not be read or written")]
    Ledger,
}


/// Why one object was refused alone; the rest of the round goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    TooLarge,
    BadGzip,
    Unreadable,
    NoCoveredDay,
    TooManyAccounts,
    AccountTooLong,
    Status(u16),
    Transport(HttpClass),
    Load(Option<InsertClass>),
    Ledger,
}


impl From<BodyFailure> for FetchError {
    fn from(failure: BodyFailure) -> Self {
        match failure {
            BodyFailure::Transport(class) => Self::Transport(class),
            BodyFailure::Status(status) => Self::Status(status),
        }
    }
}


impl From<BodyFailure> for Refusal {
    fn from(failure: BodyFailure) -> Self {
        match failure {
            BodyFailure::Transport(class) => Self::Transport(class),
            BodyFailure::Status(status) => Self::Status(status),
        }
    }
}


/// The ledger executor failed; its text is never kept.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("the ledger statement failed")]
pub struct LedgerFailure;
