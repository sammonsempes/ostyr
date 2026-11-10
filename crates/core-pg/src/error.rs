use rustls_pki_types::pem;
use std::io;
use thiserror::Error;


/// No variant carries server text, a password or a query parameter.
#[derive(Debug, Error)]
pub enum PgError {
    #[error("{file}: cannot read: {source}")]
    Io {
        file: String,
        #[source]
        source: io::Error,
    },
    #[error("{file}: not a regular file")]
    NotRegular { file: String },
    #[error("{file}: larger than {limit} bytes")]
    TooLarge { file: String, limit: u64 },
    #[error("{file}: the password is empty")]
    EmptyPassword { file: String },
    #[error("{file}: no certificate found")]
    NoCertificate { file: String },
    #[error("{file}: invalid PEM: {source}")]
    Pem {
        file: String,
        #[source]
        source: pem::Error,
    },
    #[error("tls configuration: {0}")]
    Tls(#[from] rustls::Error),
    #[error("connect deadline of {seconds} s exceeded")]
    ConnectTimeout { seconds: u64 },
    #[error("statement deadline of {seconds} s exceeded")]
    StatementTimeout { seconds: u64 },
    #[error("server error {code}: {class}")]
    Server { code: String, class: &'static str },
    #[error("database client error")]
    Client(#[source] tokio_postgres::Error),
    #[error("invalid tenant scope: expected 1 to 64 characters of [A-Za-z0-9_.-] starting with a letter or digit")]
    InvalidTenant,
    #[error("invalid migration version `{version}`: expected 1 to 64 characters of [0-9a-z_]")]
    InvalidVersion { version: String },
    #[error("migration `{version}` is not after `{previous}`: versions must be strictly ascending")]
    MigrationOrder { version: String, previous: String },
    #[error("invalid migration namespace `{namespace}`: expected 1 to 32 characters of [a-z0-9_] starting with a letter")]
    InvalidNamespace { namespace: String },
    #[error("schema_migrations has no namespace column: run adopt_legacy once with the namespace that owns its records")]
    LegacyRecords,
    #[error("migration `{version}` was applied with a different digest")]
    DigestMismatch { version: String },
    #[error("migration `{version}` is recorded as applied but unknown to this build")]
    UnknownApplied { version: String },
    #[error("migration `{version}` is older than an applied migration")]
    OutOfOrder { version: String },
}


pub const CLASS_CHARACTERS: usize = 2;


pub const SQLSTATE_CHARACTERS: usize = 5;


pub const INVALID_SQLSTATE: &str = "invalid";


/// A server-supplied code is kept only when it is five characters of `[0-9A-Z]`.
pub fn checked_sqlstate(code: &str) -> String {
    if code.len() == SQLSTATE_CHARACTERS && code.bytes().all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase()) {
        code.to_owned()
    } else {
        INVALID_SQLSTATE.to_owned()
    }
}


/// A fixed class for the first two characters of a SQLSTATE code.
pub fn sqlstate_class(code: &str) -> &'static str {
    match code.get(..CLASS_CHARACTERS) {
        Some("08") => "connection exception",
        Some("23") => "integrity constraint violation",
        Some("28") => "invalid authorization",
        Some("40") => "transaction rollback",
        Some("42") => "syntax error or access rule violation",
        Some("53") => "insufficient resources",
        Some("57") => "operator intervention",
        Some("XX") => "internal error",
        _ => "other",
    }
}


/// The server error is reduced to its SQLSTATE code: its message and detail may hold query parameters.
pub fn reduce(error: tokio_postgres::Error) -> PgError {
    match error.as_db_error() {
        Some(database) => {
            let code = checked_sqlstate(database.code().code());
            PgError::Server {
                class: sqlstate_class(&code),
                code,
            }
        }
        None => PgError::Client(error),
    }
}
