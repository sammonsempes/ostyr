use crate::model::ScopeKind;
use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum Refusal {
    #[error("no entry")]
    Empty,
    #[error("{count} entries, at most {max} are allowed")]
    TooMany { count: usize, max: usize },
    #[error("`{shown}` is not an IP address, a range or a hostname (ASCII letters, digits and hyphens, 2 to 8 labels of at most 63 bytes, 253 bytes in all, last label not all digits)")]
    BadTarget { shown: String },
    #[error("`{shown}` is wider than the limit /{min_prefix}")]
    TooBroad { shown: String, min_prefix: u8 },
    #[error("`{shown}` is not an allowed range of a {kind} scope")]
    WrongClass { shown: String, kind: ScopeKind },
    #[error("the merged ranges cover {count} addresses, above the limit {max}")]
    TooWide { count: u128, max: u128 },
    #[error("`{shown}` is not a port from 1 to 65535 or a range of two of them")]
    BadPort { shown: String },
    #[error("{count} ports, at most {max} are allowed")]
    TooManyPorts { count: u32, max: u32 },
    #[error("{value} is outside {min} to {max}")]
    Outside { value: u32, min: u32, max: u32 },
    #[error("`{shown}` is not an ownership reference of at most {max} bytes of A-Z a-z 0-9 _ . : / -, starting with a letter or digit")]
    BadReference { shown: String, max: usize },
}


#[derive(Debug, Error)]
pub enum ScopeError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: {field}: {refusal}")]
    Refused {
        file: String,
        field: String,
        #[source]
        refusal: Refusal,
    },
}


#[derive(Debug, Error)]
pub enum CommandError {
    #[error("target `{shown}` is not listed in the scope")]
    UnknownTarget { shown: String },
    #[error("argument value `{shown}` is refused")]
    BadValue { shown: String },
    #[error("rate {value} is outside {min} to {max}")]
    BadRate { value: u32, min: u32, max: u32 },
    #[error("target `{shown}` is refused: {source}")]
    BadTarget {
        shown: String,
        #[source]
        source: Refusal,
    },
}


#[derive(Debug, Error)]
pub enum ResultsError {
    #[error("cannot read the scanner output: {0}")]
    Read(#[from] std::io::Error),
}


/// Why one naabu run produced no report; a category only, never scanner output.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScanFailure {
    #[error("the scanner did not finish before the deadline")]
    Timeout,
    #[error("the scanner failed (exit code {code:?})")]
    Failed { code: Option<i32> },
    #[error("the scanner printed more than the output cap")]
    Oversized,
    #[error("the scanner could not be started or waited on")]
    Unavailable,
    #[error("the target was refused before any run")]
    Refused,
}


#[derive(Debug, Error)]
pub enum RunError {
    #[error("the run covers {v4} IPv4 and {v6} IPv6 addresses, above {max_v4} and {max_v6}")]
    TooBroad { v4: u128, v6: u128, max_v4: u128, max_v6: u128 },
}


impl From<ResultsError> for ScanFailure {
    fn from(_error: ResultsError) -> Self {
        ScanFailure::Unavailable
    }
}


#[cfg(unix)]
impl From<net_topology::model::RunFailure> for ScanFailure {
    fn from(failure: net_topology::model::RunFailure) -> Self {
        use net_topology::model::RunFailure;
        match failure {
            RunFailure::TimedOut => ScanFailure::Timeout,
            RunFailure::TooLarge => ScanFailure::Oversized,
            RunFailure::Failed { code, .. } => ScanFailure::Failed { code },
            RunFailure::Refused => ScanFailure::Refused,
            RunFailure::Spawn | RunFailure::Io | RunFailure::Unwaitable => ScanFailure::Unavailable,
        }
    }
}
