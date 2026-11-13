use crate::model::ScopeKind;
use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum Refusal {
    #[error("no entry")]
    Empty,
    #[error("{count} entries, at most {max} are allowed")]
    TooMany { count: usize, max: usize },
    #[error("`{shown}` is not an IP address or range (hostnames are not supported yet)")]
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
