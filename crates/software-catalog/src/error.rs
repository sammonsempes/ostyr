//! Errors; none quotes text taken from a document.

use thiserror::Error;


#[derive(Debug, Error)]
pub enum CatalogueError {
    #[error("reading the file failed")]
    Read(#[from] std::io::Error),
    #[error("file is not UTF-8")]
    NotUtf8,
    #[error("file is larger than {limit} bytes")]
    TooLarge { limit: usize },
    #[error("invalid document")]
    Parse(#[from] core_config::error::ConfigError),
    #[error("more than {limit} entries")]
    TooManyEntries { limit: usize },
    #[error("entry {index}: invalid field `{field}`")]
    InvalidEntry { index: usize, field: &'static str },
    #[error("duplicate entry name `{name}`")]
    DuplicateName { name: String },
}


#[derive(Debug, Error)]
pub enum PlanError {
    #[error("assignment names more than {limit} entries")]
    TooManyNames { limit: usize },
    #[error("assignment holds an invalid entry name")]
    InvalidName,
    #[error("assignment names unknown catalogue entry `{name}`")]
    UnknownEntry { name: String },
    #[error("assignment both installs and removes `{name}`")]
    Conflict { name: String },
}


#[derive(Debug, Error)]
pub enum InstalledError {
    #[error("reading the inventory failed")]
    Read(#[from] std::io::Error),
    #[error("inventory is larger than {limit} bytes")]
    TooLarge { limit: usize },
}
