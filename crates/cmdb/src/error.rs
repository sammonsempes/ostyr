use thiserror::Error;


#[derive(Debug, Error, PartialEq, Eq)]
pub enum CmdbError {
    #[error("observation from `{source_name}` carries no identity key")]
    NoIdentity { source_name: String },
}


#[derive(Debug, Error)]
pub enum ImportError {
    #[error("cannot read the import file: {0}")]
    Io(#[from] std::io::Error),
    #[error("import file exceeds {limit} bytes")]
    TooLarge { limit: u64 },
    #[error("import file exceeds {limit} rows")]
    TooManyRows { limit: usize },
    #[error("import file is not valid UTF-8: {0}")]
    NotUtf8(#[from] std::string::FromUtf8Error),
    #[error("import file header cannot be read: {0}")]
    Header(#[source] csv::Error),
    #[error("mapped column `{column}` is missing from the import file")]
    MissingColumn { column: String },
}


#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Pg(#[from] core_pg::error::PgError),
    #[error("reconciliation: {0}")]
    Cmdb(#[from] CmdbError),
    #[error("table `{table}` holds more than {limit} rows for this tenant")]
    TooManyRows { table: &'static str, limit: usize },
    #[error("table `{table}` returned a malformed row")]
    BadRow { table: &'static str },
    #[error("table `{table}` returned an unknown value")]
    BadValue {
        table: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("an asset version is not a number")]
    BadVersion(#[source] std::num::ParseIntError),
    #[error("an asset changed since it was read")]
    VersionConflict,
    #[error("still conflicting after {attempts} attempts")]
    RetriesExhausted { attempts: usize },
}
