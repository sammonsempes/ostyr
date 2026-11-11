use thiserror::Error;


#[derive(Debug, Error, PartialEq, Eq)]
pub enum CmdbError {
    #[error("observation from `{source_name}` carries no identity key")]
    NoIdentity { source_name: String },
    #[error("derived asset id `{id}` belongs to an existing asset that does not own that key")]
    IdCollision { id: String },
    #[error("observation field `{field}` uses a reserved name")]
    ReservedName { field: &'static str },
    #[error("observation field `{field}` is longer than {limit} bytes")]
    FieldTooLong { field: &'static str, limit: usize },
    #[error("observation field `{field}` holds a control or invisible character")]
    ControlCharacter { field: &'static str },
    #[error("observation carries more than {limit} attributes")]
    TooManyAttributes { limit: usize },
}


#[derive(Debug, Error)]
pub enum CmdbConfigError {
    #[error("{0}")]
    Load(#[from] core_config::error::ConfigError),
    #[error("{file}: declared asset {index}: {source}")]
    Declared {
        file: String,
        index: usize,
        #[source]
        source: CmdbError,
    },
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
    #[error("import mapping field `{field}` uses a reserved name")]
    ReservedName { field: &'static str },
    #[error("import mapping: {0}")]
    Mapping(#[from] core_config::error::ConfigError),
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
    #[error("page size must be between 1 and the page cap and reach the row caps within the page ceiling")]
    BadLimits,
    #[error("lease: {0}")]
    Lease(#[from] alerts::error::StoreError),
    #[error("page size must be between 1 and {limit}")]
    BadPageSize { limit: usize },
    #[error("cursor is malformed")]
    BadCursor,
    #[error("asset id is empty, too long or holds a NUL character")]
    BadId,
    #[error("column {column} is not a number")]
    BadNumber {
        column: usize,
        #[source]
        source: std::num::ParseIntError,
    },
    #[error("an asset version is not a number")]
    BadVersion(#[source] std::num::ParseIntError),
    #[error("the refused conflict list is malformed")]
    BadRefused(#[source] serde_json::Error),
    #[error("the duplicate conflict list is malformed")]
    BadDuplicates(#[source] serde_json::Error),
    #[error("the outcome carries two conflicts for asset `{asset}`, attribute `{attribute}`, source `{source_name}`")]
    DuplicateConflict { asset: String, attribute: String, source_name: String },
    #[error("an asset changed since it was read")]
    VersionConflict,
    #[error("still conflicting after {attempts} attempts")]
    RetriesExhausted { attempts: usize },
}
