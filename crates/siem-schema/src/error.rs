use thiserror::Error;


#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchemaError {
    #[error("invalid identifier {0:?}: only a-z, 0-9, `_`, `.` and `@` are allowed")]
    InvalidIdentifier(String),
    #[error("retention of {0} days is outside 1..={1}")]
    InvalidDays(u32, u32),
    #[error("retention of {coarse} ({coarse_days} days) is shorter than {fine} ({fine_days} days)")]
    RetentionOrder {
        fine: String,
        fine_days: u32,
        coarse: String,
        coarse_days: u32,
    },
    #[error("raw metrics retention of {0} days exceeds {1}")]
    RawRetentionTooLong(u32, u32),
    #[error("no metrics table covers a range of {0} s at a step of {1} s")]
    NoMetricsTable(u64, u64),
    #[error("{0} tiers exceed the limit of {1}")]
    TooManyTiers(usize, usize),
    #[error("required column {0} is missing")]
    MissingColumn(String),
    #[error("column {0} is listed twice")]
    DuplicateColumn(String),
    #[error("column {0} cannot be removed")]
    RemovedColumn(String),
    #[error("column {0} cannot change type")]
    ChangedColumn(String),
}
