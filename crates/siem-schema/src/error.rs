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
    #[error("trace retention of {0} days is outside 1..={1}")]
    InvalidTraceDays(u32, u32),
    #[error("no metrics table covers a range of {0} s at a step of {1} s")]
    NoMetricsTable(u64, u64),
    #[error("move after {0} days is not before the retention of {1} days")]
    MoveNotBeforeRetention(u32, u32),
    #[error("a move to the cold tier needs a cold volume name")]
    MissingColdVolume,
    #[error("the cold tier move cannot be removed")]
    RemovedMove,
    #[error("the storage policy cannot change on an existing table")]
    ChangedStoragePolicy,
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
