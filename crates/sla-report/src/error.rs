use thiserror::Error;


#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SlaError {
    #[error("too many check results: {count} over the limit of {max}")]
    TooManyResults { count: usize, max: usize },
    #[error("too many incidents: {count} over the limit of {max}")]
    TooManyIncidents { count: usize, max: usize },
    #[error("too many maintenance windows: {count} over the limit of {max}")]
    TooManyWindows { count: usize, max: usize },
    #[error("tenant mismatch: expected {expected}, found {found}")]
    TenantMismatch { expected: String, found: String },
    #[error("objective {objective_ppm} is above 1000000 parts per million")]
    InvalidObjective { objective_ppm: u32 },
    #[error("too many services: {count} over the limit of {max}")]
    TooManyServices { count: usize, max: usize },
    #[error("the total of {field} does not fit a 64-bit integer")]
    TotalOverflow { field: &'static str },
    #[error("period end {end} is not after its start {start}")]
    InvalidPeriod { start: i64, end: i64 },
}


#[derive(Debug, Error)]
pub enum ExportError {
    #[error("cannot write the CSV report")]
    Csv(#[from] csv::Error),
    #[error("cannot write the JSON report")]
    Json(#[from] serde_json::Error),
    #[error("cannot flush the report")]
    Io(#[from] std::io::Error),
}


#[derive(Debug, Error)]
pub enum ScheduleError {
    #[error(transparent)]
    Config(#[from] core_config::error::ConfigError),
    #[error("{file}: larger than {max} bytes")]
    FileTooLarge { file: String, max: u64 },
    #[error("{file}: {count} reports, at most {max} allowed")]
    TooManyReports { file: String, count: usize, max: usize },
    #[error("{file}: report #{index}: invalid `{field}`")]
    Invalid { file: String, index: usize, field: &'static str },
    #[error("{file}: report #{index}: the `pdf` format is not yet supported")]
    PdfNotSupported { file: String, index: usize },
    #[error("{file}: duplicate report id `{id}`")]
    DuplicateId { file: String, id: String },
    #[error("UTC offset of {minutes} minutes is out of range or not a multiple of 15")]
    InvalidOffset { minutes: i32 },
    #[error("grace of {seconds} seconds is out of range")]
    InvalidGrace { seconds: i64 },
    #[error("{requested} periods requested, at most {max} allowed")]
    TooManyPeriods { requested: usize, max: usize },
    #[error("time is outside the RFC 3339 range of years 0 to 9999")]
    OutOfRange,
    #[error("invalid calendar value")]
    Time(#[from] time::error::ComponentRange),
    #[error("cannot format a time")]
    Format(#[from] time::error::Format),
}
