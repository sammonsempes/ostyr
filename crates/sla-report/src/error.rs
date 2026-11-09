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
