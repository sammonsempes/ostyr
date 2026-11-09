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
    #[error("period end {end} is not after its start {start}")]
    InvalidPeriod { start: i64, end: i64 },
}
