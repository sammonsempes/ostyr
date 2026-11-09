use thiserror::Error;


#[derive(Debug, Error)]
pub enum ReportError {
    #[error("cannot read the report: {0}")]
    Read(#[source] std::io::Error),
    #[error("report is above the {max} byte limit")]
    TooLarge { max: usize },
    #[error("report holds more than {max} findings")]
    TooManyFindings { max: usize },
    #[error("report is not a JSON array (line {line}, column {column})")]
    NotAnArray { line: usize, column: usize },
    #[error("invalid skipped path pattern: {0}")]
    InvalidPattern(#[source] glob::PatternError),
}
