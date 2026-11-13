use thiserror::Error;


#[derive(Debug, Error)]
pub enum StatsError {
    #[error("too many rows: {count} over the limit of {max}")]
    TooManyRows { count: usize, max: usize },
    #[error("the interval between two timestamps does not fit a 64-bit integer")]
    IntervalOverflow,
    #[error("input is larger than {max} bytes")]
    InputTooLarge { max: u64 },
    #[error("line {line} is not of the form entity,key")]
    BadLine { line: usize },
    #[error("line {line} is not a timestamp")]
    BadTimestamp {
        line: usize,
        #[source]
        source: std::num::ParseIntError,
    },
    #[error("cannot read or write")]
    Io(#[from] std::io::Error),
}
