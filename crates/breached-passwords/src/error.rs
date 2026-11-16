use std::io;
use thiserror::Error;


/// Every error names a file or fixed text; only `Unsorted` has an offset, taken from a fixed sample position, never from a hash.
#[derive(Debug, Error)]
pub enum ListError {
    #[error("{file}: cannot open: {source}")]
    Open {
        file: String,
        #[source]
        source: io::Error,
    },
    #[error("{file}: not a regular file")]
    NotRegular { file: String },
    #[error("{file}: list is a symlink")]
    Symlink { file: String },
    #[error("cannot read the list: {source}")]
    Read {
        #[source]
        source: io::Error,
    },
    #[error("malformed line in the list")]
    Malformed,
    #[error("line longer than the cap in the list")]
    LineTooLong,
    #[error("unterminated last line in the list")]
    Unterminated,
    #[error("list is not sorted near byte {offset}")]
    Unsorted { offset: u64 },
    #[error("list changed while open")]
    Changed,
    #[error("list holds no valid line")]
    NoLines,
    #[error("search exceeded the probe limit")]
    ProbeLimit,
}


/// Hash-file errors name a line number only.
#[derive(Debug, Error)]
pub enum HashFileError {
    #[error("cannot read the hash file: {0}")]
    Read(#[source] io::Error),
    #[error("hash file is larger than the cap")]
    TooLarge,
    #[error("hash file holds more lines than the cap")]
    TooMany,
    #[error("line {line} is not an NT hash")]
    Malformed { line: usize },
}
