use std::io;
use thiserror::Error;


/// Every error names a file or a byte offset, never a line or a hash.
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
    #[error("cannot read the list at byte {offset}: {source}")]
    Read {
        offset: u64,
        #[source]
        source: io::Error,
    },
    #[error("malformed line at byte {offset}")]
    Malformed { offset: u64 },
    #[error("line longer than the cap at byte {offset}")]
    LineTooLong { offset: u64 },
    #[error("unterminated last line at byte {offset}")]
    Unterminated { offset: u64 },
    #[error("list is not sorted near byte {offset}")]
    Unsorted { offset: u64 },
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
