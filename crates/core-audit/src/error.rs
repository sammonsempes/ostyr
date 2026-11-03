use std::io;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum BrokenReason {
    #[error("line is not terminated by a newline")]
    Unterminated,
    #[error("line is not a valid record: {0}")]
    Malformed(#[source] serde_json::Error),
    #[error("line is not in canonical form")]
    NonCanonical,
    #[error("previous hash does not match the preceding record (record deleted, inserted or reordered)")]
    ChainMismatch,
    #[error("record hash does not match its content (record edited)")]
    HashMismatch,
}


#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("cannot format the timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
    #[error("line {line}: {reason}")]
    Broken {
        line: usize,
        #[source]
        reason: BrokenReason,
    },
    #[error("chain head is {actual}, expected {expected} (log truncated or replaced)")]
    HeadMismatch { expected: String, actual: String },
    #[error("an earlier append failed: the log handle refuses further appends, reopen the log to verify it")]
    LogPoisoned,
    #[error("log file mode is {mode:o}, it must grant no access to group or other")]
    InsecurePermissions { mode: u32 },
    #[error("usage: append <file> <count> | verify <file> [head] | export <file> [head]")]
    Usage,
    #[error("invalid count `{value}`: {source}")]
    InvalidCount {
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },
}
