use std::io;
use std::str::Utf8Error;
use thiserror::Error;


#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("the global rate must be above zero")]
    ZeroRate,
    #[error("the global burst must be above zero")]
    ZeroBurst,
    #[error("the per-source share must be between 1 and 99 percent")]
    BadShare,
    #[error("the undeclared sources share must be between 1 and 50 percent")]
    BadUnknownShare,
    #[error("a share of the global burst is smaller than one message")]
    ShareBelowOneMessage,
    #[error("the number of tracked sources must be above zero")]
    ZeroMaxSources,
}


#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("the message is not valid UTF-8")]
    NotUtf8(#[from] Utf8Error),
    #[error("the message is neither RFC 5424 nor RFC 3164")]
    Malformed,
    #[error("the message carries no priority")]
    MissingPriority,
    #[error("the {0} field is too long")]
    FieldTooLong(&'static str),
    #[error("the structured data exceeds its bounds")]
    TooMuchStructuredData,
}


#[derive(Debug, Error)]
pub enum SpoolError {
    #[error("spool input/output failure")]
    Io(#[from] io::Error),
    #[error("the spool path is not a directory")]
    NotDirectory,
    #[error("the spool directory is not owned by the collector user")]
    WrongOwner,
    #[error("the spool directory is writable by others")]
    WritableByOthers,
    #[error("the segment size must hold one frame and the total size two segments")]
    BadSizes,
    #[error("the payload exceeds the record bound")]
    PayloadTooLarge,
    #[error("the spool directory holds too many segment files")]
    TooManySegments,
    #[error("the spool directory holds too many entries")]
    TooManyEntries,
    #[error("the spool needs a Unix host: the collector role is Linux-only")]
    Unsupported,
    #[error("a segment changed on disk: frame {0} is unreadable")]
    Corrupt(u64),
}
