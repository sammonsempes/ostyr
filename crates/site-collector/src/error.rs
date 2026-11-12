use std::io;
use std::num::ParseIntError;
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
    #[error("the trap varbind cap must be between 1 and its ceiling")]
    BadMaxVarbinds,
    #[error("the trap value length cap must be between 1 and its ceiling")]
    BadMaxValueChars,
    #[error("the flow record cap must be between 1 and its ceiling")]
    BadMaxFlowRecords,
    #[error("a flow template cap must be between 1 and its ceiling")]
    BadFlowTemplateLimit,
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


#[derive(Debug, Error)]
pub enum ListenError {
    #[error("the listen address is not a socket address")]
    BadAddress(#[source] std::net::AddrParseError),
    #[error("cannot bind the listening socket")]
    Bind(#[source] io::Error),
    #[error("the tenant must hold between 1 and 128 bytes")]
    BadTenant,
    #[error("the forward batch must hold between 1 and 1000 records")]
    BadForwardBatch,
    #[error("the listener kind cannot change on reload: restart the collector")]
    KindChanged,
    #[error("the admission limits are invalid")]
    Limits(#[from] ConfigError),
    #[error("the settings file cannot be loaded")]
    Settings(#[from] core_config::error::ConfigError),
}


#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("spool failure")]
    Spool(#[from] SpoolError),
    #[error("forward input/output failure")]
    Io(#[from] io::Error),
    #[error("the forward cursor file is not a sequence number")]
    BadCursor(#[from] ParseIntError),
    #[error("a spooled record cannot be parsed")]
    Parse(#[from] ParseError),
    #[error("an event cannot be encoded")]
    Encode(#[from] core_export::error::ExportError),
    #[error("a spooled flow frame cannot be decoded")]
    Frame(#[from] FlowFrameError),
}


#[derive(Debug, Error)]
pub enum FlowFrameError {
    #[error("the flow frame is {0} bytes, over the record bound")]
    TooLarge(usize),
    #[error("the flow frame is not a strict flow record")]
    Json(#[from] serde_json::Error),
    #[error("the flow frame has no integer version")]
    MissingVersion,
    #[error("the flow frame has version {0}, not a known one")]
    UnknownVersion(u64),
    #[error("the flow frame has no exporter")]
    MissingExporter,
}


#[derive(Debug, Error)]
pub enum FlowStoreError {
    #[error("a flow record cannot be encoded")]
    Encode(#[from] serde_json::Error),
    #[error("a flow record cannot be appended to the spool")]
    Spool(#[from] SpoolError),
}
