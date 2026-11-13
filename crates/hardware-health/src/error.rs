//! Errors that refuse a whole smartctl output.

use thiserror::Error;


#[derive(Debug, Error)]
pub enum SmartError {
    #[error("reading the smartctl output failed")]
    Read(#[from] std::io::Error),
    #[error("smartctl output is larger than {limit} bytes")]
    Oversized { limit: u64 },
    #[error("smartctl output is not valid JSON ({category:?}) at line {line} column {column}")]
    Malformed {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    #[error("smartctl output is not a JSON object")]
    NotAnObject,
    #[error("upsc output has more than {limit} lines")]
    TooManyLines { limit: usize },
    #[error("upsc output is not valid UTF-8")]
    NotUtf8(#[from] std::str::Utf8Error),
    #[error("upsc output repeats a variable name")]
    DuplicateKey,
    #[error("thresholds file is larger than {limit} bytes")]
    ThresholdsTooLarge { limit: usize },
    #[error("thresholds file is not valid")]
    Thresholds(#[source] Box<serde_saphyr::Error>),
    #[error("document nesting is deeper than {limit} levels")]
    TooDeep { limit: usize },
    #[error("redfish {document} document refused")]
    Document {
        document: &'static str,
        #[source]
        source: Box<SmartError>,
    },
    #[error("min_battery_charge must be between 1 and 100")]
    ChargeThresholdRange,
}


impl From<serde_json::Error> for SmartError {
    fn from(error: serde_json::Error) -> Self {
        Self::Malformed {
            category: error.classify(),
            line: error.line(),
            column: error.column(),
        }
    }
}
