use thiserror::Error;
use x509_parser::error::{PEMError, X509Error};


#[derive(Debug, Error)]
pub enum CertError {
    #[error("input is {size} bytes, above the {max} byte limit")]
    InputTooLarge { size: usize, max: usize },
    #[error("input holds more than {max} PEM blocks")]
    TooManyBlocks { max: usize },
    #[error("input holds more than {max} certificates")]
    TooManyCertificates { max: usize },
    #[error("invalid PEM block: {0}")]
    Pem(#[source] PEMError),
    #[error("invalid certificate: {0}")]
    Certificate(#[source] x509_parser::nom::Err<X509Error>),
    #[error("invalid certificate extension: {0}")]
    Extension(#[source] X509Error),
}


/// No variant carries input bytes: the serde_json message is replaced by its position and category.
#[derive(Debug, Error)]
pub enum CtError {
    #[error("get-entries response is {size} bytes, above the {max} byte limit")]
    JsonTooLarge { size: usize, max: usize },
    #[error("get-entries response holds more than {max} entries")]
    TooManyEntries { max: usize },
    #[error("invalid get-entries JSON ({category:?}) at line {line} column {column}")]
    Json {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
}


#[derive(Debug, Error)]
pub enum ScanError {
    #[error("{name} must be at least 1")]
    Zero { name: &'static str },
    #[error("{name} is {value}, above the {max} ceiling")]
    AboveCeiling { name: &'static str, value: u64, max: u64 },
    #[error("an extension is 1 to {max} bytes without a dot or a path separator")]
    BadExtension { max: usize },
}
