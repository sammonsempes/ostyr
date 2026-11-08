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
