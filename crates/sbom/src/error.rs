//! Error types.

use struson::reader::ReaderError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum SbomError {
    #[error("document exceeds the limit of {max} bytes")]
    TooLarge { max: usize },
    #[error("more than {max} components")]
    TooMany { max: usize },
    #[error("components nested deeper than {max}")]
    TooDeep { max: usize },
    #[error("a member name is longer than {max} bytes")]
    NameTooLong { max: usize },
    #[error("cannot read the document")]
    Read(#[from] std::io::Error),
    #[error("invalid CycloneDX JSON")]
    Json(#[from] ReaderError),
}


#[derive(Debug, Error)]
pub enum DiffError {
    #[error("the SBOMs belong to different tenants")]
    TenantMismatch,
    #[error("the SBOMs describe different artefacts")]
    ArtefactMismatch,
}
