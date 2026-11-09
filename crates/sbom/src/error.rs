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


#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("syft setting `{0}` is invalid")]
    Invalid(&'static str),
}


#[derive(Debug, Error)]
pub enum TargetError {
    #[error("the target path is not valid UTF-8")]
    NotUtf8,
    #[error("the target path holds a control character")]
    Control,
    #[error("the target path starts with `-`")]
    LeadingDash,
    #[error("the target path is not absolute")]
    Relative,
}


#[cfg(unix)]
#[derive(Debug, Error)]
pub enum RunError {
    #[error(transparent)]
    Settings(#[from] SettingsError),
    #[error(transparent)]
    Target(#[from] TargetError),
    #[error("the syft binary is not a regular file")]
    NotRegular,
    #[error("syft exceeded its deadline and was killed")]
    TimedOut,
    #[error("syft exited with {code:?}")]
    Failed {
        code: Option<i32>,
        #[source]
        source: Option<SbomError>,
    },
    #[error("too many syft helper threads are still stuck from earlier runs")]
    Busy,
    #[error("the syft output is not a usable SBOM")]
    Sbom(#[from] SbomError),
    #[error("i/o failure while running syft")]
    Io(#[from] std::io::Error),
    #[error("cannot signal the syft process group")]
    Signal(#[from] rustix::io::Errno),
    #[error("a syft helper thread ended without a result")]
    Helper(#[from] std::sync::mpsc::RecvError),
}
