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


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Memory,
    FileSize,
    Archive,
    Disk,
}


#[cfg(unix)]
#[derive(Debug, Error)]
pub enum RunError {
    #[error("syft hit its {kind:?} resource limit")]
    ResourceLimit {
        kind: ResourceKind,
        #[source]
        cause: Option<Box<RunError>>,
    },
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
    #[error("cannot measure the syft home")]
    Walk(#[from] walkdir::Error),
    #[error("syft survived SIGKILL and could not be reaped")]
    Unreaped,
    #[error("a syft helper result was abandoned")]
    Abandoned,
    #[error("a syft helper thread ended without a result")]
    Helper(#[from] std::sync::mpsc::RecvError),
}


#[derive(Debug, Error)]
pub enum StoreError {
    #[error("the {0} name is not usable in an object key")]
    InvalidName(&'static str),
    #[error("the tenant is outside the caller's scope")]
    OutsideScope,
    #[error("the store answered status {0}")]
    Status(u16),
    #[error("the store request failed")]
    Transport(#[source] crate::types::BoxError),
    #[error("the stored document is larger than the limit of {max} bytes")]
    TooLarge { max: usize },
    #[error("the stored signature object is malformed")]
    BadSignatureObject,
    #[error("the stored signature object is not text")]
    SignatureText(#[source] std::str::Utf8Error),
    #[error("the stored signature is not hexadecimal")]
    SignatureHex(#[source] data_encoding::DecodeError),
    #[error("store setting `{0}` is invalid")]
    Settings(&'static str),
    #[error("the bucket cannot be built")]
    Bucket(#[from] rusty_s3::BucketError),
    #[error("a credential file is empty or holds a control character")]
    BadCredential,
    #[error("the CA file is larger than the limit")]
    CaTooLarge,
    #[error("the CA certificate is invalid")]
    Certificate(#[source] ureq::Error),
    #[error("cannot read a store file")]
    File(#[from] std::io::Error),
    #[error(transparent)]
    Signing(#[from] SigningError),
}


#[derive(Debug, Error)]
pub enum SigningError {
    #[error("the document is larger than the limit of {max} bytes")]
    TooLarge { max: usize },
    #[error("the signer failed")]
    Signer(#[source] crate::types::BoxError),
    #[error("unknown signing key")]
    UnknownKey,
    #[error("signing key is revoked")]
    KeyRevoked,
    #[error("signing key is outside its validity period")]
    KeyOutsideValidity,
    #[error("bad signature")]
    BadSignature,
    #[error("version {next} is not greater than {previous}")]
    VersionNotIncreasing { previous: u64, next: u64 },
    #[error("cannot read the key file")]
    KeyIo(#[from] std::io::Error),
    #[error("the key file is not private")]
    KeyNotPrivate(#[from] core_audit::error::AuditError),
    #[error("the key file is larger than the limit")]
    KeyTooLarge,
    #[error("the key path is not a regular file")]
    KeyNotRegular,
    #[error("the key file belongs to another user")]
    KeyWrongOwner,
    #[error("the key file is not hexadecimal")]
    KeyHex(#[from] data_encoding::DecodeError),
    #[error("key files are supported on unix only")]
    KeyUnsupported,
    #[error("the key file must hold exactly 32 bytes in hexadecimal")]
    KeyLength,
    #[error("the key seed is not 32 bytes")]
    KeySeed(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    Sbom(#[from] SbomError),
    #[error(transparent)]
    Diff(#[from] DiffError),
}
