use core_config::error::ConfigError;
use core_config::secret_file::SecretFileError;
use std::io;
use thiserror::Error;


/// No variant carries file bytes: only fixed text, package-relative file names (bounded) and a trusted key id.
#[derive(Debug, Error)]
pub enum ConnectorError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: {message}")]
    Document { file: String, message: String },
    #[error(transparent)]
    SecretFile(#[from] SecretFileError),
    #[error("output: {0}")]
    Output(#[from] io::Error),
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("{path}: symbolic link")]
    Symlink { path: String },
    #[error("{path}: not a regular file")]
    NotRegular { path: String },
    #[error("{path}: file was replaced while it was opened")]
    Swapped { path: String },
    #[error("{path}: file has more than one hard link")]
    HardLinked { path: String },
    #[error("{path}: file is larger than {max} bytes")]
    FileTooLarge { path: String, max: u64 },
    #[error("more than {max} files in the package")]
    TooManyFiles { max: usize },
    #[error("package is larger than {max} bytes")]
    PackageTooLarge { max: u64 },
    #[error("{name}: file name is not allowed")]
    BadFileName { name: String },
    #[error("the package has no connector.yaml")]
    MissingManifest,
    #[error("the package has no connector.sig")]
    MissingSignature,
    #[error("connector.sig is malformed")]
    MalformedSignature,
    #[error("signing key `{key_id}` is not trusted")]
    UnknownKey { key_id: String },
    #[error("signing key `{key_id}` has expired")]
    KeyExpired { key_id: String },
    #[error("the signature does not verify")]
    BadSignature,
    #[error("{path}: file added after signing")]
    FileAdded { path: String },
    #[error("{path}: file changed after signing")]
    FileChanged { path: String },
    #[error("{path}: file removed after signing")]
    FileRemoved { path: String },
    #[error("the manifest publisher is not the publisher of the signing key")]
    WrongPublisher,
    #[error("the manifest is larger than {max} bytes")]
    ManifestTooLarge { max: usize },
    #[error("invalid `{field}`")]
    Invalid { field: &'static str },
    #[error("reading a package directory is not supported on this platform")]
    Unsupported,
    #[error("the system clock is before the Unix epoch")]
    Clock,
    #[error("the OpenAPI document is not valid ({category}) at line {line} column {column}")]
    OpenApi { category: String, line: usize, column: usize },
    #[error("the OpenAPI document exceeds the bound on {bound} ({max})")]
    OpenApiBound { bound: &'static str, max: usize },
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    WorkDir(#[from] core_config::trusted_dir::TrustedDirError),
    #[error("usage: {0}")]
    Usage(&'static str),
}
