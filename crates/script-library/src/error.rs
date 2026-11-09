use core_config::error::ConfigError;
use std::io;
use thiserror::Error;


/// Values never appear in a message: a parameter may carry a secret.
#[derive(Debug, Error)]
pub enum ScriptError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("manifest exceeds {max} bytes")]
    ManifestTooLarge { max: usize },
    #[error("invalid manifest field `{field}`")]
    InvalidManifest { field: String },
    #[error("invalid parameter pattern: {0}")]
    Pattern(#[source] regex::Error),
    #[error("missing parameter `{0}`")]
    MissingParameter(String),
    #[error("unknown parameter")]
    UnknownParameter,
    #[error("parameter `{0}` has the wrong type")]
    WrongType(String),
    #[error("parameter `{0}` is too short")]
    TooShort(String),
    #[error("parameter `{0}` is too long")]
    TooLong(String),
    #[error("parameter `{0}` contains a NUL byte")]
    NulByte(String),
    #[error("parameter `{0}` does not match its pattern")]
    PatternMismatch(String),
    #[error("parameter `{0}` is out of range")]
    OutOfRange(String),
    #[error("parameter `{0}` is not one of the allowed values")]
    NotAllowed(String),
    #[error("parameter `{0}` is not a plain absolute path")]
    MalformedPath(String),
    #[error("parameter `{0}` is outside the allowed prefixes")]
    PathOutsidePrefixes(String),
    #[error("script digest does not match the manifest")]
    DigestMismatch,
    #[error("manifest `{0}` is not a regular file")]
    NotRegularFile(String),
    #[error("parameter `{name}` does not resolve to an existing path")]
    PathUnresolved {
        name: String,
        #[source]
        source: io::Error,
    },
    #[error("the work root is not a directory owned by the agent user, closed to others, below directories closed to others")]
    UnsafeWorkRoot,
    #[error("the cgroup root is not on a cgroup v2 filesystem")]
    NotCgroupV2,
    #[error("the run-as uid must be neither root nor the agent's own uid")]
    InvalidRunAs,
    #[error("none of the declared interpreter paths exists")]
    NoInterpreter,
    #[error("{context}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
}


#[cfg(unix)]
impl From<rustix::io::Errno> for ScriptError {
    fn from(errno: rustix::io::Errno) -> Self {
        Self::Io {
            context: "cannot kill the script process group",
            source: errno.into(),
        }
    }
}


#[cfg(unix)]
impl From<std::sync::mpsc::RecvTimeoutError> for ScriptError {
    fn from(error: std::sync::mpsc::RecvTimeoutError) -> Self {
        let context = match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => "the output is still held open after the process group was killed",
            std::sync::mpsc::RecvTimeoutError::Disconnected => "the output reader stopped without a result",
        };
        Self::Io {
            context,
            source: io::Error::other(error),
        }
    }
}
