use agent_command::error::SignError;
use agent_command::types::BoxError;
use core_config::secret_file::SecretFileError;
use core_config::trusted_dir::TrustedDirError;
use core_pg::error::PgError;
use rustix::io::Errno;
use std::io;
use thiserror::Error;


/// Why the routine key cannot sign now; fixed texts, no key material.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum KeyRefusal {
    #[error("the key id is not in the keys file")]
    UnknownKey,
    #[error("the keys file lists another public key under the key id")]
    PublicKeyMismatch,
    #[error("the key is not of class routine")]
    WrongClass,
    #[error("the key is not scoped to exactly ping and collect_status")]
    WrongScope,
    #[error("the key is revoked")]
    Revoked,
    #[error("the key is not valid yet")]
    NotYetValid,
    #[error("the key does not stay valid for a whole envelope lifetime")]
    ExpiresTooSoon,
}


/// A seed or key refusal names the setting, never the bytes.
#[derive(Debug, Error)]
pub enum PairError {
    #[error("commands.routine_seed_file cannot be opened")]
    Open(#[source] SecretFileError),
    #[error("commands.routine_seed_file cannot be read")]
    Read(#[source] io::Error),
    #[error("commands.routine_seed_file is not 64 lowercase hex characters and an optional newline")]
    Format,
    #[error("commands.key_id does not name a usable routine key")]
    Key(#[source] KeyRefusal),
}


/// One error for the start checks and for an issue; no variant carries a path, a seed, an envelope or a peer byte.
#[derive(Debug, Error)]
pub enum IssueError {
    #[error("the agent id is refused")]
    InvalidAgent,
    #[error("the signing key is unusable")]
    KeyUnusable(#[source] KeyRefusal),
    #[error("the agent queue is full")]
    QueueFull,
    #[error("the agent queue holds an entry that is not an envelope")]
    QueueInvalid,
    #[error("too many routine commands are unconfirmed for this agent")]
    SequenceGap,
    #[error("the tenant already has the maximum number of agents")]
    AgentLimit,
    #[error("a stored or computed number is out of range")]
    Range,
    #[error("the commands directory is refused: {0}")]
    DirectoryRefused(&'static str),
    #[error("the commands directory is not trusted")]
    Trusted(#[from] TrustedDirError),
    #[error("a file operation failed: {0}")]
    Fs(#[from] Errno),
    #[error("a file write failed: {0}")]
    Io(#[from] io::Error),
    #[error("the database refused: {0}")]
    Pg(#[from] PgError),
    #[error("cannot sign: {0}")]
    Sign(#[from] SignError),
    #[error("cannot draw random bytes: {0}")]
    Random(#[from] getrandom::Error),
    #[error("the publish hook refused")]
    Hook(#[source] BoxError),
}
