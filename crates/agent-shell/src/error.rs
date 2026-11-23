use agent_channel::error::ChannelError;
use agent_command::error::ActionError;
use core_audit::error::AuditError;
use std::io;
use std::path::PathBuf;
use thiserror::Error;


/// Every text is fixed: no command field, no peer text.
#[derive(Debug, Error)]
pub enum ShellError {
    #[error("the command is not an open-shell command")]
    NotOpenShell,
    #[error("the open-shell command is invalid")]
    Invalid(#[source] ActionError),
    #[error("the open-shell command is not signed by a sensitive key")]
    NotSensitive,
    #[error("the open-shell command lifetime is invalid")]
    Lifetime,
    #[error("the open-shell command expired before the start")]
    Expired,
    #[error("a shell session is already open or queued")]
    Busy,
    #[error("the shell queue is closed")]
    QueueClosed,
    #[error("the shell cleanup failed")]
    Cleanup(#[source] io::Error),
    #[error("{0} process(es) of an earlier session are left behind")]
    Leftover(usize),
    #[error("the session id store refused the session")]
    Store(#[from] StoreError),
    #[error("the platform could not be reached")]
    Dial(#[source] ChannelError),
    #[error("the shell could not be started")]
    Spawn(#[source] io::Error),
}


#[derive(Debug, Error)]
pub enum StoreError {
    #[error("{path}: cannot be read or written")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{path}: not a regular file")]
    NotRegular { path: PathBuf },
    #[error("{path}: not a directory")]
    NotDirectory { path: PathBuf },
    #[error("{path}: not owned by the expected user")]
    Owner { path: PathBuf },
    #[error("{path}: grants access to group or other")]
    Insecure {
        path: PathBuf,
        #[source]
        source: AuditError,
    },
    #[error("{path}: larger than the store limit")]
    TooLarge { path: PathBuf },
    #[error("{path}: a line is not a session id and an expiry")]
    Corrupt { path: PathBuf },
    #[error("the session id was already used")]
    Replayed,
    #[error("the store holds the maximum of live session ids")]
    Full,
}


/// The account the shell runs as, refused by name; no peer text.
#[derive(Debug, Error)]
pub enum AccountError {
    #[error("the shell account lookup failed")]
    Lookup(#[source] io::Error),
    #[error("the shell account {name} does not exist")]
    Missing { name: String },
    #[error("the shell account {name} has uid 0 or gid 0")]
    Privileged { name: String },
    #[error("the group database cannot be read")]
    GroupsUnreadable(#[source] io::Error),
    #[error("the shell account {name} is listed in a group")]
    SupplementaryGroups { name: String },
    #[error("the primary group database cannot be read")]
    PrimaryGroupUnreadable(#[source] io::Error),
    #[error("the primary group of the shell account {name} is not its own dedicated group")]
    SharedPrimaryGroup { name: String },
    #[error("the home of the shell account {name} cannot be read")]
    HomeUnreadable {
        name: String,
        #[source]
        source: io::Error,
    },
    #[error("the home of the shell account {name} is not a directory owned by the account")]
    HomeInvalid { name: String },
}
