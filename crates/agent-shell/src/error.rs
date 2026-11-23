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


/// The session cgroup, refused by name; no peer text.
#[cfg(target_os = "linux")]
#[derive(Debug, Error)]
pub enum CgroupError {
    #[error("the own cgroup file cannot be read")]
    Io(#[from] io::Error),
    #[error("a cgroup call failed")]
    Sys(#[from] rustix::io::Errno),
    #[error("a cgroup file is larger than its limit")]
    TooLarge,
    #[error("the own cgroup file is not exactly one cgroup v2 line")]
    SelfCgroupShape,
    #[error("the own cgroup path is outside the allowed grammar")]
    PathRefused,
    #[error("the cgroup root is not a cgroup v2 filesystem")]
    NotCgroup2,
    #[error("the own cgroup has no cgroup.kill file")]
    KillMissing(#[source] rustix::io::Errno),
    #[error("the session id is not valid for a cgroup name")]
    SessionId,
    #[error("the session cgroup already exists")]
    Exists,
    #[error("more session cgroups than the limit")]
    TooManySessions,
    #[error("more processes in a session cgroup than the limit")]
    TooManyProcesses,
    #[error("a cgroup file does not hold the expected text")]
    Malformed,
}


#[cfg(target_os = "linux")]
impl From<CgroupError> for io::Error {
    fn from(error: CgroupError) -> Self {
        io::Error::other(error)
    }
}
