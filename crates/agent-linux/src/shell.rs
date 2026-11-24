use crate::types::InspectFn;
use agent_channel::agent_app::{dialer, AgentFile};
use agent_channel::error::{AppError, ChannelError};
use agent_channel::model::ClientTlsPaths;
use agent_channel::tls::client_config;
use agent_channel::types::DialFn;
use agent_shell::model::ROOT_UID;
use agent_shell::types::EnabledFn;
use std::fs::{File, Metadata};
use std::io::{self, ErrorKind, Read};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};


/// The enable switch of the remote shell, next to the settings file of the agent.
pub const SWITCH_FILE: &str = "shell.yaml";


/// The one-use session store of the shell, inside the state directory of the agent.
pub const STORE_DIRECTORY: &str = "shell";


pub const ENABLED_BYTES: &[u8] = b"enabled: true\n";


pub const DISABLED_BYTES: &[u8] = b"enabled: false\n";


pub const MAX_SWITCH_BYTES: u64 = 32;


const GROUP_OTHER_WRITE: u32 = 0o022;


/// Why the switch file is refused, named in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchCause {
    Unreadable(ErrorKind),
    NotRegular,
    Owner,
    Writable,
    Bytes,
}


/// What one read of the switch file says: an absent file is disabled, a refused one is disabled and named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchState {
    Enabled,
    Disabled,
    Refused(SwitchCause),
}


pub fn switch_path(config: &Path) -> PathBuf {
    config.with_file_name(SWITCH_FILE)
}


pub fn store_path(cursor_file: &Path) -> PathBuf {
    cursor_file.with_file_name(STORE_DIRECTORY)
}


/// The cause a handle is refused for: not a regular file, not owned by `owner`, or writable by group or other.
pub fn fault_of(metadata: &Metadata, owner: u32) -> Option<SwitchCause> {
    if !metadata.is_file() {
        Some(SwitchCause::NotRegular)
    } else if metadata.uid() != owner {
        Some(SwitchCause::Owner)
    } else if metadata.mode() & GROUP_OTHER_WRITE != 0 {
        Some(SwitchCause::Writable)
    } else {
        None
    }
}


/// Exactly the two documented texts count; anything else, a longer file included, is refused.
pub fn judge_bytes(bytes: &[u8]) -> SwitchState {
    if bytes == ENABLED_BYTES {
        SwitchState::Enabled
    } else if bytes == DISABLED_BYTES {
        SwitchState::Disabled
    } else {
        SwitchState::Refused(SwitchCause::Bytes)
    }
}


/// Reads at most `MAX_SWITCH_BYTES` plus one byte, so a larger file is judged on its first bytes and refused.
pub fn read_switch_bytes(reader: &mut dyn Read) -> Result<Vec<u8>, SwitchCause> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_SWITCH_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| SwitchCause::Unreadable(error.kind()))
        .map(|_count| bytes)
}


/// The kind, owner and mode of the opened handle, then its bytes: both come from the one handle.
pub fn judge_handle(file: &mut File, owner: u32, inspect: InspectFn) -> Result<SwitchState, SwitchCause> {
    let metadata = inspect(file).map_err(|error| SwitchCause::Unreadable(error.kind()))?;
    match fault_of(&metadata, owner) {
        Some(cause) => Err(cause),
        None => read_switch_bytes(file).map(|bytes| judge_bytes(&bytes)),
    }
}


/// The switch file is opened without following a link or blocking on a FIFO.
pub fn open_switch(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}


/// One read of the switch: absent is disabled, any other failure is refused by name.
pub fn read_switch_with(path: &Path, owner: u32, inspect: InspectFn) -> SwitchState {
    match open_switch(path) {
        Ok(mut file) => judge_handle(&mut file, owner, inspect).unwrap_or_else(SwitchState::Refused),
        Err(error) if error.kind() == ErrorKind::NotFound => SwitchState::Disabled,
        Err(error) => SwitchState::Refused(SwitchCause::Unreadable(error.kind())),
    }
}


pub fn read_switch(path: &Path, owner: u32) -> SwitchState {
    read_switch_with(path, owner, File::metadata)
}


/// Reads the switch and logs a refusal once per distinct cause (a read that is not refused forgets the last cause); true only when enabled.
pub fn switch_enabled(path: &Path, owner: u32, seen: &Mutex<Option<SwitchCause>>) -> bool {
    let state = read_switch(path, owner);
    let cause = match state {
        SwitchState::Refused(named) => Some(named),
        SwitchState::Enabled | SwitchState::Disabled => None,
    };
    let mut last = seen.lock().unwrap_or_else(PoisonError::into_inner);
    let repeated = *last == cause;
    *last = cause;
    if let (false, Some(named)) = (repeated, cause) {
        tracing::warn!(cause = ?named, "the shell switch file is refused, the remote shell stays disabled");
    }
    state == SwitchState::Enabled
}


/// The production switch: root must own the file, read afresh at every call.
pub fn switch_fn(path: PathBuf) -> Arc<EnabledFn> {
    let seen = Mutex::new(None);
    Arc::new(move || switch_enabled(&path, ROOT_UID, &seen))
}


/// A dial that fails with a fixed error: the shell dial could not be prepared at start.
pub fn broken_dial(agent: &AgentFile) -> Box<DialFn> {
    let path = agent.certificate.clone();
    Box::new(move || {
        let refused = ChannelError::Io {
            path: path.clone(),
            source: io::Error::other("the shell dial was not prepared at start"),
        };
        Box::pin(async move { Err(refused) })
    })
}


pub fn prepared_dial(agent: &AgentFile) -> Result<Box<DialFn>, AppError> {
    let address: SocketAddr = agent.server.parse()?;
    let config = client_config(&ClientTlsPaths {
        certificate: agent.certificate.clone(),
        key: agent.key.clone(),
        platform_ca: agent.platform_ca.clone(),
    })?;
    Ok(dialer(address, config, agent.server_name.clone()))
}


/// The shell dial, built once from the agent file (a rotated certificate needs a restart); a failure is logged and every session is then refused at its dial.
pub fn shell_dial(agent: &AgentFile) -> Box<DialFn> {
    prepared_dial(agent).unwrap_or_else(|error| {
        tracing::warn!(%error, "the shell dial could not be prepared, sessions will be refused");
        broken_dial(agent)
    })
}
