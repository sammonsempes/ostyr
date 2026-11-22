use crate::types::{AttachFn, CleanupFn, ClockFn, DialFn, SpawnFn};
use agent_channel::model::ShellClientEnd;
use agent_channel::types::ShellReader;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Mutex;
use tokio::sync::mpsc;


/// Live window of the one-use store: an id is refused when this many unexpired ids are already recorded.
pub const MAX_SHELL_SESSION_IDS: usize = 256;


/// Upper bound of the store file: `MAX_SHELL_SESSION_IDS` lines of an id (128 bytes), a space, a decimal `u64` and a newline, with room to spare.
pub const MAX_STORE_BYTES: u64 = 40_960;


pub const STORE_FILE_NAME: &str = "shell-sessions";


pub const ROOT_UID: u32 = 0;


/// Fixed terminal size of the session until agent-channel gains a resize hook.
pub const SHELL_COLUMNS: u32 = 80;


pub const SHELL_ROWS: u32 = 24;


/// Queue of verified `OpenShell` commands: one, the busy slot refuses the second one by name.
pub const SHELL_QUEUE_CAPACITY: usize = 1;


/// Chunks of terminal input waiting between the attach writer and the shell input.
pub const SHELL_INPUT_CHUNKS: usize = 16;


/// After the shell exits, the output is given this long to reach the platform.
pub const SHELL_EXIT_FLUSH_SECONDS: u64 = 5;


pub const BANNER_TITLE: &str = "OSTYR REMOTE SHELL SESSION";


/// A signed `OpenShell` command that passed every grammar again; only `TryFrom<Command>` builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOpenShell {
    pub session_id: String,
    pub asset: String,
    pub ticket: String,
    pub requester: String,
    pub approvers: Vec<String>,
    pub max_seconds: u32,
    pub idle_seconds: u32,
    pub expires_at: u64,
    sealed: Sealed,
}


/// Keeps `VerifiedOpenShell` constructible only inside this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sealed;


/// One recorded session id and the time after which a replay is refused by expiry alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreEntry {
    pub session_id: String,
    pub expires_at: u64,
}


/// How a session ended; the text of a peer never appears in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    MaxSeconds,
    Idle,
    Attached(ShellClientEnd),
    AttachFailed,
    ShellExited,
    ShellGone,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellOutcome {
    pub session_id: String,
    pub reason: EndReason,
    pub cleanup_clean: bool,
}


/// What the spawner hands back: the shell output, a bounded input queue and the future of its exit.
pub struct PtyHandle {
    pub output: ShellReader,
    pub input: mpsc::Sender<Vec<u8>>,
    pub exit: Pin<Box<dyn Future<Output = ()> + Send>>,
}


/// Everything a session needs from the outside; `store_lock` is held across the check and the record of the one-use store.
pub struct ShellEnv<'env> {
    pub agent_id: String,
    pub store_directory: PathBuf,
    pub store_owner: u32,
    pub store_lock: Mutex<()>,
    pub clock: &'env ClockFn,
    pub dial: &'env DialFn,
    pub spawn: &'env SpawnFn,
    pub attach: &'env AttachFn,
    pub cleanup: &'env CleanupFn,
}


pub(crate) fn verified_open_shell(fields: (String, String, String, String, Vec<String>), limits: (u32, u32), expires_at: u64) -> VerifiedOpenShell {
    let (session_id, asset, ticket, requester, approvers) = fields;
    let (max_seconds, idle_seconds) = limits;
    VerifiedOpenShell {
        session_id,
        asset,
        ticket,
        requester,
        approvers,
        max_seconds,
        idle_seconds,
        expires_at,
        sealed: Sealed,
    }
}
