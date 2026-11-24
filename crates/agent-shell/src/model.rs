use crate::types::{AttachFn, CleanupFn, ClockFn, DialFn, EnabledFn, SpawnFn};
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


/// The one local account the remote shell runs as; a constant, never a setting.
pub const SHELL_ACCOUNT: &str = "ostyr-shell";


/// Fixed terminal size of the session until agent-channel gains a resize hook.
pub const SHELL_COLUMNS: u16 = 80;


pub const SHELL_ROWS: u16 = 24;


/// Queue of verified `OpenShell` commands: one, the busy slot refuses the second one by name.
pub const SHELL_QUEUE_CAPACITY: usize = 1;


/// Bytes of terminal input waiting between the attach writer and the shell input.
pub const SHELL_INPUT_BYTES: usize = 65_536;


/// After the shell exits, the output is given this long to reach the platform.
pub const SHELL_EXIT_FLUSH_SECONDS: u64 = 5;


pub const BANNER_TITLE: &str = "OSTYR REMOTE SHELL SESSION";


#[doc = "A signed `OpenShell` command that passed every grammar again; only `TryFrom<Command>` builds it and its fields are read through accessors.\n\n```compile_fail,E0451\nlet _forged = agent_shell::model::VerifiedOpenShell {\n    session_id: String::new(),\n    asset: String::new(),\n    ticket: String::new(),\n    requester: String::new(),\n    approvers: Vec::new(),\n    max_seconds: 1,\n    idle_seconds: 1,\n    expires_at: 1,\n};\n```\n\n```compile_fail,E0616\nfn forge(order: &mut agent_shell::model::VerifiedOpenShell) {\n    order.session_id = String::from(\"a\\nb\");\n}\n```\n"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOpenShell {
    session_id: String,
    asset: String,
    ticket: String,
    requester: String,
    approvers: Vec<String>,
    max_seconds: u32,
    idle_seconds: u32,
    expires_at: u64,
}


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


/// The outside calls every session of the process shares, as the composer takes them.
pub struct SharedHooks<'env> {
    pub clock: &'env ClockFn,
    pub dial: &'env DialFn,
    pub attach: &'env AttachFn,
    pub enabled: &'env EnabledFn,
}


/// The spawn and cleanup of one session, both built from the one account resolution of that session, with the uid it resolved to.
pub struct SessionHooks {
    pub uid: u32,
    pub running: Box<CleanupFn>,
    pub spawn: Box<SpawnFn>,
    pub cleanup: Box<CleanupFn>,
}


/// What every session of the process shares: the identity, the store, the lock, the clock, the dial, the attach and the enable switch.
pub struct ShellShared<'env> {
    pub agent_id: String,
    pub store_directory: PathBuf,
    pub store_owner: u32,
    pub store_lock: Mutex<()>,
    pub clock: &'env ClockFn,
    pub dial: &'env DialFn,
    pub attach: &'env AttachFn,
    pub enabled: &'env EnabledFn,
}


/// Everything a session needs from the outside; `store_lock` is held across the check and the record of the one-use store.
pub struct ShellEnv<'env> {
    pub agent_id: String,
    pub store_directory: PathBuf,
    pub store_owner: u32,
    pub store_lock: &'env Mutex<()>,
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
    }
}


pub fn session_id_of(order: &VerifiedOpenShell) -> &str {
    &order.session_id
}


pub fn asset_of(order: &VerifiedOpenShell) -> &str {
    &order.asset
}


pub fn ticket_of(order: &VerifiedOpenShell) -> &str {
    &order.ticket
}


pub fn requester_of(order: &VerifiedOpenShell) -> &str {
    &order.requester
}


pub fn approvers_of(order: &VerifiedOpenShell) -> &[String] {
    &order.approvers
}


pub fn max_seconds_of(order: &VerifiedOpenShell) -> u32 {
    order.max_seconds
}


pub fn idle_seconds_of(order: &VerifiedOpenShell) -> u32 {
    order.idle_seconds
}


pub fn expires_at_of(order: &VerifiedOpenShell) -> u64 {
    order.expires_at
}
