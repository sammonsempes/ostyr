use crate::model::{PtyHandle, VerifiedOpenShell};
use agent_channel::error::ChannelError;
use agent_channel::model::ShellClientEnd;
pub use agent_channel::types::DialFn;
use agent_channel::types::{ShellReader, ShellWriter};
use bytes::Bytes;
use futures_util::Stream;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tonic::transport::Channel;


/// The agent clock in Unix seconds.
pub type ClockFn = dyn Fn() -> u64 + Send + Sync;


pub type SpawnFuture = Pin<Box<dyn Future<Output = io::Result<PtyHandle>> + Send>>;


/// Starts the shell of a verified order on a PTY; the real one runs its blocking work on the blocking pool.
pub type SpawnFn = dyn Fn(&VerifiedOpenShell) -> SpawnFuture + Send + Sync;


pub type CleanupFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;


/// Removes what an earlier session left behind and returns how many processes remain; the real one runs on the blocking pool.
pub type CleanupFn = dyn Fn() -> CleanupFuture + Send + Sync;


/// The terminal input of the platform, as the chunks its writer delivered.
pub type InputChunks = Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>;


pub type AttachFuture = Pin<Box<dyn Future<Output = Result<ShellClientEnd, ChannelError>> + Send>>;


/// Attaches the shell to the platform: the channel, the session id, the shell output and the terminal input writer.
pub type AttachFn = dyn Fn(Channel, String, ShellReader, ShellWriter) -> AttachFuture + Send + Sync;


/// True from the admission of an `OpenShell` until its session has ended and cleaned up: a second one is refused by name.
pub type ShellSlot = Arc<AtomicBool>;


/// Reads the metadata of an opened store handle.
#[cfg(unix)]
pub type InspectFn = fn(&std::fs::File) -> io::Result<std::fs::Metadata>;


/// Looks an account up by name.
#[cfg(unix)]
pub type LookupFn = fn(&str) -> io::Result<Option<crate::account::AccountEntry>>;


/// Reads what a home path is on disk.
#[cfg(unix)]
pub type HomeFn = fn(&std::path::Path) -> io::Result<crate::account::HomeFacts>;


/// Lists the groups whose member list names an account.
#[cfg(unix)]
pub type GroupsFn = fn(&str) -> io::Result<Vec<String>>;


/// Reads the groups that hold a gid and the other accounts that have it as their primary group, for an account name.
#[cfg(unix)]
pub type PrimaryFn = fn(&str, u32) -> io::Result<crate::account::PrimaryGroup>;
