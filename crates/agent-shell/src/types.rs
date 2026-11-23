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


/// Reads the passwd and group files once.
#[cfg(unix)]
pub type DatabasesFn = fn() -> io::Result<crate::account::Databases>;


/// Reads what a home path is on disk.
#[cfg(unix)]
pub type HomeFn = fn(&std::path::Path) -> io::Result<crate::account::HomeFacts>;


/// Tells whether an opened directory is on a cgroup v2 filesystem.
#[cfg(target_os = "linux")]
pub type CgroupCheckFn = fn(&std::os::fd::OwnedFd) -> io::Result<bool>;


/// Removes the session cgroup directory named by the second argument from the directory of the first.
#[cfg(target_os = "linux")]
pub type CgroupRemoveFn = fn(&std::os::fd::OwnedFd, &str) -> io::Result<()>;


/// Waits for one poll interval.
pub type PauseFn = fn(std::time::Duration);
