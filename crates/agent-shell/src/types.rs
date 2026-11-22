use crate::model::{PtyHandle, VerifiedOpenShell};
use agent_channel::error::ChannelError;
use agent_channel::model::ShellClientEnd;
pub use agent_channel::types::DialFn;
use agent_channel::types::{ShellReader, ShellWriter};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tonic::transport::Channel;


/// The agent clock in Unix seconds.
pub type ClockFn = dyn Fn() -> u64 + Send + Sync;


/// Starts the shell of a verified order on a PTY; the real spawner and its privilege drop are a later slice.
pub type SpawnFn = dyn Fn(&VerifiedOpenShell) -> io::Result<PtyHandle> + Send + Sync;


/// Removes what an earlier session left behind and returns how many processes remain.
pub type CleanupFn = dyn Fn() -> io::Result<usize> + Send + Sync;


pub type AttachFuture = Pin<Box<dyn Future<Output = Result<ShellClientEnd, ChannelError>> + Send>>;


/// Attaches the shell to the platform: the channel, the session id, the shell output and the terminal input writer.
pub type AttachFn = dyn Fn(Channel, String, ShellReader, ShellWriter) -> AttachFuture + Send + Sync;


/// True from the admission of an `OpenShell` until its session has ended and cleaned up: a second one is refused by name.
pub type ShellSlot = Arc<AtomicBool>;


/// Reads the metadata of an opened store handle.
#[cfg(unix)]
pub type InspectFn = fn(&std::fs::File) -> io::Result<std::fs::Metadata>;
