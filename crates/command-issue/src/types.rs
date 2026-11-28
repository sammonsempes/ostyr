use crate::issue::Issued;
use agent_command::types::BoxError;
use rustix::io::Errno;
use std::io;
use std::os::fd::OwnedFd;


pub type ClockFn = dyn Fn() -> u64 + Send + Sync;


/// Called between staging and publish; an error unlinks the staged file and refuses the issue.
pub type HookFn = dyn Fn(&Issued) -> Result<(), BoxError> + Send + Sync;


pub type UnlinkFn = fn(&OwnedFd, &str) -> io::Result<()>;


pub type SyncFn = fn(&OwnedFd) -> Result<(), Errno>;
