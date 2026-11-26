#[cfg(target_os = "linux")]
use crate::model::CommandStatus;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
use std::os::raw::c_int;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::sync::mpsc::Receiver;
use std::time::Duration;


/// Runs the judged program (its handle and path) with separate arguments under a deadline; injected so tests never start Caddy.
#[cfg(target_os = "linux")]
pub type RunnerFn = fn(&OwnedFd, &Path, &[String], Duration) -> io::Result<CommandStatus>;


/// Waits for the child up to the deadline; injected so a test can make the wait itself fail.
pub type WaitFn = fn(&mut Child, Duration) -> io::Result<Option<ExitStatus>>;


/// Registers the process signals and returns their queue; production queues SIGHUP, SIGINT and SIGTERM, tests feed their own.
pub type SignalSourceFn<'a> = dyn Fn() -> io::Result<Receiver<c_int>> + 'a;
