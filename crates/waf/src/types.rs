#[cfg(target_os = "linux")]
use crate::model::CommandStatus;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::time::Duration;


/// Runs the judged program (its handle and path) with separate arguments under a deadline; injected so tests never start Caddy.
#[cfg(target_os = "linux")]
pub type RunnerFn = fn(&OwnedFd, &Path, &[String], Duration) -> io::Result<CommandStatus>;


/// Waits for the child up to the deadline; injected so a test can make the wait itself fail.
pub type WaitFn = fn(&mut Child, Duration) -> io::Result<Option<ExitStatus>>;


/// Blocks until the process must stop; production waits for SIGINT or SIGTERM, tests return at once.
pub type InterruptFn<'a> = dyn Fn() -> io::Result<()> + 'a;
