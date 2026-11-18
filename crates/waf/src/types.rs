use crate::model::CommandStatus;
use std::io;
use std::process::{Child, ExitStatus};
use std::time::Duration;


/// Runs a program with separate arguments under a deadline; injected so tests never start Caddy.
pub type RunnerFn = fn(&str, &[String], Duration) -> io::Result<CommandStatus>;


/// Waits for the child up to the deadline; injected so a test can make the wait itself fail.
pub type WaitFn = fn(&mut Child, Duration) -> io::Result<Option<ExitStatus>>;
