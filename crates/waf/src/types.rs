use crate::model::CommandStatus;
use std::io;
use std::time::Duration;


/// Runs a program with separate arguments under a deadline; injected so tests never start Caddy.
pub type RunnerFn = fn(&str, &[String], Duration) -> io::Result<CommandStatus>;
