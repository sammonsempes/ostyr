use crate::model::CommandStatus;
use std::io;
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;


/// Runs the command with null standard streams, so no byte of Caddy's output is ever read; past the deadline the child is killed and reaped.
pub fn run_with_deadline(program: &str, arguments: &[String], deadline: Duration) -> io::Result<CommandStatus> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    match child.wait_timeout(deadline)? {
        Some(status) if status.success() => Ok(CommandStatus::Success),
        Some(status) => Ok(CommandStatus::Failed(status.code())),
        None => {
            child.kill()?;
            child.wait()?;
            Ok(CommandStatus::TimedOut)
        }
    }
}
