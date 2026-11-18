use crate::model::CommandStatus;
use crate::types::WaitFn;
use std::io;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;
use tracing::warn;
use wait_timeout::ChildExt;


/// The production wait: `None` when the deadline passed first.
pub fn wait_child(child: &mut Child, deadline: Duration) -> io::Result<Option<ExitStatus>> {
    child.wait_timeout(deadline)
}


/// A failure while stopping a child is logged with its kind, never silent; the caller goes on.
pub fn logged(what: &'static str, result: io::Result<()>) {
    if let Err(failure) = result {
        let kind = failure.kind();
        warn!(what, ?kind, "cannot stop the caddy command cleanly");
    }
}


/// The child leads its own process group, so the whole group can be killed.
#[cfg(unix)]
pub fn own_group(command: &mut Command) -> &mut Command {
    std::os::unix::process::CommandExt::process_group(command, 0)
}


#[cfg(not(unix))]
pub fn own_group(command: &mut Command) -> &mut Command {
    command
}


#[cfg(unix)]
pub fn kill_group(child: &Child) -> io::Result<()> {
    rustix::process::kill_process_group(rustix::process::Pid::from_child(child), rustix::process::Signal::KILL).map_err(io::Error::from)
}


#[cfg(not(unix))]
pub fn kill_group(_child: &Child) -> io::Result<()> {
    Ok(())
}


/// Kills the group and the child, then reaps it; each failure is logged.
pub fn stop(child: &mut Child) {
    logged("kill group", kill_group(child));
    logged("kill", child.kill());
    logged("reap", child.wait().map(drop));
}


/// Null standard streams, so no byte of Caddy's output is read; past the deadline or on a failed wait the group is killed and reaped.
pub fn run_child(program: &str, arguments: &[String], deadline: Duration, wait: WaitFn) -> io::Result<CommandStatus> {
    let mut command = Command::new(program);
    let mut child = own_group(command.args(arguments).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())).spawn()?;
    match wait(&mut child, deadline) {
        Ok(Some(status)) if status.success() => Ok(CommandStatus::Success),
        Ok(Some(status)) => Ok(CommandStatus::Failed(status.code())),
        Ok(None) => {
            stop(&mut child);
            Ok(CommandStatus::TimedOut)
        }
        Err(failure) => {
            logged("wait", Err(failure));
            stop(&mut child);
            Ok(CommandStatus::Failed(None))
        }
    }
}


/// `run_child` with the real wait.
pub fn run_with_deadline(program: &str, arguments: &[String], deadline: Duration) -> io::Result<CommandStatus> {
    run_child(program, arguments, deadline, wait_child)
}
