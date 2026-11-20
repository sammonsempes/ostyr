#[cfg(target_os = "linux")]
use crate::model::CommandStatus;
#[cfg(target_os = "linux")]
use crate::types::WaitFn;
#[cfg(target_os = "linux")]
use core_config::trusted_program::same_program;
#[cfg(target_os = "linux")]
use rustix::process::geteuid;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::process::{Child, Command, ExitStatus};
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


/// The default hook between the first judgement and the second: nothing.
#[cfg(target_os = "linux")]
pub fn leave_alone(_program: &Path) {}


/// Starts the child with null standard streams; past the deadline or on a failed wait the group is killed and reaped.
#[cfg(target_os = "linux")]
pub fn spawn_and_wait(program: &Path, arguments: &[String], deadline: Duration, wait: WaitFn) -> io::Result<CommandStatus> {
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


/// `run_child` with the trusted uid and a hook that runs before the second judgement, so a swap and a foreign owner are testable; a refusal spawns nothing.
#[cfg(target_os = "linux")]
pub fn run_child_with_hook(
    (handle, program): (&OwnedFd, &Path),
    arguments: &[String],
    deadline: Duration,
    wait: WaitFn,
    (trusted_uid, between): (u32, fn(&Path)),
) -> io::Result<CommandStatus> {
    between(program);
    let same = same_program(handle, program, trusted_uid).inspect_err(|failure| warn!(%failure, "the caddy program cannot be judged again"));
    if same.unwrap_or(false) {
        spawn_and_wait(program, arguments, deadline, wait)
    } else {
        Ok(CommandStatus::Refused)
    }
}


/// The program is judged again from `/` right before the spawn and must still be the inode the caller judged.
#[cfg(target_os = "linux")]
pub fn run_child(handle: &OwnedFd, program: &Path, arguments: &[String], deadline: Duration, wait: WaitFn) -> io::Result<CommandStatus> {
    run_child_with_hook((handle, program), arguments, deadline, wait, (geteuid().as_raw(), leave_alone))
}


/// `run_child` with the real wait.
#[cfg(target_os = "linux")]
pub fn run_with_deadline(handle: &OwnedFd, program: &Path, arguments: &[String], deadline: Duration) -> io::Result<CommandStatus> {
    run_child(handle, program, arguments, deadline, wait_child)
}
