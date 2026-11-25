use crate::error::ReloadError;
use crate::limits::{
    MAX_CAPTURE_BYTES, NEW_ZONE_ON_DISK, READBACK_SUBCOMMAND, REAP_GRACE_SECONDS, RELOAD_AUDIT_ACTION, RELOAD_SUBCOMMAND, SERIAL_WORD,
};
use crate::model::{Capture, CommandStatus, ReloadVerdict, Reloader};
use crate::policy::{Action, Policy};
use crate::types::{GroupKillFn, RunnerFn};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_config::reload::ReloadContext;
use std::io::{self, Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;
use time::OffsetDateTime;
use tracing::{error, info};
use wait_timeout::ChildExt;


/// The `rpz:` block of `unbound.conf` for the policy zone; an override is written only when the policy sets one.
pub fn render_unbound_config(policy: &Policy) -> String {
    let unbound = &policy.unbound;
    let log_name = unbound.log_name.as_deref().unwrap_or(&policy.zone);
    let mut lines = vec![
        "rpz:".to_owned(),
        format!("    name: \"{}\"", policy.zone),
        format!("    zonefile: \"{}\"", unbound.zonefile),
    ];
    match &unbound.action_override {
        Some(Action::Nxdomain) => lines.push("    rpz-action-override: nxdomain".to_owned()),
        Some(Action::Nodata) => lines.push("    rpz-action-override: nodata".to_owned()),
        Some(Action::Passthru) => lines.push("    rpz-action-override: passthru".to_owned()),
        Some(Action::Cname(host)) => {
            lines.push("    rpz-action-override: cname".to_owned());
            lines.push(format!("    rpz-cname-override: \"{host}.\""));
        }
        None => {}
    }
    lines.push("    rpz-log: yes".to_owned());
    lines.push(format!("    rpz-log-name: \"{log_name}\""));
    lines.push(String::new());
    lines.join("\n")
}


/// Own process group for the child, so a deadline can kill its descendants too.
#[cfg(unix)]
pub fn in_own_group(command: &mut Command) -> &mut Command {
    command.process_group(0)
}


#[cfg(not(unix))]
pub fn in_own_group(command: &mut Command) -> &mut Command {
    command
}


/// A group that is already empty is fine; any other failure is an error.
#[cfg(unix)]
pub fn group_kill_result(result: rustix::io::Result<()>) -> io::Result<()> {
    match result {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(errno) => Err(io::Error::from(errno)),
    }
}


/// Ends the child's whole process group, descendants included.
#[cfg(unix)]
pub fn end_group(child: &mut Child) -> io::Result<()> {
    group_kill_result(rustix::process::kill_process_group(
        rustix::process::Pid::from_child(child),
        rustix::process::Signal::KILL,
    ))
}


#[cfg(not(unix))]
pub fn end_group(child: &mut Child) -> io::Result<()> {
    child.kill()
}


/// A leader that is still not reaped after the kill and the grace period is an error, never an unbounded wait.
pub fn reaped(status: Option<ExitStatus>) -> io::Result<()> {
    status
        .map(|_status| ())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "the command did not exit after it was killed"))
}


/// Own process group, stdout in an anonymous file; the group and the leader are killed with the command or at the deadline, output capped.
pub fn run_capture(program: &str, arguments: &[String], deadline: Duration) -> io::Result<Capture> {
    run_capture_with(program, arguments, deadline, end_group)
}


/// `run_capture` with the group kill injected: the leader is killed and reaped whatever it returns, then its error is reported.
pub fn run_capture_with(program: &str, arguments: &[String], deadline: Duration, group_kill: GroupKillFn) -> io::Result<Capture> {
    let mut capture = tempfile::tempfile()?;
    let mut command = Command::new(program);
    let mut child = in_own_group(command.args(arguments).stdin(Stdio::null()).stderr(Stdio::null()))
        .stdout(Stdio::from(capture.try_clone()?))
        .spawn()?;
    let waited = child.wait_timeout(deadline)?;
    let group_result = group_kill(&mut child);
    let leader_result = child.kill();
    let reap_result = child.wait_timeout(Duration::from_secs(REAP_GRACE_SECONDS));
    group_result?;
    leader_result?;
    reaped(reap_result?)?;
    let status = match waited {
        Some(status) if status.success() => CommandStatus::Success,
        Some(status) => CommandStatus::Failed(status.code()),
        None => CommandStatus::TimedOut,
    };
    let mut output = Vec::new();
    capture.seek(SeekFrom::Start(0))?;
    Read::take(&mut capture, MAX_CAPTURE_BYTES + 1).read_to_end(&mut output)?;
    let cut = output.len() as u64 > MAX_CAPTURE_BYTES;
    output.truncate(MAX_CAPTURE_BYTES as usize);
    Ok(Capture { status, output, cut })
}


/// Runs the command with null standard streams; past the deadline its process group is ended and reaped.
pub fn run_with_deadline(program: &str, arguments: &[String], deadline: Duration) -> io::Result<CommandStatus> {
    run_capture(program, arguments, deadline).map(|capture| capture.status)
}


/// The text a successful command printed; a failure, a timeout or output cut at the cap is an error.
pub fn captured_text(capture: Capture) -> io::Result<String> {
    match capture.status {
        CommandStatus::Success if capture.cut => Err(io::Error::other(format!("read-back cut at {MAX_CAPTURE_BYTES} bytes"))),
        CommandStatus::Success => String::from_utf8(capture.output).map_err(io::Error::other),
        CommandStatus::Failed(code) => Err(io::Error::other(ReloadError::Failed(code))),
        CommandStatus::TimedOut => Err(io::Error::new(io::ErrorKind::TimedOut, "the Unbound control command timed out")),
    }
}


/// Real read-back runner: the command's standard output.
pub fn run_readback(program: &str, arguments: &[String], deadline: Duration) -> io::Result<String> {
    run_capture(program, arguments, deadline).and_then(captured_text)
}


/// The serial `list_auth_zones` shows for the zone (`<name>.` then `serial <n>` on one line).
pub fn served_serial(listing: &str, zone: &str) -> Option<u32> {
    let wanted = zone.trim_end_matches('.');
    listing.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        let name = words.next()?;
        let named = name.trim_end_matches('.').eq_ignore_ascii_case(wanted);
        let mut rest = words.skip_while(|word| *word != SERIAL_WORD).skip(1);
        rest.next().filter(|_| named).and_then(|text| text.parse().ok())
    })
}


pub fn reload_entry(context: &ReloadContext, zone: &str, outcome: Outcome, result: String) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: context.actor_id.clone(),
        },
        tenant: context.tenant.clone(),
        module: context.module.clone(),
        action: RELOAD_AUDIT_ACTION.to_owned(),
        target: zone.to_owned(),
        outcome,
        request_id: context.request_id.clone(),
        justification: None,
        parameters: [("result".to_owned(), result)].into_iter().collect(),
    }
}


/// Asks Unbound to reload the zone; the settings come from the policy given, so a live swap applies to the next call.
pub fn run_reload(policy: &Policy, runner: &RunnerFn) -> Result<(), ReloadError> {
    let unbound = &policy.unbound;
    let arguments = [RELOAD_SUBCOMMAND.to_owned(), policy.zone.clone()];
    match runner(&unbound.command, &arguments, Duration::from_secs(unbound.timeout_seconds))? {
        CommandStatus::Success => Ok(()),
        CommandStatus::Failed(code) => Err(ReloadError::Failed(code)),
        CommandStatus::TimedOut => Err(ReloadError::TimedOut(unbound.timeout_seconds)),
    }
}


/// What is true of the zone after the attempt, read back from Unbound, never assumed from the command's status.
pub fn read_verdict(policy: &Policy, reloader: &Reloader, serial: u32) -> (ReloadVerdict, String) {
    let unbound = &policy.unbound;
    let arguments = [READBACK_SUBCOMMAND.to_owned()];
    match (reloader.readback)(&unbound.command, &arguments, Duration::from_secs(unbound.timeout_seconds)) {
        Ok(listing) => match served_serial(&listing, &policy.zone) {
            Some(served) if served == serial => (ReloadVerdict::Applied, format!("Unbound serves serial {serial}")),
            Some(served) => (ReloadVerdict::Failed, format!("Unbound serves serial {served}, not {serial}")),
            None => (ReloadVerdict::Failed, "Unbound lists no serial for the zone".to_owned()),
        },
        Err(failure) => (ReloadVerdict::Unknown, format!("the served serial could not be read: {failure}")),
    }
}


/// Reloads the zone, reads back what Unbound serves, then logs and audits that outcome; the new zone is on disk whatever the verdict.
pub fn reload_zone(policy: &Policy, reloader: &Reloader, serial: u32) -> ReloadVerdict {
    let result = run_reload(policy, reloader.runner);
    let command = result
        .as_ref()
        .map_or_else(|failure| failure.to_string(), |()| "the command succeeded".to_owned());
    let (verdict, observed) = read_verdict(policy, reloader, serial);
    let (outcome, text) = match verdict {
        ReloadVerdict::Applied => (Outcome::Success, format!("applied: {observed}; {command}")),
        ReloadVerdict::Failed => (Outcome::Failure, format!("failed: {observed}; {command}; {NEW_ZONE_ON_DISK}")),
        ReloadVerdict::Unknown => (Outcome::Failure, format!("unknown: {observed}; {command}; {NEW_ZONE_ON_DISK}")),
    };
    match verdict {
        ReloadVerdict::Applied => info!(zone = policy.zone, %observed, %command, "Unbound zone reload applied"),
        ReloadVerdict::Failed => error!(zone = policy.zone, %observed, %command, "Unbound zone reload failed, the new zone loads at the next start"),
        ReloadVerdict::Unknown => error!(zone = policy.zone, %observed, %command, "Unbound zone reload outcome unknown, new zone on disk"),
    }
    if let Err(audit_error) = (reloader.audit)(reload_entry(reloader.context, &policy.zone, outcome, text)) {
        error!(%audit_error, "cannot audit the zone reload");
    }
    verdict
}
