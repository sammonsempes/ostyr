use crate::error::ReloadError;
use crate::limits::{RELOAD_AUDIT_ACTION, RELOAD_SUBCOMMAND};
use crate::model::{CommandStatus, Reloader};
use crate::policy::{Action, Policy};
use crate::types::RunnerFn;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_config::reload::ReloadContext;
use std::io;
use std::process::{Command, Stdio};
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


/// Runs the command with null standard streams; past the deadline the process is killed and reaped.
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


/// Reloads the zone, then logs and audits the result; a failure leaves the previous zone serving and is returned to the caller.
pub fn reload_zone(policy: &Policy, reloader: &Reloader) -> Result<(), ReloadError> {
    let result = run_reload(policy, reloader.runner);
    let (outcome, text) = match &result {
        Ok(()) => (Outcome::Success, "reloaded".to_owned()),
        Err(failure) => (Outcome::Failure, failure.to_string()),
    };
    match &result {
        Ok(()) => info!(zone = policy.zone, "Unbound zone reloaded"),
        Err(failure) => error!(zone = policy.zone, %failure, "Unbound zone reload failed, the previous zone keeps serving"),
    }
    if let Err(audit_error) = (reloader.audit)(reload_entry(reloader.context, &policy.zone, outcome, text)) {
        error!(%audit_error, "cannot audit the zone reload");
    }
    result
}
