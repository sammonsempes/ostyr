use crate::error::ShellError;
use crate::model::{expires_at_of, verified_open_shell, VerifiedOpenShell};
use agent_command::action::validate_open_shell;
use agent_command::model::{Action, Command, KeyClass, CLOCK_SKEW_SECONDS, MAX_LIFETIME_SECONDS};


/// True once the command is past `expires_at` plus the clock skew on the agent clock.
pub fn is_past(expires_at: u64, now: u64) -> bool {
    now > expires_at.saturating_add(CLOCK_SKEW_SECONDS)
}


/// The start is refused after `expires_at` plus the skew; the limits then run from the PTY start and are never extended.
pub fn check_start(order: &VerifiedOpenShell, now: u64) -> Result<(), ShellError> {
    if is_past(expires_at_of(order), now) {
        Err(ShellError::Expired)
    } else {
        Ok(())
    }
}


pub fn lifetime_ok(issued_at: u64, expires_at: u64) -> bool {
    expires_at
        .checked_sub(issued_at)
        .is_some_and(|lifetime| lifetime > 0 && lifetime <= MAX_LIFETIME_SECONDS)
}


pub fn judge_class_and_lifetime(command: &Command) -> Result<(), ShellError> {
    if command.key_class != KeyClass::Sensitive {
        Err(ShellError::NotSensitive)
    } else if lifetime_ok(command.issued_at, command.expires_at) {
        Ok(())
    } else {
        Err(ShellError::Lifetime)
    }
}


impl TryFrom<Command> for VerifiedOpenShell {
    type Error = ShellError;

    fn try_from(command: Command) -> Result<Self, ShellError> {
        match &command.action {
            Action::OpenShell {
                session_id,
                asset,
                ticket,
                requester,
                approvers,
                max_seconds,
                idle_seconds,
            } => {
                validate_open_shell(session_id, asset, ticket, requester, approvers, (*max_seconds, *idle_seconds)).map_err(ShellError::Invalid)?;
                judge_class_and_lifetime(&command)?;
                Ok(verified_open_shell(
                    (session_id.clone(), asset.clone(), ticket.clone(), requester.clone(), approvers.clone()),
                    (*max_seconds, *idle_seconds),
                    command.expires_at,
                ))
            }
            _ => Err(ShellError::NotOpenShell),
        }
    }
}
