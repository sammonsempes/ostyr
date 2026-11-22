use crate::error::ActionError;
use crate::model::{
    Action, PackageSelection, MAX_PACKAGES, MAX_PACKAGE_NAME_LENGTH, MAX_REFERENCE_BYTES, MAX_SESSION_ID_BYTES, MAX_SHELL_APPROVERS,
    MAX_SHELL_IDLE_SECONDS, MAX_SHELL_SECONDS, MAX_SUBJECT_BYTES, PACKAGE_NAME_PUNCTUATION, REFERENCE_PUNCTUATION, SESSION_ID_PUNCTUATION,
    SUBJECT_PUNCTUATION,
};


/// One grammar for signing and verification: letters, digits and `.+-_:~`, no leading dash, bounded length.
pub fn validate_package_name(name: &str) -> Result<(), ActionError> {
    if name.is_empty() {
        Err(ActionError::EmptyPackageName)
    } else if name.len() > MAX_PACKAGE_NAME_LENGTH {
        Err(ActionError::PackageNameTooLong)
    } else if name.starts_with('-') {
        Err(ActionError::PackageNameLeadingDash)
    } else if name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || PACKAGE_NAME_PUNCTUATION.contains(character))
    {
        Ok(())
    } else {
        Err(ActionError::PackageNameCharacter)
    }
}


pub fn validate_selection(selection: &PackageSelection) -> Result<(), ActionError> {
    match selection {
        PackageSelection::AllAllowed => Ok(()),
        PackageSelection::Named(names) if names.is_empty() => Err(ActionError::NoPackages),
        PackageSelection::Named(names) if names.len() > MAX_PACKAGES => Err(ActionError::TooManyPackages),
        PackageSelection::Named(names) => names.iter().try_for_each(|name| validate_package_name(name)),
    }
}


pub fn validate_action(action: &Action) -> Result<(), ActionError> {
    match action {
        Action::InstallUpdates { packages, .. } => validate_selection(packages),
        Action::OpenShell {
            session_id,
            asset,
            ticket,
            requester,
            approvers,
            max_seconds,
            idle_seconds,
        } => validate_open_shell(session_id, asset, ticket, requester, approvers, (*max_seconds, *idle_seconds)),
        Action::Ping
        | Action::CollectStatus
        | Action::Isolate
        | Action::Kill { .. }
        | Action::RunScript { .. }
        | Action::Update { .. }
        | Action::Uninstall
        | Action::ChangePolicy { .. }
        | Action::Reboot { .. } => Ok(()),
    }
}


fn ascii_grammar(text: &str, maximum: usize, punctuation: &str) -> bool {
    (1..=maximum).contains(&text.len())
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || punctuation.contains(character))
}


fn starts_alphanumeric(text: &str) -> bool {
    text.chars().next().is_some_and(|first| first.is_ascii_alphanumeric())
}


/// `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`.
pub fn valid_session_id(text: &str) -> bool {
    ascii_grammar(text, MAX_SESSION_ID_BYTES, SESSION_ID_PUNCTUATION) && starts_alphanumeric(text)
}


/// `[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}`, a copy of the remote-shell reference grammar (pinned by a test there).
pub fn valid_shell_reference(text: &str) -> bool {
    ascii_grammar(text, MAX_REFERENCE_BYTES, REFERENCE_PUNCTUATION) && starts_alphanumeric(text)
}


/// The remote-shell subject grammar (pinned by a test there) with no leading dash.
pub fn valid_shell_subject(text: &str) -> bool {
    ascii_grammar(text, MAX_SUBJECT_BYTES, SUBJECT_PUNCTUATION) && !text.starts_with('-')
}


pub fn validate_approvers(requester: &str, approvers: &[String]) -> Result<(), ActionError> {
    if approvers.len() > MAX_SHELL_APPROVERS {
        Err(ActionError::ShellTooManyApprovers)
    } else {
        approvers.iter().enumerate().try_for_each(|(index, approver)| {
            if !valid_shell_subject(approver) {
                Err(ActionError::ShellApprover)
            } else if approver == requester {
                Err(ActionError::ShellApproverIsRequester)
            } else if approvers.iter().take(index).any(|earlier| earlier == approver) {
                Err(ActionError::ShellApproverDuplicate)
            } else {
                Ok(())
            }
        })
    }
}


/// `limits` is `(max_seconds, idle_seconds)`; a refusal names the field only.
pub fn validate_open_shell(
    session_id: &str,
    asset: &str,
    ticket: &str,
    requester: &str,
    approvers: &[String],
    limits: (u32, u32),
) -> Result<(), ActionError> {
    let (max_seconds, idle_seconds) = limits;
    if !valid_session_id(session_id) {
        Err(ActionError::ShellSessionId)
    } else if !valid_shell_reference(asset) {
        Err(ActionError::ShellAsset)
    } else if !valid_shell_reference(ticket) {
        Err(ActionError::ShellTicket)
    } else if !valid_shell_subject(requester) {
        Err(ActionError::ShellRequester)
    } else if !(1..=MAX_SHELL_SECONDS).contains(&max_seconds) {
        Err(ActionError::ShellMaxSeconds)
    } else if !(1..=MAX_SHELL_IDLE_SECONDS).contains(&idle_seconds) {
        Err(ActionError::ShellIdleSeconds)
    } else {
        validate_approvers(requester, approvers)
    }
}
