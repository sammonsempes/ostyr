use crate::error::ActionError;
use crate::model::{
    Action, PackageSelection, BOOT_ID_DASHES, BOOT_ID_LENGTH, MAX_AGENT_PATH_BYTES, MAX_PACKAGES, MAX_PACKAGE_NAME_LENGTH, MAX_QUARANTINE_BYTES,
    MAX_REFERENCE_BYTES, MAX_SESSION_ID_BYTES, MAX_SHELL_APPROVERS, MAX_SHELL_IDLE_SECONDS, MAX_SHELL_SECONDS, MAX_STOP_SECONDS, MAX_SUBJECT_BYTES,
    MIN_STOP_SECONDS, PACKAGE_NAME_PUNCTUATION, REFERENCE_PUNCTUATION, SESSION_ID_PUNCTUATION, SHA256_HEX_LENGTH, SUBJECT_PUNCTUATION,
};
use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::char::canonical_combining_class;


/// Canonical combining class of the overlay marks (U+0334 to U+0338, U+20D2, ...).
const OVERLAY_CLASS: u8 = 1;


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
        Action::Kill { boot_id, .. } if !valid_boot_id(boot_id) => Err(ActionError::KillBootId),
        Action::Stop { resume_after_seconds } => validate_stop(*resume_after_seconds),
        Action::Quarantine { path, sha256, size } => validate_quarantine(path, sha256, *size),
        Action::RestoreQuarantine { entry, sha256 } => validate_restore(*entry, sha256),
        Action::Scan { path } if !valid_agent_path(path) => Err(ActionError::ScanPath),
        Action::Ping
        | Action::CollectStatus
        | Action::Isolate
        | Action::Kill { .. }
        | Action::RunScript { .. }
        | Action::Update { .. }
        | Action::Uninstall
        | Action::ChangePolicy { .. }
        | Action::Reboot { .. }
        | Action::Scan { .. } => Ok(()),
    }
}


pub fn validate_stop(resume_after_seconds: u32) -> Result<(), ActionError> {
    if (MIN_STOP_SECONDS..=MAX_STOP_SECONDS).contains(&resume_after_seconds) {
        Ok(())
    } else {
        Err(ActionError::StopSeconds)
    }
}


pub fn validate_quarantine(path: &str, sha256: &str, size: u64) -> Result<(), ActionError> {
    if !valid_agent_path(path) {
        Err(ActionError::QuarantinePath)
    } else if !valid_sha256(sha256) {
        Err(ActionError::QuarantineSha256)
    } else if !(1..=MAX_QUARANTINE_BYTES).contains(&size) {
        Err(ActionError::QuarantineSize)
    } else {
        Ok(())
    }
}


pub fn validate_restore(entry: u64, sha256: &str) -> Result<(), ActionError> {
    if entry == 0 {
        Err(ActionError::RestoreEntry)
    } else if !valid_sha256(sha256) {
        Err(ActionError::RestoreSha256)
    } else {
        Ok(())
    }
}


/// Exactly 64 lowercase hexadecimal characters.
pub fn valid_sha256(text: &str) -> bool {
    text.len() == SHA256_HEX_LENGTH
        && text
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}


/// Letters that render blank (a pinned copy of status-page `INVISIBLE_CHARACTERS`, a test compares them).
pub const BLANK_LETTERS: [char; 15] = [
    '\u{034F}',
    '\u{115F}',
    '\u{1160}',
    '\u{17B4}',
    '\u{17B5}',
    '\u{2800}',
    '\u{180F}',
    '\u{3164}',
    '\u{FFA0}',
    '\u{13441}',
    '\u{13442}',
    '\u{13443}',
    '\u{13444}',
    '\u{13445}',
    '\u{13446}',
];


/// Control, format, every space but U+0020, private-use and unassigned characters, and the blank-rendering letters.
pub fn is_hidden_character(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::SpaceSeparator
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
    ) && character != ' '
        || BLANK_LETTERS.contains(&character)
        || is_variation_selector(character)
        || canonical_combining_class(character) == OVERLAY_CLASS
}


/// Variation selectors: `U+180B` to `U+180D`, `U+FE00` to `U+FE0F`, `U+E0100` to `U+E01EF` (a test compares with status-page).
pub fn is_variation_selector(character: char) -> bool {
    matches!(character, '\u{180B}'..='\u{180D}' | '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}')
}


/// General category Mn, Mc or Me.
pub fn is_mark(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::NonspacingMark | GeneralCategory::SpacingMark | GeneralCategory::EnclosingMark
    )
}


fn valid_path_component(component: &str) -> bool {
    let unmarked: String = component.chars().filter(|character| !is_mark(*character)).collect();
    !component.is_empty() && unmarked != "." && unmarked != ".." && !component.chars().next().is_some_and(is_mark)
}


/// POSIX absolute path, not `/`: no empty, `.` or `..` component (marks ignored), none starting with a mark, no overlay mark, no trailing `/`, no hidden character, at most `MAX_AGENT_PATH_BYTES`.
pub fn valid_agent_path(text: &str) -> bool {
    text.len() <= MAX_AGENT_PATH_BYTES
        && text
            .strip_prefix('/')
            .is_some_and(|rest| rest.split('/').all(valid_path_component) && !rest.chars().any(is_hidden_character))
}


/// `/proc/sys/kernel/random/boot_id`: 36 characters, lowercase hex with `-` at positions 8, 13, 18 and 23.
pub fn valid_boot_id(text: &str) -> bool {
    text.len() == BOOT_ID_LENGTH
        && text.chars().enumerate().all(|(index, character)| {
            if BOOT_ID_DASHES.contains(&index) {
                character == '-'
            } else {
                character.is_ascii_digit() || ('a'..='f').contains(&character)
            }
        })
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
