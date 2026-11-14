use crate::model::{Severity, Status};


pub const IDENTITY_PUNCTUATION: &str = "_.:/@=+,*()-";


pub const MAX_ACCOUNT_BYTES: usize = 256;


pub const MAX_CHECK_ID_BYTES: usize = 128;


pub const MAX_PROVIDER_BYTES: usize = 32;


pub const MAX_REGION_BYTES: usize = 128;


pub const MAX_RESOURCE_UID_BYTES: usize = 1_024;


pub const MAX_RESOURCE_TYPE_BYTES: usize = 128;


/// ASCII allowlist for identities (ARNs and Azure resource ids included): alphanumerics and `_.:/@=+,*()-`, non-empty, no leading `-`, within the cap.
pub fn valid_reference(text: &str, max_bytes: usize) -> bool {
    !text.is_empty()
        && text.len() <= max_bytes
        && !text.starts_with('-')
        && text
            .chars()
            .all(|next| next.is_ascii_alphanumeric() || IDENTITY_PUNCTUATION.contains(next))
}


/// A provider name: lowercase ASCII letters, digits and `_`, non-empty, within the byte cap.
pub fn valid_provider(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_PROVIDER_BYTES && text.chars().all(|next| next.is_ascii_lowercase() || next.is_ascii_digit() || next == '_')
}


/// The `status_code` values of Prowler's `Status` enum.
pub fn status_of(text: &str) -> Option<Status> {
    match text {
        "PASS" => Some(Status::Pass),
        "FAIL" => Some(Status::Fail),
        "MANUAL" => Some(Status::Manual),
        "MUTED" => Some(Status::Muted),
        _ => None,
    }
}


/// The `severity` captions of the OCSF `SeverityID` enum.
pub fn severity_of(text: &str) -> Option<Severity> {
    match text {
        "Unknown" => Some(Severity::Unknown),
        "Informational" => Some(Severity::Informational),
        "Low" => Some(Severity::Low),
        "Medium" => Some(Severity::Medium),
        "High" => Some(Severity::High),
        "Critical" => Some(Severity::Critical),
        "Fatal" => Some(Severity::Fatal),
        "Other" => Some(Severity::Other),
        _ => None,
    }
}


/// One character as it is shown: ASCII graphic characters and the space unchanged, every other character as `\u{..}` (look-alikes and hidden ones included).
pub fn escaped(character: char) -> String {
    if character.is_ascii_graphic() || character == ' ' {
        character.to_string()
    } else {
        character.escape_unicode().collect()
    }
}


/// Escaped text of at most `max_bytes` bytes; a cut ends with `...[N bytes cut]`, N counting the source bytes left out.
pub fn shown(text: &str, max_bytes: usize) -> String {
    let outcome = text.chars().try_fold((String::new(), 0), |(mut out, used), next| {
        let piece = escaped(next);
        if out.len() + piece.len() > max_bytes {
            Err((out, used))
        } else {
            out.push_str(&piece);
            Ok((out, used + next.len_utf8()))
        }
    });
    match outcome {
        Ok((out, _)) => out,
        Err((out, used)) => format!("{out}...[{} bytes cut]", text.len() - used),
    }
}
