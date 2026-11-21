use crate::model::{Severity, Status};


pub const IDENTITY_PUNCTUATION: &str = "_.:/@=+,*()$#-";


pub const MAX_ACCOUNT_BYTES: usize = 256;


pub const MAX_CHECK_ID_BYTES: usize = 128;


pub const MAX_PROVIDER_BYTES: usize = 32;


pub const MAX_REGION_BYTES: usize = 128;


pub const MAX_RESOURCE_UID_BYTES: usize = 1_024;


pub const MAX_RESOURCE_TYPE_BYTES: usize = 128;


pub const MAX_FINDING_UID_BYTES: usize = 2_048;


/// ASCII allowlist for identities (ARNs and Azure resource ids included): alphanumerics and `_.:/@=+,*()$#-`, non-empty, no leading `-`, within the cap.
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


/// One character as it is shown: ASCII graphic characters other than `\` and the space unchanged, every other character as `\u{..}` (look-alikes and hidden ones included).
pub fn escaped(character: char) -> String {
    if (character.is_ascii_graphic() && character != '\\') || character == ' ' {
        character.to_string()
    } else {
        character.escape_unicode().collect()
    }
}


/// A display text kept raw: the longest prefix of at most `max_bytes` bytes ending on a character boundary, and the count of bytes left out.
pub fn cut_text(text: &str, max_bytes: usize) -> (String, usize) {
    let end = (0..=max_bytes.min(text.len()))
        .rev()
        .find(|index| text.is_char_boundary(*index))
        .unwrap_or(0);
    let mut kept = String::with_capacity(end);
    kept.push_str(text.get(..end).unwrap_or(""));
    (kept, text.len() - end)
}


/// A stored display text escaped for display; a cut ends with the marker `\[N bytes cut]`, whose backslash no escaped text can hold.
pub fn shown(text: &str, cut: usize) -> String {
    let body = escaped_whole(text);
    if cut == 0 {
        body
    } else {
        format!("{body}\\[{cut} bytes cut]")
    }
}


/// A reference whose words are separated by single spaces (`Conditional Access Policy`, `Group/Domain Admins`): no leading, trailing or double space, each word a `valid_reference`.
pub fn valid_spaced_reference(text: &str, max_bytes: usize) -> bool {
    text.len() <= max_bytes && text.split(' ').all(|word| valid_reference(word, max_bytes))
}


/// Every character of a text escaped as in `shown`, never cut: for showing a stored raw identity, such as the finding uid.
pub fn escaped_whole(text: &str) -> String {
    text.chars().map(escaped).collect()
}


/// The finding uid as identity: non-empty and within the byte cap, kept raw (escape it with `escaped_whole` to show it).
pub fn finding_uid(text: &str) -> Option<String> {
    Some(text)
        .filter(|uid| !uid.is_empty() && uid.len() <= MAX_FINDING_UID_BYTES)
        .map(str::to_owned)
}


pub const RANK_FATAL: u8 = 7;


pub const RANK_CRITICAL: u8 = 6;


pub const RANK_HIGH: u8 = 5;


pub const RANK_MEDIUM: u8 = 4;


pub const RANK_LOW: u8 = 3;


pub const RANK_INFORMATIONAL: u8 = 2;


pub const RANK_OTHER: u8 = 1;


pub const RANK_UNKNOWN: u8 = 0;


/// The `status_code` text of a status, the inverse of `status_of`.
pub fn status_text(status: Status) -> &'static str {
    match status {
        Status::Pass => "PASS",
        Status::Fail => "FAIL",
        Status::Manual => "MANUAL",
        Status::Muted => "MUTED",
    }
}


/// The OCSF caption of a severity, the inverse of `severity_of`.
pub fn severity_text(severity: Severity) -> &'static str {
    match severity {
        Severity::Unknown => "Unknown",
        Severity::Informational => "Informational",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
        Severity::Fatal => "Fatal",
        Severity::Other => "Other",
    }
}


/// The stored order of severities, the map the paging index sorts on (`RANK_*`, pinned by a CHECK of the table).
pub fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Fatal => RANK_FATAL,
        Severity::Critical => RANK_CRITICAL,
        Severity::High => RANK_HIGH,
        Severity::Medium => RANK_MEDIUM,
        Severity::Low => RANK_LOW,
        Severity::Informational => RANK_INFORMATIONAL,
        Severity::Other => RANK_OTHER,
        Severity::Unknown => RANK_UNKNOWN,
    }
}
