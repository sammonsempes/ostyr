//! Package manager grammars: a field that does not match is a malformed line, never a record.

use crate::model::Update;


pub fn is_dpkg_name(text: &str) -> bool {
    text.starts_with(|first: char| matches!(first, 'a'..='z' | '0'..='9'))
        && text.chars().all(|character| matches!(character, 'a'..='z' | '0'..='9' | '+' | '.' | '-'))
}


pub fn is_dpkg_architecture(text: &str) -> bool {
    text.starts_with(|first: char| matches!(first, 'a'..='z' | '0'..='9'))
        && text.chars().all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
}


pub fn is_rpm_name(text: &str) -> bool {
    text.starts_with(|first: char| first.is_ascii_alphanumeric() || matches!(first, '.' | '_' | '+'))
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '+' | '-'))
}


pub fn is_rpm_architecture(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|character| character.is_ascii_alphanumeric() || character == '_')
}


pub fn is_plain_text(text: &str) -> bool {
    !text.starts_with('-') && !text.is_empty() && text.chars().all(|character| character.is_ascii_graphic())
}


pub fn has_plain_text(update: &Update) -> bool {
    [
        Some(update.candidate_version.as_str()),
        update.installed_version.as_deref(),
        update.origin.as_deref(),
        update.advisory_id.as_deref(),
        update.severity.as_deref(),
    ]
    .into_iter()
    .flatten()
    .all(is_plain_text)
}


pub fn is_valid_debian(update: &Update) -> bool {
    is_dpkg_name(&update.package) && is_dpkg_architecture(&update.architecture) && has_plain_text(update)
}


pub fn is_valid_rpm(update: &Update) -> bool {
    is_rpm_name(&update.package) && is_rpm_architecture(&update.architecture) && has_plain_text(update)
}
