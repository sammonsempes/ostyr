use crate::limits::{MAX_NAME_BYTES, WILDCARD_PREFIX};
use thiserror::Error;


#[derive(Debug, Error)]
pub enum NameError {
    #[error("invalid domain name")]
    Invalid(#[from] idna::Errors),
    #[error("owner name of {0} bytes does not fit in a DNS name")]
    TooLong(usize),
}


/// Trailing dots removed, then strict IDNA: lowercase, punycode, letters digits and hyphens, label and name length limits.
pub fn normalise_name(value: &str) -> Result<String, NameError> {
    idna::domain_to_ascii_strict(value.trim_end_matches('.')).map_err(NameError::from)
}


/// The owner name `[*.]<trigger>.<zone>` must stay within the DNS name limit.
pub fn check_length(trigger: &str, zone: &str, wildcard: bool) -> Result<(), NameError> {
    let total = usize::from(wildcard) * WILDCARD_PREFIX.len() + trigger.len() + 1 + zone.len();
    if total > MAX_NAME_BYTES {
        Err(NameError::TooLong(total))
    } else {
        Ok(())
    }
}


/// `name` is `parent` or a subdomain of it.
pub fn is_under(name: &str, parent: &str) -> bool {
    name == parent || name.strip_suffix(parent).is_some_and(|rest| rest.ends_with('.'))
}
