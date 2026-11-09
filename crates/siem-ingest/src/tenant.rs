use crate::error::TenantError;


pub const EVENTS_SUBJECT_PREFIX: &str = "events";


pub fn is_tenant_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '-' || character == '_'
}


/// The tenant is the one token after the prefix, set by the authenticated producer; length is checked in bytes, before anything is copied.
pub fn tenant_from_subject<'a>(subject: &'a str, prefix: &str, max_bytes: usize) -> Result<&'a str, TenantError> {
    let tenant = subject
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('.'))
        .ok_or(TenantError::Subject)?;
    if tenant.is_empty() {
        Err(TenantError::Empty)
    } else if tenant.len() > max_bytes {
        Err(TenantError::TooLong)
    } else if tenant.chars().all(is_tenant_char) {
        Ok(tenant)
    } else {
        Err(TenantError::Characters)
    }
}
