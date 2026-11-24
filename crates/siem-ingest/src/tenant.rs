use crate::error::TenantError;
use core_pg::scope::tenant_scope;


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
    } else if tenant.contains('.') || tenant_scope(tenant).is_err() {
        Err(TenantError::Characters)
    } else {
        Ok(tenant)
    }
}


pub const INVALID_TENANT_TOKEN: &str = "_invalid";


/// The tenant as one dead-letter subject token: the same checks as `tenant_from_subject`, else `INVALID_TENANT_TOKEN`.
pub fn dead_letter_token(tenant: &str, max_bytes: usize) -> String {
    let probe = format!("{EVENTS_SUBJECT_PREFIX}.{tenant}");
    tenant_from_subject(&probe, EVENTS_SUBJECT_PREFIX, max_bytes).map_or_else(|_| INVALID_TENANT_TOKEN.to_owned(), str::to_owned)
}


/// `<prefix>.<token>`: exactly one token after the prefix, whatever the tenant text.
pub fn dead_letter_subject(prefix: &str, tenant: &str, max_bytes: usize) -> String {
    format!("{prefix}.{}", dead_letter_token(tenant, max_bytes))
}
