use crate::error::PgError;


pub const MAX_TENANT_BYTES: usize = 64;


/// The tenant every store query filters on; only `tenant_scope` builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantScope {
    tenant: String,
}


pub fn tenant_scope(tenant: &str) -> Result<TenantScope, PgError> {
    let mut characters = tenant.chars();
    let valid = tenant.len() <= MAX_TENANT_BYTES
        && characters.next().is_some_and(|first| first.is_ascii_alphanumeric())
        && characters.all(|next| next.is_ascii_alphanumeric() || matches!(next, '_' | '.' | '-'));
    if valid {
        Ok(TenantScope { tenant: tenant.to_owned() })
    } else {
        Err(PgError::InvalidTenant)
    }
}


pub fn tenant_of(scope: &TenantScope) -> &str {
    &scope.tenant
}
