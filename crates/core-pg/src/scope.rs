use crate::error::PgError;
use core_audit::tenant::is_customer_tenant;
pub use core_audit::tenant::MAX_TENANT_BYTES;


/// The tenant every store query filters on; only `tenant_scope` builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantScope {
    tenant: String,
}


pub fn tenant_scope(tenant: &str) -> Result<TenantScope, PgError> {
    if is_customer_tenant(tenant) {
        Ok(TenantScope { tenant: tenant.to_owned() })
    } else {
        Err(PgError::InvalidTenant)
    }
}


pub fn tenant_of(scope: &TenantScope) -> &str {
    &scope.tenant
}
