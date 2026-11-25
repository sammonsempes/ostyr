pub const MAX_TENANT_BYTES: usize = 64;


pub const AUDIT_TENANT: &str = "all";


pub const PLATFORM_TENANT: &str = "platform";


pub const RESERVED_TENANTS: [&str; 2] = [AUDIT_TENANT, PLATFORM_TENANT];


/// ASCII case-insensitive whole-name match against the non-customer audit tenants.
pub fn is_reserved_tenant(name: &str) -> bool {
    RESERVED_TENANTS.iter().any(|reserved| name.eq_ignore_ascii_case(reserved))
}


/// The tenant name grammar: 1 to `MAX_TENANT_BYTES` ASCII alphanumerics, `_`, `.`, `-`, starting alphanumeric.
pub fn is_valid_tenant_grammar(name: &str) -> bool {
    let mut characters = name.chars();
    name.len() <= MAX_TENANT_BYTES
        && characters.next().is_some_and(|first| first.is_ascii_alphanumeric())
        && characters.all(|next| next.is_ascii_alphanumeric() || matches!(next, '_' | '.' | '-'))
}


/// A customer tenant name: valid grammar and not reserved.
pub fn is_customer_tenant(name: &str) -> bool {
    is_valid_tenant_grammar(name) && !is_reserved_tenant(name)
}
