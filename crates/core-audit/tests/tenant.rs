use core_audit::tenant::{
    is_customer_tenant, is_reserved_tenant, is_valid_tenant_grammar, AUDIT_TENANT, MAX_TENANT_BYTES, PLATFORM_TENANT, RESERVED_TENANTS,
};
use std::error::Error;


#[test]
fn consts_are_the_reserved_list() -> Result<(), Box<dyn Error>> {
    assert_eq!(AUDIT_TENANT, "all");
    assert_eq!(PLATFORM_TENANT, "platform");
    assert_eq!(RESERVED_TENANTS, ["all", "platform"]);
    Ok(())
}


#[test]
fn reserved_match_ignores_ascii_case_and_needs_the_whole_name() -> Result<(), Box<dyn Error>> {
    ["all", "ALL", "All", "platform", "PLATFORM"]
        .iter()
        .for_each(|name| assert!(is_reserved_tenant(name), "{name}"));
    ["alla", "all-1", "default", "", "plat"]
        .iter()
        .for_each(|name| assert!(!is_reserved_tenant(name), "{name}"));
    Ok(())
}


#[test]
fn grammar_and_customer_checks() -> Result<(), Box<dyn Error>> {
    assert!(is_valid_tenant_grammar("acme-1.eu_west"));
    ["", "-x", "a b", "é"]
        .iter()
        .for_each(|name| assert!(!is_valid_tenant_grammar(name), "{name}"));
    assert!(is_valid_tenant_grammar(&"a".repeat(MAX_TENANT_BYTES)));
    assert!(!is_valid_tenant_grammar(&"a".repeat(MAX_TENANT_BYTES + 1)));
    assert!(is_customer_tenant("default"));
    assert!(!is_customer_tenant("ALL"));
    assert!(!is_customer_tenant("-x"));
    Ok(())
}
