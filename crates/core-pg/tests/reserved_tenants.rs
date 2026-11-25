use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope};


#[test]
fn reserved_names_are_refused_in_every_case() -> Result<(), PgError> {
    ["all", "ALL", "All", "aLl", "platform", "PLATFORM", "Platform"]
        .iter()
        .for_each(|name| assert!(matches!(tenant_scope(name), Err(PgError::InvalidTenant)), "{name}"));
    Ok(())
}


#[test]
fn near_reserved_names_stay_customers() -> Result<(), PgError> {
    ["alla", "all-1", "default", "platform2", "xplatform", "a"]
        .iter()
        .try_for_each(|name| tenant_scope(name).map(|scope| assert_eq!(tenant_of(&scope), *name)))
}
