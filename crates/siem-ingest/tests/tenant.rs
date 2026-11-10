use siem_ingest::error::TenantError;
use siem_ingest::tenant::{tenant_from_subject, EVENTS_SUBJECT_PREFIX};
use std::error::Error;


const CAP: usize = 8;


const WIDE: usize = 128;


const CORE_PG_MAX: usize = 64;


#[test]
fn tenant_is_the_token_after_the_prefix() -> Result<(), Box<dyn Error>> {
    assert_eq!(tenant_from_subject("events.tenant-a", EVENTS_SUBJECT_PREFIX, CAP)?, "tenant-a");
    assert_eq!(tenant_from_subject("events.T_1", EVENTS_SUBJECT_PREFIX, CAP)?, "T_1");
    Ok(())
}


#[test]
fn core_pg_grammar_applies_and_dots_are_refused() -> Result<(), Box<dyn Error>> {
    let long = format!("events.{}", "a".repeat(CORE_PG_MAX + 1));
    let exact = "a".repeat(CORE_PG_MAX);
    for bad in ["events.-x", "events._x", "events..x", "events.x\u{7}", "events.Tenant!"] {
        assert_eq!(
            tenant_from_subject(bad, EVENTS_SUBJECT_PREFIX, WIDE),
            Err(TenantError::Characters),
            "{bad}"
        );
    }
    assert_eq!(tenant_from_subject(&long, EVENTS_SUBJECT_PREFIX, WIDE), Err(TenantError::Characters));
    for good in ["events.a", "events.a-b", "events.a_b", "events.Tenant"] {
        assert!(tenant_from_subject(good, EVENTS_SUBJECT_PREFIX, WIDE).is_ok(), "{good}");
    }
    let subject = format!("events.{exact}");
    assert_eq!(tenant_from_subject(&subject, EVENTS_SUBJECT_PREFIX, WIDE)?, exact);
    Ok(())
}


#[test]
fn empty_tenant_is_refused() -> Result<(), Box<dyn Error>> {
    assert_eq!(tenant_from_subject("events.", EVENTS_SUBJECT_PREFIX, CAP), Err(TenantError::Empty));
    Ok(())
}


#[test]
fn oversized_tenant_is_refused_at_the_cap() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        tenant_from_subject("events.abcdefghi", EVENTS_SUBJECT_PREFIX, CAP),
        Err(TenantError::TooLong)
    );
    assert_eq!(tenant_from_subject("events.abcdefgh", EVENTS_SUBJECT_PREFIX, CAP)?, "abcdefgh");
    Ok(())
}


#[test]
fn foreign_subjects_and_extra_tokens_are_refused() -> Result<(), Box<dyn Error>> {
    assert_eq!(tenant_from_subject("metrics.a", EVENTS_SUBJECT_PREFIX, CAP), Err(TenantError::Subject));
    assert_eq!(tenant_from_subject("events", EVENTS_SUBJECT_PREFIX, CAP), Err(TenantError::Subject));
    assert_eq!(tenant_from_subject("eventsx.a", EVENTS_SUBJECT_PREFIX, CAP), Err(TenantError::Subject));
    assert_eq!(
        tenant_from_subject("events.a.b", EVENTS_SUBJECT_PREFIX, CAP),
        Err(TenantError::Characters)
    );
    assert_eq!(tenant_from_subject("events.*", EVENTS_SUBJECT_PREFIX, CAP), Err(TenantError::Characters));
    assert_eq!(
        tenant_from_subject("events.a b", EVENTS_SUBJECT_PREFIX, CAP),
        Err(TenantError::Characters)
    );
    Ok(())
}
