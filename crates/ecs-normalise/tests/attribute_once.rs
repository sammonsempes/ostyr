#[path = "common/types.rs"]
mod types;


use ecs_normalise::error::{SysmonError, WinSecError};
use ecs_normalise::sysmon_input::parse_event;
use ecs_normalise::winsec::normalise_security;
use std::error::Error;
use types::TestResult;


const VALID: &str = include_str!("fixtures/winsec_4625.xml");


const EVENT_ID: u32 = 4625;


fn sysmon_error(text: &str) -> Result<SysmonError, Box<dyn Error>> {
    match parse_event(text) {
        Ok(_) => Err(format!("expected an error for {text}").into()),
        Err(error) => Ok(error),
    }
}


#[test]
fn a_prefixed_provider_name_is_refused() -> TestResult {
    let text = VALID.replace(
        r#"<Provider Name="Microsoft-Windows-Security-Auditing""#,
        r#"<Provider Name="Evil" x:Name="Microsoft-Windows-Security-Auditing""#,
    );
    assert!(matches!(sysmon_error(&text)?, SysmonError::PrefixedAttribute(_)));
    assert!(matches!(
        normalise_security(&text),
        Err(WinSecError::Event(SysmonError::PrefixedAttribute(_)))
    ));
    Ok(())
}


#[test]
fn a_prefixed_system_time_is_refused() -> TestResult {
    let text = VALID.replace(
        r#"<TimeCreated SystemTime="2026-11-03T10:00:00.1234567Z""#,
        r#"<TimeCreated SystemTime="2026-11-03T10:00:00Z" y:SystemTime="2030-01-01T00:00:00Z""#,
    );
    assert!(matches!(sysmon_error(&text)?, SysmonError::PrefixedAttribute(_)));
    Ok(())
}


#[test]
fn a_prefixed_data_name_is_refused() -> TestResult {
    let text = VALID.replace(
        r#"<Data Name="TargetUserName">"#,
        r#"<Data Name="TargetUserName" x:Name="SubjectUserName">"#,
    );
    assert!(matches!(sysmon_error(&text)?, SysmonError::PrefixedAttribute(_)));
    Ok(())
}


#[test]
fn an_event_truncated_at_every_offset_is_never_accepted() -> TestResult {
    let accepted = (0..VALID.trim_end().len())
        .filter(|end| VALID.is_char_boundary(*end))
        .filter(|end| VALID.get(..*end).is_some_and(|cut| parse_event(cut).is_ok()))
        .count();
    assert_eq!(accepted, 0);
    Ok(())
}


#[test]
fn a_4625_cut_after_a_data_element_is_truncated() -> TestResult {
    let cut = VALID.split("<Data Name=\"Status\">").next().ok_or("no split")?;
    assert!(matches!(sysmon_error(cut)?, SysmonError::Truncated));
    assert!(matches!(normalise_security(cut), Err(WinSecError::Event(SysmonError::Truncated))));
    Ok(())
}


#[test]
fn an_event_id_is_ascii_digits_only() -> TestResult {
    let plus = VALID.replace("<EventID>4625<", "<EventID>+4625<");
    assert!(matches!(sysmon_error(&plus)?, SysmonError::BadEventId(_)));
    let padded = VALID.replace("<EventID>4625<", "<EventID> 4625 <");
    assert_eq!(parse_event(&padded)?.event_id, EVENT_ID);
    Ok(())
}
