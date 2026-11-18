#[path = "common/types.rs"]
mod types;


use hardware_health::error::SmartError;
use hardware_health::smart_settings::parse_settings;
use std::error::Error;
use std::path::Path;
use types::TestResult;


const DEFAULT_DEADLINE: u64 = 30;


const DEFAULT_ROUND: u64 = 600;


const OVER_SETTINGS: usize = 5000;


#[test]
fn defaults_and_explicit_values() -> TestResult {
    let defaults = parse_settings("{}")?;
    assert_eq!(defaults.program, Path::new("/usr/sbin/smartctl"));
    assert_eq!(defaults.deadline_seconds, DEFAULT_DEADLINE);
    assert_eq!(defaults.round_deadline_seconds, DEFAULT_ROUND);
    let explicit = parse_settings("program: /opt/smartctl\ndeadline_seconds: 120\n")?;
    assert_eq!(explicit.program, Path::new("/opt/smartctl"));
    Ok(())
}


#[test]
fn refused_settings() -> TestResult {
    assert!(matches!(
        parse_settings("program: \"/a\\0b\""),
        Err(SmartError::SettingsField { field: "program" })
    ));
    assert!(matches!(
        parse_settings("program: smartctl"),
        Err(SmartError::SettingsField { field: "program" })
    ));
    assert!(matches!(
        parse_settings("program: ../x"),
        Err(SmartError::SettingsField { field: "program" })
    ));
    assert!(matches!(
        parse_settings("deadline_seconds: 0"),
        Err(SmartError::SettingsField { field: "deadline_seconds" })
    ));
    assert!(matches!(
        parse_settings("round_deadline_seconds: 0"),
        Err(SmartError::SettingsField {
            field: "round_deadline_seconds"
        })
    ));
    assert!(matches!(
        parse_settings("round_deadline_seconds: 3601"),
        Err(SmartError::SettingsField {
            field: "round_deadline_seconds"
        })
    ));
    assert!(matches!(
        parse_settings("deadline_seconds: 121"),
        Err(SmartError::SettingsField { field: "deadline_seconds" })
    ));
    assert!(matches!(
        parse_settings(&"#".repeat(OVER_SETTINGS)),
        Err(SmartError::SettingsTooLarge { .. })
    ));
    let unknown = parse_settings("surprise-MARKER: 1").err().ok_or("accepted")?;
    assert!(matches!(unknown, SmartError::Settings(_)));
    let text = format!("{unknown}{}", unknown.source().map_or_else(String::new, ToString::to_string));
    assert!(!text.contains("MARKER") && !format!("{unknown:?}").contains("MARKER"));
    Ok(())
}
