use crate::types::TestResult;
use core_config::types::SettingsMap;
use platform::error::PlatformError;
use platform::merge::{modules_of, parse_modules, MAX_MODULES_CHARS, SETTING_MODULES};
use platform::model::Module;


const LONG_VALUE_CHARS: usize = 10_000;


#[test]
fn valid_lists_parse_in_order_and_trim() -> TestResult {
    assert_eq!(parse_modules("alerts,cases")?, [Module::Alerts, Module::Cases]);
    assert_eq!(parse_modules(" cases ")?, [Module::Cases]);
    assert_eq!(parse_modules("cmdb, alerts ,cases")?, [Module::Cmdb, Module::Alerts, Module::Cases]);
    Ok(())
}


#[test]
fn bad_lists_name_the_entry_index() -> TestResult {
    assert_eq!(parse_modules("alerts,alerts"), Err(PlatformError::DuplicateModule { index: 1 }));
    assert_eq!(parse_modules("x"), Err(PlatformError::UnknownModule { index: 0 }));
    assert_eq!(parse_modules("alerts,,cases"), Err(PlatformError::UnknownModule { index: 1 }));
    assert_eq!(parse_modules("alerts,"), Err(PlatformError::UnknownModule { index: 1 }));
    assert_eq!(parse_modules(""), Err(PlatformError::EmptyModules));
    assert_eq!(parse_modules("  "), Err(PlatformError::EmptyModules));
    Ok(())
}


#[test]
fn a_long_value_is_refused_without_an_echo() -> TestResult {
    let value = "z".repeat(LONG_VALUE_CHARS);
    let error = parse_modules(&value).err().ok_or("accepted")?;
    assert_eq!(error, PlatformError::ModulesTooLong { limit: MAX_MODULES_CHARS });
    assert!(!error.to_string().contains("zzz"));
    let edge = "a".repeat(MAX_MODULES_CHARS);
    assert_eq!(parse_modules(&edge), Err(PlatformError::UnknownModule { index: 0 }));
    Ok(())
}


#[test]
fn the_setting_is_required() -> TestResult {
    let mut settings = SettingsMap::new();
    assert_eq!(modules_of(&settings), Err(PlatformError::MissingModules));
    settings.insert(SETTING_MODULES.to_owned(), "cmdb".to_owned());
    assert_eq!(modules_of(&settings)?, [Module::Cmdb]);
    Ok(())
}
