use crate::types::TestResult;
use core_config::types::SettingsMap;
use platform::error::PlatformError;
use platform::merge::{module_of, modules_of, parse_modules, weights_file_of, MAX_MODULES_CHARS, SETTING_MODULES, SETTING_WEIGHTS_FILE};
use platform::model::Module;
use std::path::PathBuf;


const LONG_VALUE_CHARS: usize = 10_000;


const ALL_MODULES: usize = 8;


const EXPECTED_LIMIT: usize = 128;


const THIRD_INDEX: usize = 2;


#[test]
fn valid_lists_parse_in_order_and_trim() -> TestResult {
    assert_eq!(parse_modules("alerts,cases")?, [Module::Alerts, Module::Cases]);
    assert_eq!(parse_modules(" cases ")?, [Module::Cases]);
    assert_eq!(parse_modules("cmdb, alerts ,cases")?, [Module::Cmdb, Module::Alerts, Module::Cases]);
    assert_eq!(parse_modules("risk")?, [Module::Risk]);
    assert_eq!(parse_modules("hunts")?, [Module::Hunts]);
    assert_eq!(parse_modules(" certificates , oncall")?, [Module::Certificates, Module::Oncall]);
    assert_eq!(module_of("hunts"), Some(Module::Hunts));
    assert_eq!(module_of("certificates"), Some(Module::Certificates));
    assert_eq!(module_of("oncall"), Some(Module::Oncall));
    assert_eq!(module_of("dhcp"), Some(Module::Dhcp));
    assert_eq!(module_of("hunt"), None);
    Ok(())
}


#[test]
fn the_longest_list_fits_the_limit() -> TestResult {
    let all = "alerts, cases, cmdb, risk, hunts, certificates, oncall, dhcp";
    assert!(all.chars().count() <= MAX_MODULES_CHARS);
    assert_eq!(parse_modules(all)?.len(), ALL_MODULES);
    Ok(())
}


#[test]
fn the_limit_is_128_characters_and_129_is_refused() -> TestResult {
    assert_eq!(MAX_MODULES_CHARS, EXPECTED_LIMIT);
    let padded = |width: usize| format!("alerts{}", " ".repeat(width - "alerts".len()));
    assert_eq!(parse_modules(&padded(MAX_MODULES_CHARS))?, [Module::Alerts]);
    assert_eq!(
        parse_modules(&padded(MAX_MODULES_CHARS + 1)),
        Err(PlatformError::ModulesTooLong { limit: MAX_MODULES_CHARS })
    );
    assert_eq!(
        parse_modules("hunts,oncall,hunts"),
        Err(PlatformError::DuplicateModule { index: THIRD_INDEX })
    );
    assert_eq!(parse_modules("hunts,oncalls"), Err(PlatformError::UnknownModule { index: 1 }));
    Ok(())
}


#[test]
fn the_weights_file_is_required_only_with_risk() -> TestResult {
    let mut settings = SettingsMap::new();
    assert_eq!(weights_file_of(&settings, &[Module::Alerts])?, None);
    assert_eq!(
        weights_file_of(&settings, &[Module::Risk, Module::Alerts]),
        Err(PlatformError::MissingWeightsFile)
    );
    assert!(PlatformError::MissingWeightsFile.to_string().contains(SETTING_WEIGHTS_FILE));
    settings.insert(SETTING_WEIGHTS_FILE.to_owned(), "/etc/w.yaml".to_owned());
    assert_eq!(weights_file_of(&settings, &[Module::Risk])?, Some(PathBuf::from("/etc/w.yaml")));
    assert_eq!(weights_file_of(&settings, &[Module::Cmdb])?, None);
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
