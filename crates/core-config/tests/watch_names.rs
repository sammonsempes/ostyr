#[path = "common/types.rs"]
mod types;


use core_config::error::WatchError;
use core_config::watch::{accept_path, check_windows_path, is_short_name, names_equal_exact, names_equal_ignoring_case, same_name};
use std::ffi::OsStr;
use std::path::Path;
use types::TestResult;


#[test]
fn exact_comparison_is_case_sensitive_and_ignoring_case_is_not() -> TestResult {
    assert!(names_equal_exact(OsStr::new("settings.yaml"), OsStr::new("settings.yaml")));
    assert!(!names_equal_exact(OsStr::new("settings.yaml"), OsStr::new("Settings.yaml")));
    assert!(names_equal_ignoring_case(OsStr::new("settings.yaml"), OsStr::new("Settings.YAML")));
    assert!(!names_equal_ignoring_case(OsStr::new("settings.yaml"), OsStr::new("other.yaml")));
    assert_eq!(same_name(OsStr::new("a"), OsStr::new("A")), cfg!(windows));
    Ok(())
}


#[test]
fn short_names_are_recognised() -> TestResult {
    ["SETTIN~1.YAM", "A~1", "ABCDEF~12.Y", "x~3.", "~1"]
        .iter()
        .for_each(|name| assert!(is_short_name(name), "{name}"));
    [
        "settings.yaml",
        "ABCDEFG~1.YAM",
        "SETTIN~.YAM",
        "SETTIN~1.YAML",
        "SETTIN~1x",
        "plain",
        "a~b~1",
        "",
    ]
    .iter()
    .for_each(|name| assert!(!is_short_name(name), "{name}"));
    Ok(())
}


#[test]
fn windows_rules_accept_full_paths() -> TestResult {
    [
        r"C:\ProgramData\ostyr\settings.yaml",
        "C:/ProgramData/settings.yaml",
        r"\\?\C:\ProgramData\settings.yaml",
        r"\\.\C:\settings.yaml",
        r"\\server\share\settings.yaml",
        "settings.yaml",
        r"conf\settings.yaml",
        "1:x",
    ]
    .iter()
    .try_for_each(|path| check_windows_path(Path::new(path)))?;
    Ok(())
}


#[test]
fn windows_rules_refuse_relative_and_short_forms() -> TestResult {
    ["C:settings.yaml", r"c:x\y", "C:"]
        .iter()
        .for_each(|path| assert!(matches!(check_windows_path(Path::new(path)), Err(WatchError::DriveRelative(_))), "{path}"));
    [r"\x\settings.yaml", "/x/settings.yaml"]
        .iter()
        .for_each(|path| assert!(matches!(check_windows_path(Path::new(path)), Err(WatchError::RootRelative(_))), "{path}"));
    [r"C:\PROGRA~1\ostyr\settings.yaml", r"C:\x\SETTIN~1.YAM", r"\\?\C:\PROGRA~1\s.yaml"]
        .iter()
        .for_each(|path| assert!(matches!(check_windows_path(Path::new(path)), Err(WatchError::ShortName(_))), "{path}"));
    let message = check_windows_path(Path::new("C:x")).map_err(|error| error.to_string());
    assert!(matches!(message, Err(text) if text.contains("C:x")));
    Ok(())
}


#[test]
fn other_platforms_accept_every_path() -> TestResult {
    accept_path(Path::new("C:x"))?;
    accept_path(Path::new("PROGRA~1"))?;
    Ok(())
}
