#[path = "common/types.rs"]
mod types;


use core_config::error::WatchError;
use core_config::watch::{
    accept_path, after_drive, check_windows_path, is_plain_file_name, is_short_name, names_equal_exact, names_equal_ignoring_case, same_name,
};
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


#[test]
fn windows_rules_refuse_unmatchable_names() -> TestResult {
    [
        "C:\\x\\settings.yaml.",
        "C:\\x\\settings.yaml ",
        "C:\\x\\settings.yaml::$DATA",
        "C:\\x\\settings.yaml:evil",
        "C:\\x\\\u{c9}a.yaml",
        "C:\\x\\a b.yaml",
        "C:\\x\\",
        "C:\\x\\..",
        "\\\\server\\share\\x:y",
        "1:x",
    ]
    .iter()
    .for_each(|path| assert!(check_windows_path(Path::new(path)).is_err(), "{path}"));
    assert!(matches!(
        check_windows_path(Path::new("C:\\a:b\\s.yaml")),
        Err(WatchError::StreamSyntax(_))
    ));
    assert!(matches!(
        check_windows_path(Path::new("C:\\x\\\u{c9}a.yaml")),
        Err(WatchError::FileName(_))
    ));
    let message = check_windows_path(Path::new("C:\\x\\s.yaml.")).map_err(|error| error.to_string());
    assert!(matches!(message, Err(text) if text.contains("ASCII")));
    let stream = check_windows_path(Path::new("C:\\x\\s.yaml:a")).map_err(|error| error.to_string());
    assert!(matches!(stream, Err(text) if text.contains("stream")));
    Ok(())
}


#[test]
fn drive_and_file_name_helpers() -> TestResult {
    assert_eq!(after_drive("C:\\x:y"), "\\x:y");
    assert_eq!(after_drive("\\\\?\\C:\\x"), "\\x");
    assert_eq!(after_drive("\\\\.\\C:\\x"), "\\x");
    assert_eq!(after_drive("1:x"), "1:x");
    assert_eq!(after_drive("\u{e9}:x"), "\u{e9}:x");
    assert_eq!(after_drive("a"), "a");
    assert!(is_plain_file_name("Settings_1-b.yaml"));
    assert!(!is_plain_file_name(""));
    assert!(!is_plain_file_name("a."));
    Ok(())
}
