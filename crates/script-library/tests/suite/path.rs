use crate::types::TestResult;
use script_library::model::MAX_PATH_LENGTH;
use script_library::path::{absolute_components, is_separator, is_under_prefixes};


fn prefixes(list: &[&str]) -> Vec<String> {
    list.iter().map(|prefix| prefix.to_string()).collect()
}


#[test]
fn separators() -> TestResult {
    assert!(is_separator('/'));
    assert!(is_separator('\\'));
    assert!(!is_separator('a'));
    Ok(())
}


#[test]
fn unix_and_drive_paths_are_split() -> TestResult {
    assert_eq!(absolute_components("/var//log/").ok_or("unix")?, vec!["/", "var", "log"]);
    assert_eq!(absolute_components("C:\\Data\\x").ok_or("drive")?, vec!["C:", "Data", "x"]);
    assert_eq!(absolute_components("d:/").ok_or("drive root")?, vec!["d:"]);
    assert_eq!(absolute_components("/").ok_or("root")?, vec!["/"]);
    Ok(())
}


#[test]
fn refused_forms() -> TestResult {
    let long = format!("/{}", "a".repeat(MAX_PATH_LENGTH));
    let refused = [
        "",
        "relative/path",
        "./x",
        "\\x",
        "\\\\server\\share",
        "//server/share",
        "/\\server\\share",
        "\\/server/share",
        "//tmp/x",
        "/tmp/.. ",
        "/tmp/... /x",
        "/tmp/a./x",
        "/tmp/a /x",
        "/tmp/./x",
        "C:",
        "C:x",
        "1:/x",
        "CC:/x",
        "/a/../b",
        "/a\\..\\b",
        "C:\\a\\..",
        "/a\0b",
        "/a\nb",
        long.as_str(),
    ];
    refused.iter().for_each(|path| assert!(absolute_components(path).is_none(), "{path:?}"));
    Ok(())
}


#[test]
fn unc_lookalikes_are_not_under_prefixes() -> TestResult {
    let allowed = prefixes(&["/tmp"]);
    ["//tmp/share/x", "/\\tmp\\share\\x", "//server/share"]
        .iter()
        .for_each(|path| assert!(!is_under_prefixes(path, &allowed), "{path:?}"));
    Ok(())
}


#[test]
fn prefix_match_is_by_component() -> TestResult {
    let allowed = prefixes(&["/var/log", "C:\\Data"]);
    assert!(is_under_prefixes("/var/log", &allowed));
    assert!(is_under_prefixes("/var/log/app/x.log", &allowed));
    assert!(is_under_prefixes("C:\\Data\\sub", &allowed));
    assert!(!is_under_prefixes("/var/logs/x", &allowed));
    assert!(!is_under_prefixes("/var", &allowed));
    assert!(!is_under_prefixes("/C:/Data/x", &allowed));
    assert!(!is_under_prefixes("/var/log/../etc", &allowed));
    assert!(!is_under_prefixes("/var/log/x", &prefixes(&["relative", "/etc"])));
    assert!(!is_under_prefixes("/var/log/x", &[]));
    Ok(())
}


#[test]
fn windows_device_names_are_refused_in_any_component() -> TestResult {
    let refused = [
        "/var/CON",
        "/var/con",
        "/var/nul.txt",
        "C:\\Data\\Aux.log",
        "/a/COM1/b",
        "/a/lpt9.tar.gz",
        "/prn",
    ];
    refused.iter().try_for_each(|path| -> TestResult {
        assert!(absolute_components(path).is_none(), "{path}");
        Ok(())
    })?;
    let allowed = ["/var/console", "/var/COM10", "/var/com", "/var/.con", "/var/lpt", "/var/nulls.txt"];
    allowed.iter().try_for_each(|path| -> TestResult {
        assert!(absolute_components(path).is_some(), "{path}");
        Ok(())
    })?;
    assert!(!is_under_prefixes("/var/log/CON", &prefixes(&["/var/log"])));
    Ok(())
}


#[test]
fn device_names_with_spaces_streams_and_superscripts_are_refused() -> TestResult {
    let refused = [
        "C:\\x\\nul .txt",
        "C:\\x\\CON .log",
        "C:\\x\\NUL:",
        "/var/nul .txt",
        "/var/nul:stream",
        "/var/COM\u{b9}",
        "/var/com\u{b2}.txt",
        "/var/COM\u{b3}",
        "/var/LPT\u{b9}",
        "/var/LPT\u{b2}",
        "/var/lpt\u{b3}.x",
        "/var/CONIN$",
        "/var/conout$",
        "/var/CLOCK$.txt",
    ];
    refused.iter().try_for_each(|path| -> TestResult {
        assert!(absolute_components(path).is_none(), "{path}");
        Ok(())
    })?;
    assert!(absolute_components("/var/CLOCK").is_some());
    Ok(())
}
