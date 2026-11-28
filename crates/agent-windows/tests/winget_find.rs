#[path = "common/types.rs"]
mod types;


use agent_windows::winget_find::{finding_name, highest, locate_in, locate_with, parse_version, Entry, FindError, MAX_WINDOWSAPPS_ENTRIES};
use std::io;
use std::path::Path;
use types::TestResult;


const PARENT: &str = r"C:\Program Files\WindowsApps";


const INSTALLER: &str = "Microsoft.DesktopAppInstaller";


const VCLIBS: &str = "Microsoft.VCLibs.140.00.UWPDesktop";


const FOUR_PARTS: [u16; 4] = [1, 2, 3, 4];


const TAIL: &str = "_x64__8wekyb3d8bbwe";


fn directory(name: &str) -> Entry {
    Entry {
        name: name.to_owned(),
        directory: true,
    }
}


fn versioned(prefix: &str, version: &str) -> Entry {
    directory(&format!("{prefix}_{version}{TAIL}"))
}


fn empty_list(_: &Path) -> io::Result<Vec<Entry>> {
    Ok(Vec::new())
}


fn failing_list(_: &Path) -> io::Result<Vec<Entry>> {
    Err(io::Error::from(io::ErrorKind::PermissionDenied))
}


fn two_installers(_: &Path) -> io::Result<Vec<Entry>> {
    Ok(vec![
        versioned(INSTALLER, "1.6.10121.0"),
        versioned(VCLIBS, "14.0.33519.0"),
        directory("Microsoft.DesktopAppInstaller_1.6.10121.0_neutral_~_8wekyb3d8bbwe"),
    ])
}


#[test]
fn version_one_ten_is_above_one_nine_by_number_not_by_text() -> TestResult {
    let entries = vec![
        versioned(INSTALLER, "1.9.0.0"),
        versioned(INSTALLER, "1.10.0.0"),
        versioned(INSTALLER, "1.2.0.0"),
    ];
    assert_eq!(
        highest(&entries, INSTALLER),
        Some("Microsoft.DesktopAppInstaller_1.10.0.0_x64__8wekyb3d8bbwe")
    );
    Ok(())
}


#[test]
fn only_the_build_architecture_a_directory_and_a_strict_version_match() -> TestResult {
    let file = Entry {
        name: format!("{INSTALLER}_9.9.9.9{TAIL}"),
        directory: false,
    };
    let entries = vec![
        file,
        directory(&format!("{INSTALLER}_9.9.9.9_arm64__8wekyb3d8bbwe")),
        directory("Microsoft.DesktopAppInstaller_9.9.9.9_neutral_~_8wekyb3d8bbwe"),
        directory(&format!("{INSTALLER}_9.9.9{TAIL}")),
        directory(&format!("{INSTALLER}_9.9.9.9.9{TAIL}")),
        directory(&format!("{INSTALLER}_9.9.9.65536{TAIL}")),
        directory(&format!("{INSTALLER}_+9.9.9.9{TAIL}")),
        directory(&format!("{INSTALLER}_09.9.9.9{TAIL}")),
        directory(&format!("{INSTALLER}_9.9..9{TAIL}")),
        directory(&format!("{INSTALLER}9.9.9.9{TAIL}")),
        directory(&format!("{INSTALLER}_x.9.9.9{TAIL}")),
        directory(&format!("{INSTALLER}_123456.9.9.9{TAIL}")),
        directory("Other_9.9.9.9_x64__8wekyb3d8bbwe"),
        versioned(INSTALLER, "1.0.0.0"),
    ];
    assert_eq!(
        highest(&entries, INSTALLER),
        Some("Microsoft.DesktopAppInstaller_1.0.0.0_x64__8wekyb3d8bbwe")
    );
    let first = entries.get(..1).ok_or("no first entry")?;
    assert_eq!(highest(first, INSTALLER), None);
    Ok(())
}


#[test]
fn a_version_has_four_plain_parts() -> TestResult {
    assert_eq!(parse_version("1.2.3.4"), Some(FOUR_PARTS));
    assert_eq!(parse_version("0.0.0.0"), Some([0, 0, 0, 0]));
    assert_eq!(parse_version("1.2.3"), None);
    assert_eq!(parse_version("1.2.3.-4"), None);
    Ok(())
}


#[test]
fn the_program_and_the_vclibs_directory_come_from_the_highest_directories() -> TestResult {
    let entries = vec![
        versioned(INSTALLER, "1.6.10121.0"),
        versioned(INSTALLER, "1.7.0.0"),
        versioned(VCLIBS, "14.0.33519.0"),
        versioned(VCLIBS, "14.0.30704.0"),
    ];
    let found = locate_in(PARENT, &entries)?;
    assert_eq!(found.winget, format!(r"{PARENT}\{INSTALLER}_1.7.0.0{TAIL}\winget.exe"));
    assert_eq!(found.vclibs_dir, format!(r"{PARENT}\{VCLIBS}_14.0.33519.0{TAIL}"));
    Ok(())
}


#[test]
fn a_parent_without_a_match_is_named_not_found() -> TestResult {
    let only_vclibs = vec![versioned(VCLIBS, "14.0.33519.0")];
    let only_installer = vec![versioned(INSTALLER, "1.6.10121.0")];
    assert!(matches!(locate_in(PARENT, &[]), Err(FindError::NotFound)));
    assert!(matches!(locate_in(PARENT, &only_vclibs), Err(FindError::NotFound)));
    assert!(matches!(locate_in(PARENT, &only_installer), Err(FindError::NotFound)));
    assert!(matches!(locate_with(PARENT, empty_list), Err(FindError::NotFound)));
    Ok(())
}


#[test]
fn more_entries_than_the_bound_is_named_too_large() -> TestResult {
    let entries: Vec<Entry> = (0..=MAX_WINDOWSAPPS_ENTRIES).map(|index| directory(&format!("entry{index}"))).collect();
    assert!(matches!(locate_in(PARENT, &entries), Err(FindError::TooLarge)));
    let at_bound: Vec<Entry> = entries.into_iter().take(MAX_WINDOWSAPPS_ENTRIES).collect();
    assert!(matches!(locate_in(PARENT, &at_bound), Err(FindError::NotFound)));
    Ok(())
}


#[test]
fn an_unreadable_parent_is_named_and_the_names_are_fixed() -> TestResult {
    let error = locate_with(PARENT, failing_list).err().ok_or("expected an error")?;
    assert_eq!(finding_name(&error), "windowsapps_unreadable");
    assert_eq!(finding_name(&FindError::TooLarge), "windowsapps_too_large");
    assert_eq!(finding_name(&FindError::NotFound), "winget_not_found");
    assert!(locate_with(PARENT, two_installers).is_ok());
    Ok(())
}
