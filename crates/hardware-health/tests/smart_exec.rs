#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use hardware_health::model::FailureClass;
use hardware_health::smart_exec::{check_program, check_program_as, distrust, split_program};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use types::TestResult;


const OWNER: u32 = 1000;


const EXECUTABLE: u32 = 0o755;


const GROUP_WRITABLE: u32 = 0o775;


const OTHER_WRITABLE_FILE: u32 = 0o757;


const REGULAR_MODE: u32 = 0o100_755;


const GROUP_WRITE: u32 = 0o020;


const OTHER_WRITE: u32 = 0o002;


fn scratch() -> Result<tempfile::TempDir, std::io::Error> {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))
}


fn program(dir: &Path, mode: u32) -> Result<PathBuf, std::io::Error> {
    let path = dir.join("smartctl");
    fs::write(&path, "#!/bin/sh\n")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    Ok(path)
}


#[test]
fn a_root_or_caller_owned_closed_program_is_accepted() -> TestResult {
    let dir = scratch()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(EXECUTABLE))?;
    let path = program(dir.path(), EXECUTABLE)?;
    assert_eq!(check_program(&path), Ok(()));
    Ok(())
}


#[test]
fn paths_that_are_not_plain_absolute_names_are_refused() -> TestResult {
    let not_text = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/\xff"));
    assert_eq!(check_program(not_text), Err(FailureClass::ProgramRefused));
    for text in ["smartctl", "./smartctl", "/usr/../tmp/x", "/usr/./x", "/usr//x", "/usr/sbin/", "/", ""] {
        assert_eq!(check_program(Path::new(text)), Err(FailureClass::ProgramRefused), "{text}");
    }
    assert!(split_program(Path::new("/a/b")).is_some());
    Ok(())
}


#[test]
fn a_writable_directory_a_link_or_a_missing_file_is_refused() -> TestResult {
    let dir = scratch()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(EXECUTABLE))?;
    let path = program(dir.path(), EXECUTABLE)?;
    let link = dir.path().join("link");
    symlink(&path, &link)?;
    assert_eq!(check_program(&link), Err(FailureClass::ProgramRefused));
    assert_eq!(check_program(&dir.path().join("missing")), Err(FailureClass::ProgramRefused));
    assert_eq!(check_program(dir.path()), Err(FailureClass::ProgramRefused));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert_eq!(check_program(&path), Err(FailureClass::ProgramRefused));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(EXECUTABLE))?;
    let other = program(dir.path(), OTHER_WRITABLE_FILE)?;
    assert_eq!(check_program(&other), Err(FailureClass::ProgramRefused));
    let linked_dir = scratch()?;
    let alias = linked_dir.path().join("alias");
    symlink(dir.path(), &alias)?;
    assert_eq!(check_program(&alias.join("smartctl")), Err(FailureClass::ProgramRefused));
    Ok(())
}


#[test]
fn a_directory_of_another_user_is_refused() -> TestResult {
    let dir = scratch()?;
    let path = program(dir.path(), EXECUTABLE)?;
    assert_eq!(check_program_as(&path, OWNER), Err(FailureClass::ProgramRefused));
    Ok(())
}


#[test]
fn the_file_judgement_names_each_reason() -> TestResult {
    assert_eq!(distrust(true, 0, REGULAR_MODE, OWNER), None);
    assert_eq!(distrust(true, OWNER, REGULAR_MODE, OWNER), None);
    assert!(distrust(false, 0, REGULAR_MODE, OWNER).is_some());
    assert!(distrust(true, OWNER + 1, REGULAR_MODE, OWNER).is_some());
    assert!(distrust(true, 0, REGULAR_MODE | GROUP_WRITE, OWNER).is_some());
    assert!(distrust(true, 0, REGULAR_MODE | OTHER_WRITE, OWNER).is_some());
    Ok(())
}
