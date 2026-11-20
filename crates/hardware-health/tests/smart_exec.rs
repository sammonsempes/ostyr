#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use hardware_health::model::FailureClass;
use hardware_health::smart_exec::{check_program, check_program_as, check_unchanged};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use types::TestResult;


const EXECUTABLE: u32 = 0o755;


const GROUP_WRITABLE: u32 = 0o775;


const OTHER_WRITABLE_FILE: u32 = 0o757;


const NOT_EXECUTABLE: u32 = 0o644;


const NOBODY: u32 = 65_534;


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
    assert!(check_program(&path).is_ok());
    Ok(())
}


#[test]
fn paths_that_are_not_plain_absolute_names_are_refused() -> TestResult {
    let not_text = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/\xff"));
    assert_eq!(check_program(not_text).err(), Some(FailureClass::ProgramRefused));
    for text in ["smartctl", "./smartctl", "/usr/../tmp/x", "/usr/./x", "/usr//x", "/usr/sbin/", "/", ""] {
        assert_eq!(check_program(Path::new(text)).err(), Some(FailureClass::ProgramRefused), "{text}");
    }
    Ok(())
}


#[test]
fn a_writable_directory_a_link_or_a_missing_file_is_refused() -> TestResult {
    let dir = scratch()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(EXECUTABLE))?;
    let path = program(dir.path(), EXECUTABLE)?;
    let link = dir.path().join("link");
    symlink(&path, &link)?;
    assert_eq!(check_program(&link).err(), Some(FailureClass::ProgramRefused));
    assert_eq!(check_program(&dir.path().join("missing")).err(), Some(FailureClass::ProgramRefused));
    assert_eq!(check_program(dir.path()).err(), Some(FailureClass::ProgramRefused));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert_eq!(check_program(&path).err(), Some(FailureClass::ProgramRefused));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(EXECUTABLE))?;
    let other = program(dir.path(), OTHER_WRITABLE_FILE)?;
    assert_eq!(check_program(&other).err(), Some(FailureClass::ProgramRefused));
    let linked_dir = scratch()?;
    let alias = linked_dir.path().join("alias");
    symlink(dir.path(), &alias)?;
    assert_eq!(check_program(&alias.join("smartctl")).err(), Some(FailureClass::ProgramRefused));
    Ok(())
}


fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}


fn hand_to_nobody(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    rustix::fs::chown(path, Some(rustix::fs::Uid::from_raw(NOBODY)), None)?;
    Ok(())
}


#[test]
fn a_directory_or_file_of_another_user_is_refused() -> TestResult {
    let dir = scratch()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(EXECUTABLE))?;
    let path = program(dir.path(), EXECUTABLE)?;
    assert!(check_program_as(&path, euid()).is_ok());
    if euid() == 0 {
        hand_to_nobody(&path)?;
        assert_eq!(check_program_as(&path, 1).err(), Some(FailureClass::ProgramRefused));
        assert!(check_program_as(&path, NOBODY).is_ok());
        hand_to_nobody(dir.path())?;
        assert!(check_program_as(&path, NOBODY).is_ok());
        assert_eq!(check_program_as(&path, 1).err(), Some(FailureClass::ProgramRefused));
    }
    Ok(())
}


#[test]
fn the_production_check_refuses_a_program_owned_by_nobody() -> TestResult {
    let dir = scratch()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(EXECUTABLE))?;
    let path = program(dir.path(), EXECUTABLE)?;
    if euid() == 0 {
        hand_to_nobody(&path)?;
        assert_eq!(check_program(&path).err(), Some(FailureClass::ProgramRefused));
    }
    Ok(())
}


#[test]
fn a_program_without_the_owner_execute_bit_is_refused() -> TestResult {
    let dir = scratch()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(EXECUTABLE))?;
    let path = program(dir.path(), NOT_EXECUTABLE)?;
    assert_eq!(check_program(&path).err(), Some(FailureClass::ProgramRefused));
    Ok(())
}


#[test]
fn a_rename_swap_or_a_removal_is_detected_after_the_check() -> TestResult {
    let dir = scratch()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(EXECUTABLE))?;
    let path = program(dir.path(), EXECUTABLE)?;
    let handle = check_program(&path)?;
    assert_eq!(check_unchanged(&path, &handle, euid()), Ok(()));
    fs::rename(&path, dir.path().join("moved"))?;
    program(dir.path(), EXECUTABLE)?;
    assert_eq!(check_unchanged(&path, &handle, euid()), Err(FailureClass::ProgramRefused));
    fs::remove_file(&path)?;
    assert_eq!(check_unchanged(&path, &handle, euid()), Err(FailureClass::ProgramRefused));
    Ok(())
}
