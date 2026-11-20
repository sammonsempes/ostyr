#![cfg(target_os = "linux")]
#[path = "common/types.rs"]
mod types;


use core_config::trusted_program::{open_trusted_program, same_program, TrustedProgramError};
use std::error::Error;
use std::fs;
use std::os::unix::fs::{chown, symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use types::TestResult;


const EXECUTABLE: u32 = 0o755;


const NOT_EXECUTABLE: u32 = 0o644;


const GROUP_WRITABLE: u32 = 0o775;


const OTHER_OWNER: u32 = 4242;


struct Env {
    root: TempDir,
    program: PathBuf,
}


fn setup() -> Result<Env, Box<dyn Error>> {
    let root = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(EXECUTABLE))?;
    let program = root.path().join("tool");
    fs::write(&program, b"#!/bin/true\n")?;
    fs::set_permissions(&program, fs::Permissions::from_mode(EXECUTABLE))?;
    Ok(Env { root, program })
}


fn owner() -> u32 {
    rustix::process::geteuid().as_raw()
}


fn reason(path: &Path, uid: u32) -> Result<&'static str, Box<dyn Error>> {
    match open_trusted_program(path, uid) {
        Err(TrustedProgramError::Refused(text)) => Ok(text),
        _ => Err("the program was not refused".into()),
    }
}


#[test]
fn a_system_program_is_accepted_for_root() -> TestResult {
    let resolved = fs::canonicalize("/usr/bin/true")?;
    assert!(open_trusted_program(&resolved, 0).is_ok());
    Ok(())
}


#[test]
fn a_plain_program_of_the_caller_is_accepted() -> TestResult {
    let env = setup()?;
    assert!(open_trusted_program(&env.program, owner()).is_ok());
    Ok(())
}


#[test]
fn paths_that_are_not_plain_are_refused_with_distinct_reasons() -> TestResult {
    let env = setup()?;
    assert_eq!(reason(Path::new("usr/bin/true"), 0)?, "program path is not absolute");
    assert_eq!(
        reason(&env.root.path().join("../tool"), owner())?,
        "program path has a component other than a name"
    );
    assert_eq!(reason(Path::new("/"), 0)?, "program path has no file name");
    Ok(())
}


#[test]
fn a_path_not_in_canonical_form_is_refused() -> TestResult {
    ["/usr/bin/./true", "/usr/bin/true/.", "/usr/bin/true/", "/usr//bin/true", "/."]
        .iter()
        .try_for_each(|text| {
            assert_eq!(reason(Path::new(text), 0)?, "path is not in canonical form", "{text}");
            Ok::<(), Box<dyn Error>>(())
        })
}


#[test]
fn a_symlink_as_last_component_or_ancestor_is_refused() -> TestResult {
    let env = setup()?;
    let link = env.root.path().join("link");
    symlink(&env.program, &link)?;
    assert_eq!(reason(&link, owner())?, "program is not a regular file");
    let dir_link = env.root.path().join("dirlink");
    symlink(env.root.path(), &dir_link)?;
    assert_eq!(
        reason(&dir_link.join("tool"), owner())?,
        "program path has a symlink or a non-directory component"
    );
    Ok(())
}


#[test]
fn a_program_in_a_sticky_world_writable_directory_is_refused() -> TestResult {
    let dir = tempfile::tempdir_in("/tmp")?;
    let program = dir.path().join("tool");
    fs::write(&program, b"x")?;
    fs::set_permissions(&program, fs::Permissions::from_mode(EXECUTABLE))?;
    assert_eq!(reason(&program, owner())?, "program ancestor is writable by group or others");
    Ok(())
}


#[test]
fn a_group_writable_ancestor_is_refused() -> TestResult {
    let env = setup()?;
    fs::set_permissions(env.root.path(), fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert_eq!(reason(&env.program, owner())?, "program ancestor is writable by group or others");
    Ok(())
}


#[test]
fn an_ancestor_or_file_of_another_owner_is_refused() -> TestResult {
    let env = setup()?;
    chown(&env.program, Some(OTHER_OWNER), None)?;
    assert_eq!(reason(&env.program, owner())?, "program is not owned by root or the trusted user");
    chown(&env.program, Some(0), None)?;
    chown(env.root.path(), Some(OTHER_OWNER), None)?;
    assert_eq!(
        reason(&env.program, owner())?,
        "program ancestor is not owned by root or the trusted user"
    );
    Ok(())
}


#[test]
fn a_directory_a_fifo_and_a_file_without_execute_bit_are_refused() -> TestResult {
    let env = setup()?;
    assert_eq!(reason(env.root.path(), owner())?, "program is not a regular file");
    let fifo = env.root.path().join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(EXECUTABLE),
        0,
    )?;
    assert_eq!(reason(&fifo, owner())?, "program is not a regular file");
    fs::set_permissions(&env.program, fs::Permissions::from_mode(NOT_EXECUTABLE))?;
    assert_eq!(reason(&env.program, owner())?, "program has no owner execute bit");
    Ok(())
}


#[test]
fn a_group_writable_program_is_refused() -> TestResult {
    let env = setup()?;
    fs::set_permissions(&env.program, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert_eq!(reason(&env.program, owner())?, "program is writable by group or others");
    Ok(())
}


#[test]
fn a_missing_program_is_an_io_error_and_a_file_ancestor_is_refused() -> TestResult {
    let env = setup()?;
    let missing = open_trusted_program(&env.root.path().join("none"), owner());
    assert!(matches!(missing, Err(TrustedProgramError::Io(ref source)) if source.kind() == std::io::ErrorKind::NotFound));
    assert_eq!(
        reason(&env.program.join("below"), owner())?,
        "program path has a symlink or a non-directory component"
    );
    Ok(())
}


#[test]
fn same_program_is_false_after_a_rename_swap_and_errors_hold_no_path() -> TestResult {
    let env = setup()?;
    let handle = open_trusted_program(&env.program, owner())?;
    assert!(same_program(&handle, &env.program, owner())?);
    let other = env.root.path().join("other");
    fs::write(&other, b"y")?;
    fs::set_permissions(&other, fs::Permissions::from_mode(EXECUTABLE))?;
    fs::rename(&other, &env.program)?;
    assert!(!same_program(&handle, &env.program, owner())?);
    fs::remove_file(&env.program)?;
    assert!(same_program(&handle, &env.program, owner()).is_err());
    let error = open_trusted_program(&env.root.path().join("none"), owner()).err().ok_or("accepted")?;
    let text = format!("{error} {error:?}");
    assert!(!text.contains(env.root.path().to_string_lossy().as_ref()));
    Ok(())
}
