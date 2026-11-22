use crate::types::TestResult;
use agent_linux::trusted::{
    directory_reason, judge_trusted_file, no_hook, read_trusted_capped, read_trusted_with, DIRECTORY_ANCESTOR_NOT_OWNED, DIRECTORY_NOT_OWNED,
    DIRECTORY_WRITABLE, NOT_OWNED, NOT_REGULAR, PATH_NOT_ABSOLUTE, PATH_NOT_PLAIN, ROOT_UID, SYMLINK, WRITABLE,
};
use core_config::error::ConfigError;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use tempfile::tempdir;


const ALICE: u32 = 1000;


const OTHER: u32 = 65534;


const GOOD_MODE: u32 = 0o100_600;


const READABLE_MODE: u32 = 0o100_644;


const GROUP_WRITABLE: u32 = 0o100_664;


const OTHER_WRITABLE: u32 = 0o100_646;


const CAP: u64 = 1024;


const CLOSED: u32 = 0o600;


const READABLE: u32 = 0o644;


const GROUP_WRITE: u32 = 0o664;


const OTHER_WRITE: u32 = 0o646;


const ALL_WRITE: u32 = 0o666;


const WIDE_DIRECTORY: u32 = 0o777;


const PRIVATE_DIRECTORY: u32 = 0o755;


const BODY: &str = "/root/passwords.txt\t1\t2\n";


fn accept_all(_is_file: bool, _mode: u32, _owner: u32, _process_user: u32) -> Result<(), &'static str> {
    Ok(())
}


fn swap_in(path: &Path) {
    assert!(fs::rename(path.with_file_name("swap"), path).is_ok());
}


fn reason_of(result: Result<Vec<u8>, ConfigError>) -> Result<String, Box<dyn std::error::Error>> {
    match result {
        Err(ConfigError::WatchedFile { reason, .. }) => Ok(reason),
        other => Err(format!("not a named refusal: {other:?}").into()),
    }
}


#[test]
fn the_judgement_wants_a_regular_file_of_root_or_the_agent_not_writable_by_others() -> TestResult {
    assert_eq!(judge_trusted_file(true, GOOD_MODE, ROOT_UID, ROOT_UID), Ok(()));
    assert_eq!(judge_trusted_file(true, READABLE_MODE, ROOT_UID, ROOT_UID), Ok(()));
    assert_eq!(judge_trusted_file(true, READABLE_MODE, ALICE, ALICE), Ok(()));
    assert_eq!(judge_trusted_file(true, READABLE_MODE, ROOT_UID, ALICE), Ok(()));
    assert_eq!(judge_trusted_file(false, GOOD_MODE, ROOT_UID, ROOT_UID), Err(NOT_REGULAR));
    assert_eq!(judge_trusted_file(true, GOOD_MODE, ALICE, ROOT_UID), Err(NOT_OWNED));
    assert_eq!(judge_trusted_file(true, GROUP_WRITABLE, ROOT_UID, ROOT_UID), Err(WRITABLE));
    assert_eq!(judge_trusted_file(true, OTHER_WRITABLE, ROOT_UID, ROOT_UID), Err(WRITABLE));
    Ok(())
}


#[test]
fn a_file_of_root_with_a_closed_mode_is_read() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("planted.tsv");
    fs::write(&path, BODY)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(CLOSED))?;
    assert_eq!(read_trusted_capped(&path, CAP)?, BODY.as_bytes());
    fs::set_permissions(&path, fs::Permissions::from_mode(READABLE))?;
    assert_eq!(read_trusted_capped(&path, CAP)?, BODY.as_bytes());
    Ok(())
}


#[test]
fn a_file_owned_by_another_user_is_refused_by_name() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("planted.tsv");
    fs::write(&path, BODY)?;
    std::os::unix::fs::chown(&path, Some(OTHER), None)?;
    assert_eq!(reason_of(read_trusted_capped(&path, CAP))?, NOT_OWNED);
    Ok(())
}


#[test]
fn a_file_writable_by_group_or_other_is_refused_by_name() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("planted.tsv");
    fs::write(&path, BODY)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(GROUP_WRITE))?;
    assert_eq!(reason_of(read_trusted_capped(&path, CAP))?, WRITABLE);
    fs::set_permissions(&path, fs::Permissions::from_mode(OTHER_WRITE))?;
    assert_eq!(reason_of(read_trusted_capped(&path, CAP))?, WRITABLE);
    Ok(())
}


#[test]
fn a_directory_another_user_can_write_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("planted.tsv");
    fs::write(&path, BODY)?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(WIDE_DIRECTORY))?;
    assert!(reason_of(read_trusted_capped(&path, CAP))?.contains("writable"));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(PRIVATE_DIRECTORY))?;
    std::os::unix::fs::chown(dir.path(), Some(OTHER), None)?;
    assert!(reason_of(read_trusted_capped(&path, CAP))?.contains("not owned"));
    Ok(())
}


#[test]
fn a_symlink_a_fifo_a_missing_file_and_a_bad_path_are_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("planted.tsv");
    assert!(matches!(read_trusted_capped(&path, CAP), Err(ConfigError::Io { .. })));
    assert!(matches!(
        read_trusted_capped(&dir.path().join("no/planted.tsv"), CAP),
        Err(ConfigError::Io { .. })
    ));
    symlink("/etc/hostname", &path)?;
    assert_eq!(reason_of(read_trusted_capped(&path, CAP))?, SYMLINK);
    fs::remove_file(&path)?;
    assert!(std::process::Command::new("mkfifo").arg(&path).status()?.success());
    assert_eq!(reason_of(read_trusted_capped(&path, CAP))?, NOT_REGULAR);
    assert!(reason_of(read_trusted_capped(Path::new("/"), CAP))?.contains("no directory"));
    assert!(reason_of(read_trusted_capped(Path::new("planted.tsv"), CAP))?.contains("not absolute"));
    Ok(())
}


#[test]
fn a_file_over_the_cap_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("planted.tsv");
    fs::write(&path, BODY)?;
    assert!(matches!(read_trusted_capped(&path, 1), Err(ConfigError::TooLarge { .. })));
    Ok(())
}


#[test]
fn a_read_failure_keeps_its_cause() -> TestResult {
    let dir = tempdir()?;
    fs::create_dir(dir.path().join("sub"))?;
    let result = read_trusted_with(&dir.path().join("sub"), CAP, accept_all, no_hook);
    assert!(matches!(result, Err(ConfigError::Io { .. })), "{result:?}");
    Ok(())
}


#[test]
fn the_judgement_is_made_on_the_opened_handle_not_on_the_path() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("planted.tsv");
    fs::write(&path, BODY)?;
    fs::write(dir.path().join("swap"), "/etc/passwd\t1\t2\n")?;
    fs::set_permissions(dir.path().join("swap"), fs::Permissions::from_mode(ALL_WRITE))?;
    assert_eq!(read_trusted_with(&path, CAP, judge_trusted_file, swap_in)?, BODY.as_bytes());
    assert_eq!(fs::read(&path)?, b"/etc/passwd\t1\t2\n");
    Ok(())
}


#[test]
fn a_bad_handle_is_refused_even_when_the_path_is_swapped_for_a_good_file() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("planted.tsv");
    fs::write(&path, BODY)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(ALL_WRITE))?;
    fs::write(dir.path().join("swap"), BODY)?;
    assert_eq!(reason_of(read_trusted_with(&path, CAP, judge_trusted_file, swap_in))?, WRITABLE);
    Ok(())
}


#[test]
fn a_directory_refusal_is_worded_about_the_directory_of_the_file() -> TestResult {
    assert_eq!(
        directory_reason("work directory ancestor is not owned by root or the caller"),
        DIRECTORY_ANCESTOR_NOT_OWNED
    );
    assert_eq!(directory_reason("work directory is not owned by the caller"), DIRECTORY_NOT_OWNED);
    assert_eq!(
        directory_reason("work directory ancestor is writable by group or others"),
        DIRECTORY_WRITABLE
    );
    assert_eq!(directory_reason("work directory is not absolute"), PATH_NOT_ABSOLUTE);
    assert_eq!(directory_reason("path is not in canonical form"), PATH_NOT_PLAIN);
    Ok(())
}
