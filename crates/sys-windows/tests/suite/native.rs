use crate::types::TestResult;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use sys_windows::judge::principals_from_token_user;
use sys_windows::native::{judge_directory_handle, read_descriptor, token_user_sid};
use sys_windows::types::DirAclError;
use tempfile::tempdir;


const BACKUP_SEMANTICS: u32 = 0x0200_0000;


#[test]
fn the_process_account_is_a_sid_string() -> TestResult {
    let sid = token_user_sid()?;
    assert!(sid.starts_with("S-1-"), "{sid}");
    principals_from_token_user(&sid)?;
    Ok(())
}


#[test]
fn a_directory_descriptor_is_read_from_its_handle() -> TestResult {
    let dir = tempdir()?;
    let handle = OpenOptions::new().read(true).custom_flags(BACKUP_SEMANTICS).open(dir.path())?;
    let descriptor = read_descriptor(&handle)?;
    assert!(descriptor.owner.starts_with("S-1-"), "{}", descriptor.owner);
    assert!(descriptor.dacl.is_some());
    Ok(())
}


#[test]
fn a_temporary_directory_is_judged_without_failing_to_read() -> TestResult {
    let dir = tempdir()?;
    let handle = OpenOptions::new().read(true).custom_flags(BACKUP_SEMANTICS).open(dir.path())?;
    let verdict = judge_directory_handle(&handle, dir.path());
    assert!(verdict.is_ok() || matches!(verdict, Err(DirAclError::UntrustedAce { .. } | DirAclError::UntrustedOwner { .. })));
    Ok(())
}
