use crate::types::TestResult;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use sys_windows::judge::principals_from_token_user;
use sys_windows::native::{file_identity, judge_directory_handle, judge_spool_entries, judge_spool_path, read_descriptor, token_user_sid};
use sys_windows::types::DirAclError;
use tempfile::tempdir;


const BACKUP_SEMANTICS: u32 = 0x0200_0000;


const MKLINK_HOST: &str = "cmd";


const MKLINK_RUN: &str = "/c";


fn open_directory(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new().read(true).custom_flags(BACKUP_SEMANTICS).open(path)
}


#[test]
fn a_directory_identity_is_stable_and_differs_between_directories() -> TestResult {
    let first = tempdir()?;
    let second = tempdir()?;
    assert_eq!(
        file_identity(&open_directory(first.path())?)?,
        file_identity(&open_directory(first.path())?)?
    );
    assert_ne!(
        file_identity(&open_directory(first.path())?)?,
        file_identity(&open_directory(second.path())?)?
    );
    Ok(())
}


#[test]
fn a_handle_that_is_not_the_walked_directory_is_refused() -> TestResult {
    let first = tempdir()?;
    let second = tempdir()?;
    let verdict = judge_spool_path(&open_directory(first.path())?, &second.path().join("spool.jsonl"));
    assert!(matches!(verdict, Err(DirAclError::IdentityMismatch { .. })), "{verdict:?}");
    Ok(())
}


#[test]
fn a_missing_or_relative_directory_is_refused_by_the_walk() -> TestResult {
    let dir = tempdir()?;
    let handle = open_directory(dir.path())?;
    let missing = judge_spool_path(&handle, &dir.path().join("absent").join("spool.jsonl"));
    assert!(matches!(missing, Err(DirAclError::Open { .. })), "{missing:?}");
    let relative = judge_spool_path(&handle, std::path::Path::new("spool\\spool.jsonl"));
    assert!(matches!(relative, Err(DirAclError::BadPath { .. })), "{relative:?}");
    Ok(())
}


fn link_directory(link: &std::path::Path, target: &std::path::Path, flag: &str) -> TestResult {
    let status = std::process::Command::new(MKLINK_HOST)
        .args([MKLINK_RUN, "mklink", flag])
        .arg(link)
        .arg(target)
        .status()?;
    assert!(status.success(), "mklink {flag} failed: {status}");
    Ok(())
}


#[test]
fn a_junction_in_the_path_is_refused_at_its_component() -> TestResult {
    let dir = tempdir()?;
    let target = dir.path().join("real");
    std::fs::create_dir(&target)?;
    let handle = open_directory(&target)?;
    let junction = dir.path().join("junction");
    link_directory(&junction, &target, "/J")?;
    let through_junction = judge_spool_path(&handle, &junction.join("spool.jsonl"));
    assert!(
        matches!(&through_junction, Err(DirAclError::ReparsePoint { path }) if path == &junction),
        "{through_junction:?}"
    );
    let inner = dir.path().join("inner");
    std::fs::create_dir(&inner)?;
    link_directory(&inner.join("junction"), &target, "/J")?;
    let deeper = judge_spool_path(&handle, &inner.join("junction").join("spool.jsonl"));
    assert!(
        matches!(&deeper, Err(DirAclError::ReparsePoint { path }) if path == &inner.join("junction")),
        "{deeper:?}"
    );
    Ok(())
}


#[test]
fn an_ancestor_the_user_controls_is_refused_by_name_before_the_spool_directory() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    std::fs::create_dir(&spool)?;
    let file = spool.join("spool.jsonl");
    let verdict = judge_spool_path(&open_directory(&spool)?, &file);
    let named = match &verdict {
        Err(DirAclError::UntrustedAce { path, .. } | DirAclError::UntrustedOwner { path, .. }) => path != &file,
        _ => false,
    };
    assert!(named, "{verdict:?}");
    Ok(())
}


#[test]
fn a_user_temporary_directory_is_judged_from_the_root_without_failing_to_read() -> TestResult {
    let dir = tempdir()?;
    let verdict = judge_spool_path(&open_directory(dir.path())?, &dir.path().join("spool.jsonl"));
    let expected = matches!(
        verdict,
        Ok(()) | Err(DirAclError::UntrustedAce { .. } | DirAclError::UntrustedOwner { .. } | DirAclError::ReparsePoint { .. })
    );
    assert!(expected, "{verdict:?}");
    Ok(())
}


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


#[test]
fn an_absent_entry_is_accepted() -> TestResult {
    let dir = tempdir()?;
    judge_spool_entries(&[dir.path().join("spool.sending")])?;
    judge_spool_entries(&[])?;
    Ok(())
}


#[test]
fn a_directory_at_an_entry_name_is_refused_by_name() -> TestResult {
    let dir = tempdir()?;
    let entry = dir.path().join("spool.sending");
    std::fs::create_dir(&entry)?;
    let verdict = judge_spool_entries(&[dir.path().join("absent"), entry.clone()]);
    assert!(
        matches!(&verdict, Err(DirAclError::NotRegularFile { path }) if path == &entry),
        "{verdict:?}"
    );
    Ok(())
}


#[test]
fn a_junction_at_an_entry_name_is_refused_as_a_reparse_point() -> TestResult {
    let dir = tempdir()?;
    let target = dir.path().join("real");
    std::fs::create_dir(&target)?;
    let entry = dir.path().join("spool.sending");
    link_directory(&entry, &target, "/J")?;
    let verdict = judge_spool_entries(std::slice::from_ref(&entry));
    assert!(
        matches!(&verdict, Err(DirAclError::ReparsePoint { path }) if path == &entry),
        "{verdict:?}"
    );
    Ok(())
}


#[test]
fn a_regular_entry_is_judged_on_its_descriptor() -> TestResult {
    let dir = tempdir()?;
    let entry = dir.path().join("spool");
    std::fs::write(&entry, b"x")?;
    let verdict = judge_spool_entries(&[entry]);
    let expected = matches!(
        verdict,
        Ok(()) | Err(DirAclError::UntrustedAce { .. } | DirAclError::UntrustedOwner { .. })
    );
    assert!(expected, "{verdict:?}");
    Ok(())
}
