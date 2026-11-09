use crate::common::refusal;
use crate::types::TestResult;
use script_library::error::ScriptError;
use script_library::fsdir::{
    create_private_directory, open_work_root, open_work_root_with, random_name, write_all_into, write_private_file, NAME_ATTEMPTS,
};
use std::io::{self, Write};
use std::os::fd::BorrowedFd;
use std::os::unix::fs::{symlink, PermissionsExt};


pub const MODE_BITS: u32 = 0o777;


pub const FILE_MODE: u32 = 0o600;


pub const DIRECTORY_MODE: u32 = 0o700;


pub const UNSAFE_MODES: [u32; 4] = [0o770, 0o707, STICKY_SHARED, 0o772];


pub const GROUP_WRITABLE: u32 = 0o775;


pub const STICKY_SHARED: u32 = 0o1777;


pub const SECOND_CALL: u32 = 2;


pub const RANDOM_NAME_LENGTH: usize = 7 + 16;


fn owner() -> u32 {
    rustix::process::geteuid().as_raw()
}


fn set_mode(path: &std::path::Path, mode: u32) -> io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}


#[test]
fn the_work_root_must_be_private_to_the_agent_user() -> TestResult {
    let base = tempfile::tempdir()?;
    let root = base.path().join("work");
    std::fs::create_dir(&root)?;
    set_mode(&root, DIRECTORY_MODE)?;
    let opened = open_work_root(&root, owner())?;
    assert_eq!(opened.path, std::fs::canonicalize(&root)?);
    assert!(matches!(
        refusal(open_work_root(&root, owner() + 1).map(drop))?,
        ScriptError::UnsafeWorkRoot
    ));
    let file = base.path().join("file");
    std::fs::write(&file, "x")?;
    assert!(matches!(refusal(open_work_root(&file, owner()).map(drop))?, ScriptError::Io { .. }));
    assert!(matches!(
        refusal(open_work_root(&base.path().join("absent"), owner()).map(drop))?,
        ScriptError::Io { context, .. } if context.contains("work root")
    ));
    UNSAFE_MODES.iter().try_for_each(|mode| -> TestResult {
        set_mode(&root, *mode)?;
        assert!(
            matches!(refusal(open_work_root(&root, owner()).map(drop))?, ScriptError::UnsafeWorkRoot),
            "{mode:o}"
        );
        Ok(())
    })
}


#[test]
fn a_parent_directory_writable_by_others_is_refused_unless_sticky() -> TestResult {
    let base = tempfile::tempdir()?;
    let parent = base.path().join("parent");
    let root = parent.join("work");
    std::fs::create_dir_all(&root)?;
    set_mode(&root, DIRECTORY_MODE)?;
    set_mode(&parent, DIRECTORY_MODE)?;
    open_work_root(&root, owner())?;
    set_mode(&parent, GROUP_WRITABLE)?;
    assert!(matches!(refusal(open_work_root(&root, owner()).map(drop))?, ScriptError::UnsafeWorkRoot));
    set_mode(&parent, STICKY_SHARED)?;
    open_work_root(&root, owner())?;
    set_mode(&parent, DIRECTORY_MODE)?;
    assert!(matches!(
        refusal(open_work_root(&root, owner() + 1).map(drop))?,
        ScriptError::UnsafeWorkRoot
    ));
    Ok(())
}


#[test]
fn a_symlinked_work_root_resolves_to_the_checked_directory() -> TestResult {
    let base = tempfile::tempdir()?;
    let real = base.path().join("real");
    std::fs::create_dir(&real)?;
    set_mode(&real, DIRECTORY_MODE)?;
    symlink(&real, base.path().join("alias"))?;
    let opened = open_work_root(&base.path().join("alias"), owner())?;
    assert_eq!(opened.path, std::fs::canonicalize(&real)?);
    Ok(())
}


#[test]
fn private_files_have_owner_only_modes_and_never_overwrite() -> TestResult {
    let base = tempfile::tempdir()?;
    set_mode(base.path(), DIRECTORY_MODE)?;
    let root = open_work_root(base.path(), owner())?;
    let directory = create_private_directory(&root, &mut random_name)?;
    let path = write_private_file(&directory, "script.sh", b"echo hi\n")?;
    assert_eq!(std::fs::metadata(&path)?.permissions().mode() & MODE_BITS, FILE_MODE);
    assert_eq!(std::fs::metadata(&directory.path)?.permissions().mode() & MODE_BITS, DIRECTORY_MODE);
    assert_eq!(std::fs::read(&path)?, b"echo hi\n");
    assert!(matches!(
        refusal(write_private_file(&directory, "script.sh", b"x"))?,
        ScriptError::Io { context, .. } if context.contains("create")
    ));
    assert!(matches!(
        refusal(write_private_file(&directory, "../escape/x", b"x"))?,
        ScriptError::Io { .. }
    ));
    let kept = directory.path.clone();
    drop(directory);
    assert!(!kept.exists());
    Ok(())
}


#[test]
fn private_directory_names_are_random_retried_and_bounded() -> TestResult {
    let base = tempfile::tempdir()?;
    set_mode(base.path(), DIRECTORY_MODE)?;
    let root = open_work_root(base.path(), owner())?;
    assert_eq!(random_name()?.len(), RANDOM_NAME_LENGTH);
    assert_ne!(random_name()?, random_name()?);
    std::fs::create_dir(root.path.join("taken"))?;
    let mut calls = 0;
    let directory = create_private_directory(&root, &mut || {
        calls += 1;
        Ok(if calls == 1 { "taken" } else { "fresh" }.to_string())
    })?;
    assert!(directory.path.ends_with("fresh"));
    assert_eq!(calls, SECOND_CALL);
    let mut attempts = 0;
    let exhausted = refusal(
        create_private_directory(&root, &mut || {
            attempts += 1;
            Ok("taken".to_string())
        })
        .map(drop),
    )?;
    assert!(matches!(exhausted, ScriptError::Io { context, .. } if context.contains("private script directory")));
    assert_eq!(attempts, NAME_ATTEMPTS);
    let failed = refusal(create_private_directory(&root, &mut || Err(io::Error::other("injected random failure"))).map(drop))?;
    assert!(matches!(failed, ScriptError::Io { .. }));
    let invalid = refusal(create_private_directory(&root, &mut || Ok("a/b/c".to_string())).map(drop))?;
    assert!(matches!(invalid, ScriptError::Io { .. }));
    Ok(())
}


pub struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected write failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn failing_stat(_directory: BorrowedFd<'_>) -> Result<rustix::fs::Stat, rustix::io::Errno> {
    Err(rustix::io::Errno::IO)
}


fn failing_on_the_private_root(directory: BorrowedFd<'_>) -> Result<rustix::fs::Stat, rustix::io::Errno> {
    let stat = rustix::fs::fstat(directory)?;
    if stat.st_mode & MODE_BITS == DIRECTORY_MODE {
        Err(rustix::io::Errno::IO)
    } else {
        Ok(stat)
    }
}


#[test]
fn inspection_failures_keep_their_cause() -> TestResult {
    let base = tempfile::tempdir()?;
    set_mode(base.path(), DIRECTORY_MODE)?;
    assert!(matches!(
        refusal(open_work_root_with(base.path(), owner(), failing_stat).map(drop))?,
        ScriptError::Io { context, .. } if context.contains("parent")
    ));
    assert!(matches!(
        refusal(open_work_root_with(base.path(), owner(), failing_on_the_private_root).map(drop))?,
        ScriptError::Io { context, .. } if context.contains("inspect the work root")
    ));
    assert!(matches!(
        refusal(write_all_into(FailingWriter, b"x"))?,
        ScriptError::Io { context, .. } if context.contains("write")
    ));
    write_all_into(Vec::new(), b"x")?;
    Ok(())
}


#[test]
fn a_private_directory_that_vanished_is_only_logged_on_drop() -> TestResult {
    let base = tempfile::tempdir()?;
    set_mode(base.path(), DIRECTORY_MODE)?;
    let root = open_work_root(base.path(), owner())?;
    let directory = create_private_directory(&root, &mut random_name)?;
    std::fs::remove_dir(&directory.path)?;
    drop(directory);
    Ok(())
}


pub const FOREIGN_UID: u32 = 12345;


fn owned_by_a_stranger(directory: BorrowedFd<'_>) -> Result<rustix::fs::Stat, rustix::io::Errno> {
    let mut stat = rustix::fs::fstat(directory)?;
    stat.st_uid = FOREIGN_UID;
    Ok(stat)
}


#[test]
fn an_ancestor_owned_by_a_stranger_is_refused() -> TestResult {
    let base = tempfile::tempdir()?;
    set_mode(base.path(), DIRECTORY_MODE)?;
    assert!(matches!(
        refusal(open_work_root_with(base.path(), owner(), owned_by_a_stranger).map(drop))?,
        ScriptError::UnsafeWorkRoot
    ));
    Ok(())
}
