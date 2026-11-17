#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use core_config::trusted_dir::{check_trusted_path, open_trusted_dir, TrustedDirError};
use rustix::fs::fstat;
use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::{chown, symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use types::TestResult;


const PRIVATE_MODE: u32 = 0o700;


const GROUP_WRITABLE: u32 = 0o775;


const ALL_WRITABLE: u32 = 0o777;


const STICKY_WRITABLE: u32 = 0o1777;


const NORMAL_DIR: u32 = 0o755;


const OTHER_OWNER_OFFSET: u32 = 4242;


struct Env {
    root: TempDir,
    work: PathBuf,
}


fn setup() -> Result<Env, Box<dyn Error>> {
    let root = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let work = root.path().join("work");
    fs::create_dir(&work)?;
    fs::set_permissions(&work, fs::Permissions::from_mode(PRIVATE_MODE))?;
    Ok(Env { root, work })
}


fn owner() -> u32 {
    rustix::process::geteuid().as_raw()
}


fn refusal(path: &Path, uid: u32) -> Result<TrustedDirError, Box<dyn Error>> {
    open_trusted_dir(path, uid).err().ok_or_else(|| "the directory was accepted".into())
}


struct Restore {
    path: PathBuf,
    uid: u32,
}


impl Drop for Restore {
    fn drop(&mut self) {
        assert!(chown(&self.path, Some(self.uid), None).is_ok());
    }
}


#[test]
fn a_private_directory_of_the_caller_is_opened_and_the_handle_is_that_directory() -> TestResult {
    let env = setup()?;
    let handle = open_trusted_dir(&env.work, owner())?;
    assert_eq!(fstat(&handle)?.st_ino, fs::metadata(&env.work)?.ino());
    Ok(())
}


#[test]
fn a_path_that_is_not_plain_is_refused_before_anything_is_opened() -> TestResult {
    let env = setup()?;
    assert!(matches!(
        refusal(Path::new("relative/work"), owner())?,
        TrustedDirError::Refused("work directory is not absolute")
    ));
    assert!(matches!(
        refusal(&env.work.join("../work"), owner())?,
        TrustedDirError::Refused("work directory has a component other than a name")
    ));
    assert!(check_trusted_path(&env.work).is_ok());
    Ok(())
}


#[test]
fn the_directory_itself_must_be_the_callers_and_closed_to_group_and_others() -> TestResult {
    let env = setup()?;
    assert!(matches!(
        refusal(&env.work, owner() + 1)?,
        TrustedDirError::Refused("work directory is not owned by the caller")
    ));
    fs::set_permissions(&env.work, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert!(matches!(
        refusal(&env.work, owner())?,
        TrustedDirError::Refused("work directory is writable by group or others")
    ));
    Ok(())
}


#[test]
fn a_missing_directory_and_a_symlink_are_io_errors_never_followed() -> TestResult {
    let env = setup()?;
    let kind = |error: TrustedDirError| match error {
        TrustedDirError::Io(source) => Ok(source.kind()),
        other => Err(other),
    };
    assert_eq!(kind(refusal(&env.root.path().join("missing"), owner())?)?, io::ErrorKind::NotFound);
    let link = env.root.path().join("work-link");
    symlink(&env.work, &link)?;
    assert!(matches!(refusal(&link, owner())?, TrustedDirError::Io(_)));
    let linked_parent = env.root.path().join("parent-link");
    symlink(env.root.path(), &linked_parent)?;
    assert!(matches!(refusal(&linked_parent.join("work"), owner())?, TrustedDirError::Io(_)));
    Ok(())
}


#[test]
fn every_ancestor_is_checked_and_only_a_sticky_one_may_be_writable() -> TestResult {
    let env = setup()?;
    fs::set_permissions(env.root.path(), fs::Permissions::from_mode(ALL_WRITABLE))?;
    assert!(matches!(
        refusal(&env.work, owner())?,
        TrustedDirError::Refused("work directory ancestor is writable by group or others")
    ));
    fs::set_permissions(env.root.path(), fs::Permissions::from_mode(STICKY_WRITABLE))?;
    assert!(open_trusted_dir(&env.work, owner()).is_ok());
    fs::set_permissions(env.root.path(), fs::Permissions::from_mode(NORMAL_DIR))?;
    let restore = Restore {
        path: env.root.path().to_path_buf(),
        uid: fs::metadata(env.root.path())?.uid(),
    };
    let moved = chown(env.root.path(), Some(owner() + OTHER_OWNER_OFFSET), None).is_ok();
    assert!(matches!(
        refusal(&env.work, owner() + 1)?,
        TrustedDirError::Refused("work directory ancestor is not owned by root or the caller")
    ));
    assert!(moved || owner() != 0);
    drop(restore);
    Ok(())
}


#[test]
fn the_error_texts_name_the_check_and_keep_the_cause() -> TestResult {
    let env = setup()?;
    let refused = refusal(&env.work, owner() + 1)?;
    assert_eq!(
        refused.to_string(),
        "work directory is refused: work directory is not owned by the caller"
    );
    let missing = refusal(&env.root.path().join("missing"), owner())?;
    assert!(missing.to_string().starts_with("work directory cannot be opened: "));
    Ok(())
}
