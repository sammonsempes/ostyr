#![cfg(unix)]

use core_config::secret_file::{judge_secret, open_secret, open_secret_with, SecretFileError};
use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::{chown, symlink, PermissionsExt};
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;


const SECRET_MODE: u32 = 0o600;


const MODE_400: u32 = 0o400;


const MODE_644: u32 = 0o644;


const MODE_640: u32 = 0o640;


const MODE_604: u32 = 0o604;


const FOREIGN_UID: u32 = 65534;


const PROCESS_USER: u32 = 1000;


const OTHER_USER: u32 = 5;


const ROOT_USER: u32 = 0;


fn write_with_mode(path: &Path, mode: u32) -> io::Result<()> {
    fs::write(path, "s3cret")?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}


#[test]
fn modes_600_and_400_are_accepted() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("pass");
    write_with_mode(&path, SECRET_MODE)?;
    open_secret(&path)?;
    write_with_mode(&path, MODE_400)?;
    open_secret(&path)?;
    Ok(())
}


#[test]
fn group_or_other_bits_are_refused_naming_the_file() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("pass");
    [MODE_644, MODE_640, MODE_604].iter().try_for_each(|mode| -> Result<(), Box<dyn Error>> {
        write_with_mode(&path, *mode)?;
        let error = open_secret(&path).err().ok_or("accepted")?;
        assert!(matches!(error, SecretFileError::Mode { .. }));
        assert!(error.to_string().contains(&path.display().to_string()));
        assert!(!error.to_string().contains("s3cret"));
        Ok(())
    })
}


#[test]
fn a_symlink_a_foreign_owner_and_a_fifo_are_refused() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let target = dir.path().join("target");
    let link = dir.path().join("link");
    write_with_mode(&target, SECRET_MODE)?;
    symlink(&target, &link)?;
    assert!(matches!(open_secret(&link), Err(SecretFileError::Symlink { .. })));
    write_with_mode(&target, MODE_644)?;
    chown(&target, Some(FOREIGN_UID), None)?;
    assert!(matches!(open_secret(&target), Err(SecretFileError::Owner { .. })));
    let fifo = dir.path().join("fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    assert!(matches!(open_secret(&fifo), Err(SecretFileError::NotRegular { .. })));
    Ok(())
}


#[test]
fn a_missing_file_and_a_failing_inspection_are_io_errors() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    assert!(matches!(open_secret(&dir.path().join("none")), Err(SecretFileError::Io { .. })));
    let path = dir.path().join("pass");
    write_with_mode(&path, SECRET_MODE)?;
    let failing = open_secret_with(&path, |_| Err(io::Error::other("injected")));
    assert!(matches!(failing, Err(SecretFileError::Io { .. })));
    Ok(())
}


#[test]
fn the_judgement_covers_every_branch() -> Result<(), Box<dyn Error>> {
    let judged = |is_file, mode, owner| judge_secret("f", is_file, mode, owner, PROCESS_USER);
    judged(true, SECRET_MODE, PROCESS_USER)?;
    judged(true, SECRET_MODE, ROOT_USER)?;
    assert!(matches!(
        judged(false, SECRET_MODE, PROCESS_USER),
        Err(SecretFileError::NotRegular { .. })
    ));
    assert!(matches!(judged(true, MODE_640, PROCESS_USER), Err(SecretFileError::Mode { .. })));
    assert!(matches!(judged(true, SECRET_MODE, OTHER_USER), Err(SecretFileError::Owner { .. })));
    Ok(())
}
