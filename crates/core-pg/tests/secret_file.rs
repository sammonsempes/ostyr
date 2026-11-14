#![cfg(unix)]

use core_pg::error::PgError;
use core_pg::password::{judge_secret, open_secret_with, read_password};
use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;


const SECRET_MODE: u32 = 0o600;


const FOREIGN_UID: u32 = 65534;


const MODE_400: u32 = 0o400;


const MODE_644: u32 = 0o644;


const MODE_640: u32 = 0o640;


const MODE_604: u32 = 0o604;


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
    assert_eq!(read_password(&path)?.as_slice(), b"s3cret");
    write_with_mode(&path, MODE_400)?;
    assert_eq!(read_password(&path)?.as_slice(), b"s3cret");
    Ok(())
}


#[test]
fn group_or_other_bits_are_refused_naming_the_file() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("pass");
    [MODE_644, MODE_640, MODE_604].iter().try_for_each(|mode| -> Result<(), Box<dyn Error>> {
        write_with_mode(&path, *mode)?;
        let error = read_password(&path).err().ok_or("accepted")?;
        assert!(matches!(error, PgError::SecretMode { .. }));
        assert!(error.to_string().contains(&path.display().to_string()));
        assert!(!error.to_string().contains("s3cret"));
        Ok(())
    })
}


#[test]
fn a_symlink_to_a_private_file_is_refused() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let target = dir.path().join("target");
    let link = dir.path().join("link");
    write_with_mode(&target, SECRET_MODE)?;
    symlink(&target, &link)?;
    assert!(matches!(read_password(&link), Err(PgError::SecretSymlink { .. })));
    Ok(())
}


#[test]
fn a_foreign_owner_is_refused() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("pass");
    write_with_mode(&path, MODE_644)?;
    std::os::unix::fs::chown(&path, Some(FOREIGN_UID), None)?;
    assert!(matches!(read_password(&path), Err(PgError::SecretOwner { .. })));
    Ok(())
}


#[test]
fn a_fifo_is_refused_without_blocking() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("fifo");
    assert!(Command::new("mkfifo").arg(&path).status()?.success());
    assert!(matches!(read_password(&path), Err(PgError::NotRegular { .. })));
    Ok(())
}


#[test]
fn a_missing_secret_is_an_io_error_and_a_failing_inspection_too() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    assert!(matches!(read_password(&dir.path().join("none")), Err(PgError::Io { .. })));
    let path = dir.path().join("pass");
    write_with_mode(&path, SECRET_MODE)?;
    let failing = open_secret_with(&path, |_| Err(io::Error::other("injected")));
    assert!(matches!(failing, Err(PgError::Io { .. })));
    Ok(())
}


#[test]
fn the_judgement_covers_every_branch() -> Result<(), Box<dyn Error>> {
    let judged = |is_file, mode, owner| judge_secret("f", is_file, mode, owner, PROCESS_USER);
    judged(true, SECRET_MODE, PROCESS_USER)?;
    judged(true, SECRET_MODE, ROOT_USER)?;
    assert!(matches!(judged(false, SECRET_MODE, PROCESS_USER), Err(PgError::NotRegular { .. })));
    assert!(matches!(judged(true, MODE_640, PROCESS_USER), Err(PgError::SecretMode { .. })));
    assert!(matches!(judged(true, SECRET_MODE, OTHER_USER), Err(PgError::SecretOwner { .. })));
    Ok(())
}
