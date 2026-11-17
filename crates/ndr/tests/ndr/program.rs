use crate::support::{ready, TestResult};
use ndr::error::NdrError;
use ndr::exec::{check_program, check_program_as};
use ndr::model::Yr;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};


const MODE_PRIVATE: u32 = 0o700;


const MODE_PLAIN: u32 = 0o644;


const MODE_WORLD_WRITABLE: u32 = 0o777;


const MODE_GROUP_WRITABLE: u32 = 0o775;


const NOBODY: u32 = 65_534;


pub struct OwnerGuard {
    path: PathBuf,
    owner: u32,
}


impl Drop for OwnerGuard {
    fn drop(&mut self) {
        if let Err(error) = rustix::fs::chown(&self.path, Some(rustix::fs::Uid::from_raw(self.owner)), None) {
            tracing::warn!(kind = ?error, "chown back failed");
        }
    }
}


pub fn hand_to_nobody(path: &Path, owner: u32) -> Result<OwnerGuard, Box<dyn std::error::Error>> {
    let guard = OwnerGuard {
        path: path.to_path_buf(),
        owner,
    };
    if owner == 0 {
        rustix::fs::chown(path, Some(rustix::fs::Uid::from_raw(NOBODY)), None)?;
    }
    Ok(guard)
}


const WRITABLE: &str = "it or a directory on its path is writable by group or others";


const SYMLINK: &str = "a path component is a symlink, not a directory or not valid text";


const NOT_ABSOLUTE: &str = "the path is not absolute or holds a .. component";


pub fn own_dir() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    ready()?;
    Ok(tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(MODE_PRIVATE))
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))?)
}


pub fn plain_program(dir: &Path) -> Result<Yr, Box<dyn std::error::Error>> {
    let program = dir.join("yr");
    fs::write(&program, "#!/bin/sh\n")?;
    fs::set_permissions(&program, fs::Permissions::from_mode(MODE_PLAIN))?;
    Ok(Yr {
        program,
        work_dir: dir.to_path_buf(),
    })
}


fn at(program: PathBuf, dir: &Path) -> Yr {
    Yr {
        program,
        work_dir: dir.to_path_buf(),
    }
}


fn refused(yr: &Yr) -> Option<&'static str> {
    match check_program(yr) {
        Err(NdrError::Program { reason, .. }) => Some(reason),
        _ => None,
    }
}


#[test]
fn the_program_must_be_an_absolute_regular_file_nobody_else_can_write() -> TestResult {
    let own = own_dir()?;
    let plain = plain_program(own.path())?;
    check_program(&plain)?;
    assert_eq!(refused(&at(PathBuf::from("Cargo.toml"), own.path())), Some(NOT_ABSOLUTE));
    assert_eq!(refused(&at(own.path().join("..").join("yr"), own.path())), Some(NOT_ABSOLUTE));
    assert_eq!(refused(&at(PathBuf::from("/"), own.path())), Some("it is not a regular file"));
    assert_eq!(refused(&at(own.path().to_path_buf(), own.path())), Some("it is not a regular file"));
    assert_eq!(refused(&at(own.path().join("absent"), own.path())), Some("it does not exist"));
    fs::set_permissions(&plain.program, fs::Permissions::from_mode(MODE_WORLD_WRITABLE))?;
    assert_eq!(refused(&plain), Some(WRITABLE));
    Ok(())
}


#[test]
fn a_program_owned_by_another_user_is_refused() -> TestResult {
    let own = own_dir()?;
    let plain = plain_program(own.path())?;
    let owner = rustix::process::geteuid().as_raw();
    let _restore = hand_to_nobody(&plain.program, owner)?;
    let result = check_program_as(&plain, owner + 1);
    assert!(matches!(
        result,
        Err(NdrError::Program {
            reason: "it or a directory on its path is owned by another user",
            ..
        })
    ));
    Ok(())
}


#[test]
fn a_directory_owned_by_another_user_is_refused() -> TestResult {
    let own = own_dir()?;
    let nested = own.path().join("nested");
    fs::create_dir(&nested)?;
    let plain = plain_program(&nested)?;
    let owner = rustix::process::geteuid().as_raw();
    let _restore = hand_to_nobody(&nested, owner)?;
    assert!(matches!(
        check_program_as(&plain, owner + 1),
        Err(NdrError::Program {
            reason: "it or a directory on its path is owned by another user",
            ..
        })
    ));
    Ok(())
}


#[test]
fn a_root_owned_program_in_a_directory_others_can_write_is_refused() -> TestResult {
    let own = own_dir()?;
    let shared = own.path().join("shared");
    fs::create_dir(&shared)?;
    let plain = plain_program(&shared)?;
    check_program(&plain)?;
    fs::set_permissions(&shared, fs::Permissions::from_mode(MODE_WORLD_WRITABLE))?;
    assert_eq!(refused(&plain), Some(WRITABLE));
    fs::set_permissions(&shared, fs::Permissions::from_mode(MODE_GROUP_WRITABLE))?;
    assert_eq!(refused(&plain), Some(WRITABLE));
    Ok(())
}


#[test]
fn a_symlink_anywhere_in_the_path_is_refused() -> TestResult {
    let own = own_dir()?;
    let real = own.path().join("real");
    fs::create_dir(&real)?;
    let plain = plain_program(&real)?;
    symlink(&real, own.path().join("link"))?;
    symlink(&plain.program, own.path().join("yr-link"))?;
    assert_eq!(refused(&at(own.path().join("link").join("yr"), own.path())), Some(SYMLINK));
    assert_eq!(refused(&at(own.path().join("yr-link"), own.path())), Some(SYMLINK));
    assert_eq!(refused(&at(own.path().join(OsStr::from_bytes(b"y\xffr")), own.path())), Some(SYMLINK));
    Ok(())
}


#[test]
fn a_component_that_cannot_be_opened_is_a_spawn_error() -> TestResult {
    let own = own_dir()?;
    let nul = at(own.path().join(OsStr::from_bytes(b"a\0b")), own.path());
    assert!(matches!(check_program(&nul), Err(NdrError::Spawn(_))));
    Ok(())
}
