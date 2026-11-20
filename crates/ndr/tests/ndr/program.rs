use crate::support::{ready, TestResult};
use ndr::error::NdrError;
use ndr::exec::{check_program, check_program_as, check_unchanged, run_with_hook};
use ndr::model::Yr;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};


const MODE_PRIVATE: u32 = 0o700;


const MODE_TRAVERSABLE: u32 = 0o755;


const MODE_PLAIN: u32 = 0o755;


const MODE_NO_EXECUTE: u32 = 0o644;


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


const WRITABLE: &str = "program is writable by group or others";


const DIR_WRITABLE: &str = "program ancestor is writable by group or others";


const SYMLINK: &str = "program path has a symlink or a non-directory component";


const NOT_ABSOLUTE: &str = "program path is not absolute";


const NOT_REGULAR: &str = "program is not a regular file";


const OTHER_OWNER: &str = "program is not owned by root or the trusted user";


const DIR_OTHER_OWNER: &str = "program ancestor is not owned by root or the trusted user";


const CHANGED: &str = "program changed after the check";


pub fn own_dir() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    ready()?;
    Ok(tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(MODE_PRIVATE))
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))?)
}


pub fn private_dir(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(MODE_TRAVERSABLE))?;
    Ok(())
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
    assert_eq!(
        refused(&at(own.path().join("..").join("yr"), own.path())),
        Some("program path has a component other than a name")
    );
    assert_eq!(refused(&at(PathBuf::from("/"), own.path())), Some("program path has no file name"));
    assert_eq!(refused(&at(own.path().to_path_buf(), own.path())), Some(NOT_REGULAR));
    assert_eq!(refused(&at(own.path().join("absent"), own.path())), Some("it does not exist"));
    fs::set_permissions(&plain.program, fs::Permissions::from_mode(MODE_NO_EXECUTE))?;
    assert_eq!(refused(&plain), Some("program has no owner execute bit"));
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
    assert!(matches!(result, Err(NdrError::Program { reason: OTHER_OWNER, .. })));
    Ok(())
}


#[test]
fn a_directory_owned_by_another_user_is_refused() -> TestResult {
    let own = own_dir()?;
    let nested = own.path().join("nested");
    private_dir(&nested)?;
    let plain = plain_program(&nested)?;
    let owner = rustix::process::geteuid().as_raw();
    let _restore = hand_to_nobody(&nested, owner)?;
    assert!(matches!(
        check_program_as(&plain, owner + 1),
        Err(NdrError::Program { reason: DIR_OTHER_OWNER, .. })
    ));
    Ok(())
}


#[test]
fn a_root_owned_program_in_a_directory_others_can_write_is_refused() -> TestResult {
    let own = own_dir()?;
    let shared = own.path().join("shared");
    private_dir(&shared)?;
    let plain = plain_program(&shared)?;
    check_program(&plain)?;
    fs::set_permissions(&shared, fs::Permissions::from_mode(MODE_WORLD_WRITABLE))?;
    assert_eq!(refused(&plain), Some(DIR_WRITABLE));
    fs::set_permissions(&shared, fs::Permissions::from_mode(MODE_GROUP_WRITABLE))?;
    assert_eq!(refused(&plain), Some(DIR_WRITABLE));
    Ok(())
}


#[test]
fn a_symlink_anywhere_in_the_path_is_refused() -> TestResult {
    let own = own_dir()?;
    let real = own.path().join("real");
    private_dir(&real)?;
    let plain = plain_program(&real)?;
    symlink(&real, own.path().join("link"))?;
    symlink(&plain.program, own.path().join("yr-link"))?;
    assert_eq!(refused(&at(own.path().join("link").join("yr"), own.path())), Some(SYMLINK));
    assert_eq!(refused(&at(own.path().join("yr-link"), own.path())), Some(NOT_REGULAR));
    assert_eq!(
        refused(&at(own.path().join(OsStr::from_bytes(b"y\xffr")), own.path())),
        Some("it does not exist")
    );
    Ok(())
}


#[test]
fn a_component_that_cannot_be_opened_is_a_spawn_error() -> TestResult {
    let own = own_dir()?;
    let nul = at(own.path().join(OsStr::from_bytes(b"a\0b")), own.path());
    assert!(matches!(check_program(&nul), Err(NdrError::Spawn(_))));
    Ok(())
}


#[test]
fn a_rename_between_the_check_and_the_guard_is_refused() -> TestResult {
    let own = own_dir()?;
    let plain = plain_program(own.path())?;
    let owner = rustix::process::geteuid().as_raw();
    let handle = check_program_as(&plain, owner)?;
    check_unchanged(&plain, &handle, owner)?;
    fs::rename(&plain.program, own.path().join("moved"))?;
    fs::write(&plain.program, "#!/bin/sh\n")?;
    fs::set_permissions(&plain.program, fs::Permissions::from_mode(MODE_PLAIN))?;
    assert!(matches!(
        check_unchanged(&plain, &handle, owner),
        Err(NdrError::Program { reason: CHANGED, .. })
    ));
    Ok(())
}


fn swap_program(yr: &Yr) {
    let moved = yr.program.with_extension("moved");
    if let Err(error) = fs::rename(&yr.program, moved).and_then(|()| fs::write(&yr.program, "#!/bin/sh\n")) {
        tracing::warn!(error = ?error, "the swap failed");
    }
    if let Err(error) = fs::set_permissions(&yr.program, fs::Permissions::from_mode(MODE_PLAIN)) {
        tracing::warn!(error = ?error, "the swap permissions failed");
    }
}


#[test]
fn a_run_refuses_a_program_swapped_after_the_check() -> TestResult {
    let own = own_dir()?;
    let plain = plain_program(own.path())?;
    let owner = rustix::process::geteuid().as_raw();
    let result = run_with_hook(
        &plain,
        &[],
        1,
        std::time::Duration::from_secs(1),
        ndr::exec::read_bounded,
        (owner, swap_program),
    );
    assert!(matches!(result, Err(NdrError::Program { reason: CHANGED, .. })));
    Ok(())
}


#[test]
fn a_program_that_cannot_be_judged_again_is_refused() -> TestResult {
    let own = own_dir()?;
    let plain = plain_program(own.path())?;
    let owner = rustix::process::geteuid().as_raw();
    let handle = check_program_as(&plain, owner)?;
    fs::remove_file(&plain.program)?;
    assert!(matches!(
        check_unchanged(&plain, &handle, owner),
        Err(NdrError::Program { reason: CHANGED, .. })
    ));
    Ok(())
}


fn leave(_yr: &Yr) {}


#[test]
fn a_run_refuses_a_program_owned_by_another_user() -> TestResult {
    let own = own_dir()?;
    let plain = plain_program(own.path())?;
    let owner = rustix::process::geteuid().as_raw();
    let _restore = hand_to_nobody(&plain.program, owner)?;
    let result = run_with_hook(
        &plain,
        &[],
        1,
        std::time::Duration::from_secs(1),
        ndr::exec::read_bounded,
        (owner + 1, leave),
    );
    assert!(matches!(result, Err(NdrError::Program { reason: OTHER_OWNER, .. })));
    Ok(())
}
