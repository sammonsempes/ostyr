use crate::harness::long_tempdir;
use crate::spool_append::agent_file;
use crate::types::TestResult;
use agent_channel::agent_app::AgentFile;
use agent_channel::error::{AppError, SpoolDirReason};
use agent_channel::spool_dirs::{
    held_directories, open_fault, open_parent, open_parent_with, open_spool_dirs, open_spool_dirs_with, parent_directory, spool_dir_fault, SpoolDirs,
};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};


const PRIVATE: u32 = 0o700;


const GROUP_WRITABLE: u32 = 0o775;


const OTHERS_WRITABLE: u32 = 0o757;


const STICKY_WORLD: u32 = 0o1777;


const READABLE: u32 = 0o755;


const STRANGER: u32 = 4242;


const PROCESS: u32 = 1000;


const NOT_A_DIRECTORY: i32 = 20;


const SYMLINK_LOOP: i32 = 40;


const PERMISSION_DENIED: i32 = 13;


const NO_SUCH_FILE: i32 = 2;


const TWO_DIRECTORIES: usize = 2;


fn refusal(result: Result<SpoolDirs, AppError>) -> Option<(PathBuf, SpoolDirReason)> {
    match result {
        Err(AppError::SpoolDir { path, reason }) => Some((path, reason)),
        _ => None,
    }
}


fn reason_of(code: i32) -> Option<SpoolDirReason> {
    match open_fault(Path::new("/spool/file"), io::Error::from_raw_os_error(code)) {
        AppError::SpoolDir { reason, .. } => Some(reason),
        _ => None,
    }
}


fn private_dir(path: &Path) -> TestResult {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE))?;
    Ok(())
}


#[test]
fn the_fault_rule_judges_owner_and_group_other_write() -> TestResult {
    assert_eq!(spool_dir_fault(PROCESS, PROCESS, PRIVATE), None);
    assert_eq!(spool_dir_fault(0, PROCESS, READABLE), None);
    assert_eq!(spool_dir_fault(STRANGER, PROCESS, PRIVATE), Some(SpoolDirReason::WrongOwner));
    assert_eq!(spool_dir_fault(PROCESS, PROCESS, GROUP_WRITABLE), Some(SpoolDirReason::Writable));
    assert_eq!(spool_dir_fault(PROCESS, PROCESS, OTHERS_WRITABLE), Some(SpoolDirReason::Writable));
    assert_eq!(spool_dir_fault(0, PROCESS, STICKY_WORLD), Some(SpoolDirReason::Writable));
    Ok(())
}


#[test]
fn an_open_error_maps_to_a_fixed_reason_or_stays_io() -> TestResult {
    assert_eq!(reason_of(NO_SUCH_FILE), Some(SpoolDirReason::Missing));
    assert_eq!(reason_of(NOT_A_DIRECTORY), Some(SpoolDirReason::NotDirectory));
    assert_eq!(reason_of(SYMLINK_LOOP), Some(SpoolDirReason::NotDirectory));
    assert_eq!(reason_of(PERMISSION_DENIED), None);
    assert!(matches!(
        open_fault(Path::new("/x"), io::Error::from_raw_os_error(PERMISSION_DENIED)),
        AppError::Io(_)
    ));
    Ok(())
}


#[test]
fn every_reason_has_its_own_text() -> TestResult {
    let texts: Vec<String> = [
        SpoolDirReason::Missing,
        SpoolDirReason::NotDirectory,
        SpoolDirReason::WrongOwner,
        SpoolDirReason::Writable,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(texts.iter().collect::<HashSet<_>>().len(), texts.len());
    let error = AppError::SpoolDir {
        path: PathBuf::from("/x/seq"),
        reason: SpoolDirReason::Writable,
    };
    assert!(error.to_string().contains("/x/seq") && error.to_string().contains("group or others"));
    Ok(())
}


#[test]
fn a_bare_name_has_the_current_directory_and_a_root_path_has_none() -> TestResult {
    assert_eq!(parent_directory(Path::new("spool")), Some(Path::new(".")));
    assert_eq!(parent_directory(Path::new("/a/spool")), Some(Path::new("/a")));
    assert_eq!(parent_directory(Path::new("/")), None);
    Ok(())
}


#[test]
fn one_private_directory_is_opened_once_for_all_five_files() -> TestResult {
    let dir = long_tempdir()?;
    let dirs = open_spool_dirs(&agent_file(dir.path()))?;
    assert_eq!(held_directories(&dirs), 1);
    Ok(())
}


#[test]
fn distinct_private_directories_are_each_held() -> TestResult {
    let dir = long_tempdir()?;
    let other = dir.path().join("other");
    private_dir(&other)?;
    let file = AgentFile {
        sequence_file: other.join("sequence"),
        ..agent_file(dir.path())
    };
    assert_eq!(held_directories(&open_spool_dirs(&file)?), TWO_DIRECTORIES);
    Ok(())
}


#[test]
fn a_root_owned_closed_directory_is_accepted() -> TestResult {
    let dir = long_tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(READABLE))?;
    assert_eq!(held_directories(&open_spool_dirs(&agent_file(dir.path()))?), 1);
    Ok(())
}


#[test]
fn a_directory_writable_by_group_or_others_ends_the_start() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    [STICKY_WORLD, GROUP_WRITABLE, OTHERS_WRITABLE].iter().try_for_each(|mode| -> TestResult {
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(*mode))?;
        assert_eq!(refusal(open_spool_dirs(&file)), Some((file.spool_file.clone(), SpoolDirReason::Writable)));
        Ok(())
    })
}


#[test]
fn a_directory_owned_by_another_user_ends_the_start() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    rustix::fs::chownat(
        rustix::fs::CWD,
        dir.path(),
        Some(rustix::fs::Uid::from_raw(STRANGER)),
        None,
        rustix::fs::AtFlags::empty(),
    )?;
    assert_eq!(
        refusal(open_spool_dirs(&file)),
        Some((file.spool_file.clone(), SpoolDirReason::WrongOwner))
    );
    Ok(())
}


#[test]
fn a_symlinked_a_missing_and_a_file_directory_are_refused() -> TestResult {
    let dir = long_tempdir()?;
    let real = dir.path().join("real");
    private_dir(&real)?;
    let link = dir.path().join("link");
    symlink(&real, &link)?;
    let plain = dir.path().join("plain");
    fs::write(&plain, "")?;
    let reason = |parent: &Path| {
        let file = AgentFile {
            spool_file: parent.join("spool"),
            ..agent_file(&real)
        };
        refusal(open_spool_dirs(&file)).map(|found| found.1)
    };
    assert_eq!(reason(&link), Some(SpoolDirReason::NotDirectory));
    assert_eq!(reason(&plain), Some(SpoolDirReason::NotDirectory));
    assert_eq!(reason(&dir.path().join("absent")), Some(SpoolDirReason::Missing));
    Ok(())
}


#[test]
fn a_path_without_a_parent_is_refused() -> TestResult {
    let dir = long_tempdir()?;
    let file = AgentFile {
        spool_file: PathBuf::from("/"),
        ..agent_file(dir.path())
    };
    assert_eq!(refusal(open_spool_dirs(&file)), Some((PathBuf::from("/"), SpoolDirReason::NotDirectory)));
    Ok(())
}


#[test]
fn every_file_of_the_agent_has_its_directory_judged() -> TestResult {
    let dir = long_tempdir()?;
    let open = dir.path().join("open");
    fs::create_dir(&open)?;
    fs::set_permissions(&open, fs::Permissions::from_mode(STICKY_WORLD))?;
    let base = agent_file(dir.path());
    let variants = [
        AgentFile {
            sequence_file: open.join("sequence"),
            ..base.clone()
        },
        AgentFile {
            executed_file: open.join("executed"),
            ..base.clone()
        },
        AgentFile {
            state_file: open.join("state"),
            ..base.clone()
        },
        AgentFile {
            audit_file: open.join("audit"),
            ..base.clone()
        },
    ];
    variants.iter().try_for_each(|file| -> TestResult {
        let found = refusal(open_spool_dirs(file));
        assert_eq!(found.as_ref().map(|item| item.1), Some(SpoolDirReason::Writable));
        assert!(found.is_some_and(|item| item.0.starts_with(&open)));
        Ok(())
    })
}


fn refuse_every_acl(_directory: &fs::File, shown: &Path) -> Result<(), sys_windows::types::DirAclError> {
    Err(sys_windows::types::DirAclError::NullDacl { path: shown.to_path_buf() })
}


#[test]
fn an_acl_refusal_ends_the_start() -> TestResult {
    let dir = long_tempdir()?;
    let result = open_spool_dirs_with(&agent_file(dir.path()), refuse_every_acl);
    assert!(matches!(
        result,
        Err(AppError::SpoolDirAcl(sys_windows::types::DirAclError::NullDacl { .. }))
    ));
    Ok(())
}


#[test]
fn the_parent_judge_is_the_injected_one() -> TestResult {
    let dir = long_tempdir()?;
    let result = open_parent_with(&dir.path().join("audit"), refuse_every_acl);
    assert!(matches!(
        result,
        Err(AppError::SpoolDirAcl(sys_windows::types::DirAclError::NullDacl { .. }))
    ));
    Ok(())
}


#[test]
fn the_parent_of_one_path_is_judged_like_the_spool_directories() -> TestResult {
    let dir = long_tempdir()?;
    open_parent(&dir.path().join("audit"))?;
    let open = dir.path().join("open");
    fs::create_dir(&open)?;
    fs::set_permissions(&open, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    let refused = open_parent(&open.join("audit")).err();
    assert!(matches!(
        refused,
        Some(AppError::SpoolDir {
            reason: SpoolDirReason::Writable,
            ..
        })
    ));
    let link = dir.path().join("link");
    symlink(dir.path(), &link)?;
    let linked = open_parent(&link.join("audit")).err();
    assert!(matches!(
        linked,
        Some(AppError::SpoolDir {
            reason: SpoolDirReason::NotDirectory,
            ..
        })
    ));
    assert!(matches!(
        open_parent(Path::new("/")).err(),
        Some(AppError::SpoolDir {
            reason: SpoolDirReason::NotDirectory,
            ..
        })
    ));
    Ok(())
}
