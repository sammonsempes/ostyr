#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use agent_channel::error::AppError;
use agent_channel::spool_dirs::accept_any_entries;
use agent_windows::serve::{entry_paths, error_line, judged_directory, start_site, StartError};
use core_config::reload::{current_config, reload, ReloadOutcome};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use sys_windows::types::DirAclError;
use tempfile::tempdir;
use types::TestResult;


const OWNER_ONLY: u32 = 0o700;


const GOOD: &str = "audit_file: audit-log\n";


const SEVEN_SECONDS: &str = "audit_file: audit-log\npoll_interval_seconds: 7\n";


const DEFAULT_POLL_SECONDS: u64 = 10;


const CHANGED_POLL_SECONDS: u64 = 7;


const USER_OWNED_MARKER: &str = "user-owned";


struct Site {
    state: PathBuf,
    spool: PathBuf,
}


fn site(root: &Path) -> Result<Site, Box<dyn std::error::Error>> {
    let state = root.join("state");
    let spool_dir = root.join("spool");
    [&state, &spool_dir].iter().try_for_each(|directory| {
        fs::create_dir(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(OWNER_ONLY))
    })?;
    fs::write(state.join("settings.yaml"), GOOD)?;
    Ok(Site {
        state,
        spool: spool_dir.join("spool"),
    })
}


fn is_settings(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "settings.yaml")
}


fn untrusted(path: &Path) -> DirAclError {
    DirAclError::UntrustedOwner {
        path: path.to_path_buf(),
        sid: "S-1-5-21-1".to_owned(),
    }
}


fn refuse_existing_entries(paths: &[PathBuf]) -> Result<(), DirAclError> {
    paths
        .iter()
        .filter(|path| !is_settings(path))
        .find(|path| path.symlink_metadata().is_ok())
        .map_or(Ok(()), |path| Err(untrusted(path)))
}


fn refuse_the_settings_file(paths: &[PathBuf]) -> Result<(), DirAclError> {
    paths.iter().find(|path| is_settings(path)).map_or(Ok(()), |path| Err(untrusted(path)))
}


fn refuse_when_marked(paths: &[PathBuf]) -> Result<(), DirAclError> {
    paths
        .iter()
        .filter(|path| is_settings(path))
        .find(|path| path.with_file_name(USER_OWNED_MARKER).exists())
        .map_or(Ok(()), |path| Err(untrusted(path)))
}


fn refuse_links(paths: &[PathBuf]) -> Result<(), DirAclError> {
    paths
        .iter()
        .find(|path| path.symlink_metadata().is_ok_and(|metadata| metadata.is_symlink()))
        .map_or(Ok(()), |path| Err(DirAclError::ReparsePoint { path: path.clone() }))
}


#[test]
fn the_entry_list_holds_every_fixed_name_the_service_opens() -> TestResult {
    let listed = entry_paths(Path::new("state"), Path::new("spool/spool"), "audit-log");
    let expected: Vec<PathBuf> = [
        "state/settings.yaml",
        "state/audit-log",
        "spool/spool",
        "state/sysmon.cursor",
        "state/sysmon.cursor.tmp",
        "state/security.cursor",
        "state/security.cursor.tmp",
        "spool/spool.sending.tmp",
        "spool/spool.sending.old",
        "spool/spool.sending",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    assert_eq!(listed, expected);
    Ok(())
}


#[test]
fn each_entry_that_exists_and_is_refused_stops_the_start() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path())?;
    let listed = entry_paths(&made.state, &made.spool, "audit-log");
    listed.iter().filter(|path| !is_settings(path)).try_for_each(|path| -> TestResult {
        fs::write(path, "")?;
        let refused = start_site(&made.state, &made.spool, refuse_existing_entries).err();
        assert!(matches!(refused, Some(StartError::Entry(_))), "{path:?}: {refused:?}");
        fs::remove_file(path)?;
        Ok(())
    })?;
    start_site(&made.state, &made.spool, refuse_existing_entries)?;
    Ok(())
}


#[test]
fn a_refused_settings_file_is_refused_before_it_is_read() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path())?;
    let refused = start_site(&made.state, &made.spool, refuse_the_settings_file).err();
    assert!(matches!(refused, Some(StartError::Read(_))), "{refused:?}");
    assert!(!made.state.join("audit-log").exists());
    Ok(())
}


#[test]
fn a_spool_path_that_is_a_link_is_refused_by_name() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path())?;
    std::os::unix::fs::symlink(root.path().join("elsewhere"), &made.spool)?;
    let refused = start_site(&made.state, &made.spool, refuse_links).err().ok_or("accepted")?;
    let line = error_line(&refused);
    assert!(line.starts_with("entry refused"), "{line}");
    assert!(line.contains(&made.spool.display().to_string()), "{line}");
    Ok(())
}


#[test]
fn a_reload_of_a_settings_file_swapped_to_a_refused_owner_keeps_the_old_configuration_and_is_audited() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path())?;
    let started = start_site(&made.state, &made.spool, refuse_when_marked)?;
    fs::write(made.state.join("settings.yaml"), SEVEN_SECONDS)?;
    fs::write(made.state.join(USER_OWNED_MARKER), "")?;
    let outcome = reload(&started.engine);
    assert!(matches!(outcome, ReloadOutcome::Refused { .. }), "{outcome:?}");
    assert_eq!(current_config(&started.engine).poll_interval_seconds, DEFAULT_POLL_SECONDS);
    let audit = fs::read_to_string(made.state.join("audit-log"))?;
    assert!(audit.to_ascii_lowercase().contains("denied"), "{audit}");
    fs::remove_file(made.state.join(USER_OWNED_MARKER))?;
    assert!(matches!(reload(&started.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&started.engine).poll_interval_seconds, CHANGED_POLL_SECONDS);
    Ok(())
}


#[test]
fn an_accepting_judge_leaves_the_reload_alone() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path())?;
    let started = start_site(&made.state, &made.spool, accept_any_entries)?;
    assert!(matches!(reload(&started.engine), ReloadOutcome::Unchanged));
    Ok(())
}


#[test]
fn a_directory_refusal_names_the_path_it_judged() -> TestResult {
    let root = tempdir()?;
    let missing = root.path().join("absent").join("settings.yaml");
    let refused = judged_directory(&missing).err().ok_or("accepted")?;
    assert!(refused.to_string().contains(&missing.display().to_string()), "{refused}");
    Ok(())
}


#[test]
fn a_spool_path_without_a_parent_is_refused() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path())?;
    let refused = start_site(&made.state, Path::new("/"), accept_any_entries).err();
    assert!(matches!(refused, Some(StartError::SpoolDir(_))), "{refused:?}");
    Ok(())
}


#[test]
fn a_cause_the_message_already_holds_is_not_repeated() -> TestResult {
    let acl = DirAclError::NullDacl {
        path: PathBuf::from("C:\\state"),
    };
    let refused = StartError::StateDir(AppError::SpoolDirAcl(acl));
    let line = error_line(&refused);
    assert_eq!(line.matches("NULL DACL").count(), 1, "{line}");
    assert!(line.starts_with("state directory: spool directory ACL refused: "), "{line}");
    Ok(())
}
