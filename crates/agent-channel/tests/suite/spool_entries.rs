use crate::harness::long_tempdir;
use crate::spool_append::agent_file;
use crate::types::TestResult;
use agent_channel::error::AppError;
use agent_channel::spool::{suffixed, ASIDE_SUFFIX, QUARANTINE_LOCK_SUFFIX, REJECTED_SUFFIX, SENDING_SUFFIX, TEMPORARY_SUFFIX};
use agent_channel::spool_dirs::{
    accept_any_entries, held_directories, open_spool_dirs_judged, open_spool_dirs_with, platform_entries_judge, spool_entry_paths,
};
use std::fs::File;
use std::path::{Path, PathBuf};
use sys_windows::types::DirAclError;


const LISTED_ENTRIES: usize = 11;


fn accept_directory(_directory: &File, _shown: &Path) -> Result<(), DirAclError> {
    Ok(())
}


fn refuse_directory(_directory: &File, shown: &Path) -> Result<(), DirAclError> {
    Err(DirAclError::NullDacl { path: shown.to_path_buf() })
}


fn refuse_every_entry(paths: &[PathBuf]) -> Result<(), DirAclError> {
    paths
        .first()
        .map_or(Ok(()), |path| Err(DirAclError::NotRegularFile { path: path.clone() }))
}


fn refuse_the_sending_entry(paths: &[PathBuf]) -> Result<(), DirAclError> {
    paths
        .iter()
        .find(|path| path.extension().is_some_and(|extension| extension == "sending"))
        .map_or(Ok(()), |path| Err(DirAclError::NotRegularFile { path: path.clone() }))
}


#[test]
fn every_fixed_name_the_agent_opens_is_listed() -> TestResult {
    let dir = long_tempdir()?;
    let names: Vec<String> = spool_entry_paths(&agent_file(dir.path()))
        .iter()
        .filter_map(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
        .collect();
    let file = agent_file(dir.path());
    let sending = suffixed(&file.spool_file, SENDING_SUFFIX);
    let rejected = suffixed(&file.spool_file, REJECTED_SUFFIX);
    let derived: Vec<PathBuf> = vec![
        file.spool_file.clone(),
        file.sequence_file.clone(),
        suffixed(&file.sequence_file, TEMPORARY_SUFFIX),
        file.executed_file.clone(),
        file.state_file.clone(),
        file.audit_file.clone(),
        suffixed(&sending, TEMPORARY_SUFFIX),
        suffixed(&sending, ASIDE_SUFFIX),
        sending,
        suffixed(&rejected, QUARANTINE_LOCK_SUFFIX),
        rejected,
    ];
    let expected: Vec<String> = derived
        .iter()
        .filter_map(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
        .collect();
    let literal = [
        "spool",
        "sequence",
        "sequence.tmp",
        "executed",
        "state",
        "audit",
        "spool.sending.tmp",
        "spool.sending.old",
        "spool.sending",
        "spool.rejected.lock",
        "spool.rejected",
    ];
    assert_eq!(expected, literal);
    assert_eq!(names, expected);
    assert_eq!(names.len(), LISTED_ENTRIES);
    Ok(())
}


#[test]
fn an_entry_refusal_ends_the_start_and_names_the_entry() -> TestResult {
    let dir = long_tempdir()?;
    let refused = open_spool_dirs_judged(&agent_file(dir.path()), accept_directory, refuse_every_entry);
    assert!(matches!(refused, Err(AppError::SpoolDirAcl(DirAclError::NotRegularFile { .. }))));
    let named = open_spool_dirs_judged(&agent_file(dir.path()), accept_directory, refuse_the_sending_entry);
    assert!(
        matches!(&named, Err(AppError::SpoolDirAcl(DirAclError::NotRegularFile { path })) if path == &dir.path().join("spool.sending")),
        "{named:?}"
    );
    Ok(())
}


#[test]
fn a_directory_refusal_comes_before_the_entries() -> TestResult {
    let dir = long_tempdir()?;
    let refused = open_spool_dirs_judged(&agent_file(dir.path()), refuse_directory, refuse_every_entry);
    assert!(matches!(refused, Err(AppError::SpoolDirAcl(DirAclError::NullDacl { .. }))));
    Ok(())
}


#[test]
fn the_default_entry_judges_accept_entries_that_are_absent() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    assert_eq!(held_directories(&open_spool_dirs_with(&file, accept_directory)?), 1);
    assert!(accept_any_entries(&[]).is_ok());
    assert!(platform_entries_judge(&spool_entry_paths(&file)).is_ok());
    Ok(())
}
