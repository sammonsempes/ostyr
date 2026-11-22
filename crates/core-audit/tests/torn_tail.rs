#[path = "support/log_builder.rs"]
mod log_builder;
#[path = "support/sample.rs"]
mod sample;
#[path = "support/types.rs"]
mod types;


use core_audit::error::{AuditError, BrokenReason};
use core_audit::log::open_file_log;
use log_builder::build_log;
use std::fs;
use std::path::Path;
use types::TestResult;


const COMPLETE_RECORDS: usize = 3;


const CUT_POINTS: [usize; 4] = [1, 10, 100, 200];


#[cfg(unix)]
const OWNER_ONLY_MODE: u32 = 0o600;


#[cfg(unix)]
fn owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY_MODE))
}


#[cfg(not(unix))]
fn owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}


#[test]
fn a_log_ending_in_a_torn_record_is_refused_and_left_untouched() -> TestResult {
    let (lines, _) = build_log(COMPLETE_RECORDS + 1)?;
    let complete: String = lines.iter().take(COMPLETE_RECORDS).cloned().collect();
    let torn_line = lines.get(COMPLETE_RECORDS).ok_or("missing record")?;
    let dir = tempfile::tempdir()?;
    CUT_POINTS.iter().try_for_each(|cut| -> TestResult {
        let path = dir.path().join(format!("audit-{cut}.log"));
        let content = format!("{complete}{}", torn_line.get(..*cut).ok_or("cut out of range")?);
        fs::write(&path, &content)?;
        owner_only(&path)?;
        let refused = open_file_log(&path);
        assert!(matches!(
            refused,
            Err(AuditError::Broken {
                line,
                reason: BrokenReason::Unterminated | BrokenReason::Malformed(_)
            }) if line == COMPLETE_RECORDS + 1
        ));
        assert_eq!(fs::read_to_string(&path)?, content);
        Ok(())
    })
}


#[test]
fn a_record_cut_before_its_newline_is_unterminated() -> TestResult {
    let (lines, _) = build_log(COMPLETE_RECORDS)?;
    let full: String = lines.concat();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("audit.log");
    fs::write(&path, full.trim_end_matches('\n'))?;
    owner_only(&path)?;
    assert!(matches!(
        open_file_log(&path),
        Err(AuditError::Broken {
            line: COMPLETE_RECORDS,
            reason: BrokenReason::Unterminated
        })
    ));
    Ok(())
}
