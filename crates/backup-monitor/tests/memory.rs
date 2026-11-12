use backup_monitor::error::BackupError;
use backup_monitor::model::Limits;
use backup_monitor::parse::{parse_borg, parse_restic};
use std::error::Error;


const MEBIBYTE: usize = 1024 * 1024;


const LISTING_BYTES: usize = 8 * MEBIBYTE;


const PEAK_BUDGET_KIB: u64 = 40 * 1024;


const SMALL_COUNT: usize = 10;


const RESTIC_ELEMENT_BYTES: usize = 2;


const BORG_ELEMENT_BYTES: usize = 3;


const BORG_OVERHEAD_BYTES: usize = 200;


const REPOSITORY_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";


fn peak_kib() -> Result<u64, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM")?;
    let digits = line.split_whitespace().nth(1).ok_or("no value")?;
    Ok(digits.parse()?)
}


#[test]
fn a_listing_of_minimal_elements_is_refused_before_any_is_parsed() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_bytes: LISTING_BYTES as u64,
        max_snapshots: SMALL_COUNT,
        ..Limits::default()
    };
    let restic = format!("[{}0]", "0,".repeat(LISTING_BYTES / RESTIC_ELEMENT_BYTES - RESTIC_ELEMENT_BYTES));
    let borg = format!(
        "{{\"repository\":{{\"id\":\"{REPOSITORY_ID}\"}},\"archives\":[{}{{}}]}}",
        "{},".repeat((LISTING_BYTES - BORG_OVERHEAD_BYTES) / BORG_ELEMENT_BYTES)
    );
    let before = peak_kib()?;
    assert!(matches!(
        parse_restic(restic.as_bytes(), "repo", &limits),
        Err(BackupError::TooManySnapshots { .. })
    ));
    assert!(matches!(
        parse_borg(borg.as_bytes(), false, &limits),
        Err(BackupError::TooManySnapshots { .. })
    ));
    let growth = peak_kib()?.saturating_sub(before);
    assert!(growth < PEAK_BUDGET_KIB, "peak grew by {growth} KiB");
    Ok(())
}
