use backup_monitor::model::{Limits, SkipReason};
use backup_monitor::parse::parse_pbs;
use std::error::Error;


const COPIES: usize = 99_999;


const COPIES_BUDGET_KIB: u64 = 48 * 1024;


const ELEMENT: &str = "{\"backup-type\":\"vm\",\"backup-id\":\"1\",\"backup-time\":1794000000,\"files\":[]},";


const LAST_ELEMENT: &str = "{\"backup-type\":\"vm\",\"backup-id\":\"1\",\"backup-time\":1794000000,\"files\":[]}";


fn peak_kib() -> Result<u64, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM")?;
    let digits = line.split_whitespace().nth(1).ok_or("no value")?;
    Ok(digits.parse()?)
}


#[test]
fn ninety_nine_thousand_copies_of_one_id_stay_within_the_budget() -> Result<(), Box<dyn Error>> {
    let listing = format!("[{}{LAST_ELEMENT}]", ELEMENT.repeat(COPIES - 1));
    let limits = Limits {
        max_bytes: listing.len() as u64,
        ..Limits::default()
    };
    let before = peak_kib()?;
    let parsed = parse_pbs(listing.as_bytes(), "store1", &limits)?;
    let growth = peak_kib()?.saturating_sub(before);
    assert_eq!(
        (parsed.snapshots.len(), parsed.skipped.get(&SkipReason::Duplicate)),
        (0, Some(&(COPIES as u64)))
    );
    assert!(growth < COPIES_BUDGET_KIB, "peak grew by {growth} KiB");
    Ok(())
}
