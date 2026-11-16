use ad_posture::error::SnapshotError;
use ad_posture::limits::{Limits, DEFAULT_MAX_ENTRIES};
use ad_posture::snapshot::read_snapshot;
use std::error::Error;


const PEAK_BOUND_KIB: u64 = 12_288;


const HUGE: usize = 1_000_000;


fn peak_kib() -> Result<u64, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM")?;
    Ok(line.split_whitespace().nth(1).ok_or("no value")?.parse()?)
}


#[test]
fn a_million_entries_are_counted_without_being_built() -> Result<(), Box<dyn Error>> {
    let text = format!("[{}{{}}]", "{},".repeat(HUGE - 1));
    let error = read_snapshot(text.as_bytes(), &Limits::default()).err().ok_or("accepted")?;
    assert!(matches!(
        error,
        SnapshotError::TooManyEntries {
            count: HUGE,
            max: DEFAULT_MAX_ENTRIES
        }
    ));
    let peak = peak_kib()?;
    assert!(peak < PEAK_BOUND_KIB, "peak {peak} KiB");
    Ok(())
}
