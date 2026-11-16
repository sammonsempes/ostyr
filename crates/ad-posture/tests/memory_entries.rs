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
    let hit = read_snapshot(text.as_bytes(), &Limits::default())?;
    assert_eq!(
        hit.bounds.first().map(|found| (found.bound, found.observed, found.limit)),
        Some(("entries", HUGE as u64, DEFAULT_MAX_ENTRIES as u64))
    );
    let peak = peak_kib()?;
    assert!(peak < PEAK_BOUND_KIB, "peak {peak} KiB");
    Ok(())
}
