use ad_posture::error::SnapshotError;
use ad_posture::limits::{Limits, DEFAULT_MAX_BYTES};
use ad_posture::snapshot::read_snapshot;
use std::error::Error;
use std::io::{repeat, Read};


const PEAK_BOUND_KIB: u64 = 131_072;


const HUGE_DN_BYTES: u64 = 104_857_600;


const NEAR_CAP_DN_BYTES: u64 = 33_000_000;


const DN_HEAD: &str = "[{\"distinguishedName\":\"";


const DN_TAIL: &str = "\"}]";


fn peak_kib() -> Result<u64, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM")?;
    Ok(line.split_whitespace().nth(1).ok_or("no value")?.parse()?)
}


#[test]
fn hostile_snapshots_are_refused_within_bounds() -> Result<(), Box<dyn Error>> {
    let limits = Limits::default();
    let huge = DN_HEAD.as_bytes().chain(repeat(b'a').take(HUGE_DN_BYTES));
    let huge_error = read_snapshot(huge, &limits).err().ok_or("accepted")?;
    assert!(matches!(huge_error, SnapshotError::TooLarge { max: DEFAULT_MAX_BYTES }));

    let near_cap = DN_HEAD.as_bytes().chain(repeat(b'a').take(NEAR_CAP_DN_BYTES)).chain(DN_TAIL.as_bytes());
    let near = read_snapshot(near_cap, &limits)?;
    assert_eq!(near.unreadable.first().map(|item| item.reason), Some("too long"));
    assert!(near.entries.is_empty());

    let peak = peak_kib()?;
    assert!(peak < PEAK_BOUND_KIB, "peak {peak} KiB");
    Ok(())
}
