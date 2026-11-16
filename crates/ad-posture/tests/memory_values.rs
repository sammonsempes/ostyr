use ad_posture::limits::Limits;
use ad_posture::snapshot::read_snapshot;
use std::error::Error;


const PEAK_BOUND_KIB: u64 = 28_672;


const HUGE: usize = 1_000_000;


fn peak_kib() -> Result<u64, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM")?;
    Ok(line.split_whitespace().nth(1).ok_or("no value")?.parse()?)
}


#[test]
fn a_million_values_are_counted_without_being_built() -> Result<(), Box<dyn Error>> {
    let text = format!(
        "[{{\"distinguishedName\":\"a\",\"memberOf\":[{}\"CN=g\"]}}]",
        "\"CN=g\",".repeat(HUGE - 1)
    );
    let snapshot = read_snapshot(text.as_bytes(), &Limits::default())?;
    let entry = snapshot.entries.first().ok_or("entry set aside")?;
    assert!(entry.member_of.is_empty() && snapshot.unreadable.is_empty());
    assert_eq!(
        entry.gaps.first().map(|gap| (gap.field, gap.dropped, gap.over_limit)),
        Some(("memberOf", HUGE, true))
    );
    let peak = peak_kib()?;
    assert!(peak < PEAK_BOUND_KIB, "peak {peak} KiB");
    Ok(())
}
