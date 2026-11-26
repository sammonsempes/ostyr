use std::error::Error;
use std::fs;
use waf::limits::MAX_DEADLINE_SECONDS;


const STEPS_PER_DELIVERY: u64 = 3;


fn setting(unit: &str, key: &str) -> Option<String> {
    unit.lines()
        .find_map(|line| line.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')).map(str::to_owned))
}


#[test]
fn the_unit_stops_with_mixed_kill_and_a_timeout_above_three_deadlines() -> Result<(), Box<dyn Error>> {
    let unit = fs::read_to_string(format!("{}/packaging/ostyr-waf.service", env!("CARGO_MANIFEST_DIR")))?;
    assert_eq!(setting(&unit, "KillMode").as_deref(), Some("mixed"));
    let timeout: u64 = setting(&unit, "TimeoutStopSec").ok_or("no TimeoutStopSec")?.parse()?;
    assert!(timeout > STEPS_PER_DELIVERY * MAX_DEADLINE_SECONDS);
    assert_eq!(setting(&unit, "KillModeX"), None);
    Ok(())
}
