#![cfg(target_os = "linux")]
#[path = "common/types.rs"]
mod types;


use hardware_health::error::SmartError;
use hardware_health::limits::default_limits;
use hardware_health::model::{FailureClass, RunOutput, SmartSettings};
use hardware_health::parse::parse_smartctl;
use hardware_health::smart_run::scan_and_report;
use std::path::Path;
use std::time::Duration;
use types::TestResult;


const ENTRY_ELEMENTS: usize = 500_000;


const EMPTY_ARRAYS: usize = 340_000;


const MAX_GROWTH_KIB: u64 = 4096;


const SECONDS: u64 = 5;


fn peak_kib() -> Result<u64, Box<dyn std::error::Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM")?;
    Ok(line.split_whitespace().nth(1).ok_or("no value")?.parse()?)
}


fn nested_scan(_program: &Path, _arguments: &[&str], _cap: u64, _deadline: Duration) -> Result<RunOutput, FailureClass> {
    let elements = "0,".repeat(ENTRY_ELEMENTS);
    let text = format!(r#"{{"devices":[{{"name":[{elements}0],"type":"sat"}}]}}"#);
    Ok(RunOutput {
        bytes: text.into_bytes(),
        exit_code: Some(0),
    })
}


#[test]
fn nested_input_never_materialises_a_value_tree() -> TestResult {
    let settings = SmartSettings {
        deadline_seconds: SECONDS,
        round_deadline_seconds: SECONDS,
    };
    let output = format!("[{}[]]", "[],".repeat(EMPTY_ARRAYS));
    let before = peak_kib()?;
    let report = scan_and_report(&settings, nested_scan);
    let after_scan = peak_kib()?;
    assert_eq!(report.refused_devices, 1);
    assert!(after_scan - before < MAX_GROWTH_KIB, "scan grew by {} KiB", after_scan - before);
    let refused = parse_smartctl(output.as_bytes(), &default_limits());
    assert!(matches!(refused, Err(SmartError::TooManyNodes { .. })));
    let after_parse = peak_kib()?;
    assert!(
        after_parse - after_scan < MAX_GROWTH_KIB,
        "parse grew by {} KiB",
        after_parse - after_scan
    );
    Ok(())
}
