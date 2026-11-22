#[path = "common/types.rs"]
mod types;


use std::error::Error;
use types::TestResult;
use virt_inventory::error::ParseError;
use virt_inventory::limits::{Limits, DEFAULT_MAX_BYTES};
use virt_inventory::vsphere::{parse_hosts, parse_vms};


const GROWTH_SLACK_KIB: u64 = 2_048;


const KIB: u64 = 1_024;


const BUFFER_COPIES: u64 = 2;


const INPUT_BYTES: usize = 4_194_304;


const NEST_DEPTH: usize = 1_000_000;


fn peak_kib() -> Result<u64, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM")?;
    Ok(line.split_whitespace().nth(1).ok_or("no value")?.parse()?)
}


fn repeated(head: &str, unit: &str, tail: &str) -> String {
    let count = (INPUT_BYTES - head.len() - tail.len()) / unit.len();
    format!("{head}{}{tail}", unit.repeat(count))
}


fn growth_of(label: &str, input: &str, run: fn(&[u8]) -> bool) -> Result<(String, u64), Box<dyn Error>> {
    let before = peak_kib()?;
    assert!(run(input.as_bytes()), "{label} was not handled as expected");
    Ok((label.to_owned(), peak_kib()?.saturating_sub(before)))
}


fn vms_refused(input: &[u8]) -> bool {
    matches!(parse_vms(input, &Limits::default()), Err(ParseError::TooManyItems { .. }))
}


fn hosts_refused(input: &[u8]) -> bool {
    matches!(parse_hosts(input, &Limits::default()), Err(ParseError::TooManyItems { .. }))
}


fn nested_survived(input: &[u8]) -> bool {
    parse_vms(input, &Limits::default()).is_ok_and(|parsed| parsed.items.len() == 1)
}


fn nested_refused_alone(input: &[u8]) -> bool {
    parse_vms(input, &Limits::default()).is_ok_and(|parsed| parsed.items.is_empty() && parsed.skipped.bad_field == 1)
}


#[test]
fn hostile_counts_are_refused_before_anything_is_built() -> TestResult {
    assert!(u64::try_from(INPUT_BYTES)? < DEFAULT_MAX_BYTES);
    let bound = u64::try_from(INPUT_BYTES)? * BUFFER_COPIES / KIB + GROWTH_SLACK_KIB;
    let elements = repeated("[", "{},", "{}]");
    let hosts = repeated("[", r#"{"host":"host-1"},"#, "{}]");
    let nest = format!("{}{}", "[".repeat(NEST_DEPTH), "]".repeat(NEST_DEPTH));
    let ignored = format!(r#"[{{"vm":"vm-1","x":{nest}}}]"#);
    let typed = format!(r#"[{{"vm":"vm-1","name":{nest}}}]"#);
    let growths = [
        growth_of("elements", &elements, vms_refused)?,
        growth_of("hosts", &hosts, hosts_refused)?,
        growth_of("nested ignored", &ignored, nested_survived)?,
        growth_of("nested typed", &typed, nested_refused_alone)?,
    ];
    growths
        .iter()
        .for_each(|(label, growth)| assert!(*growth < bound, "{label}: growth {growth} KiB above {bound}"));
    Ok(())
}
