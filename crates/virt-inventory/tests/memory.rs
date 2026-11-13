#[path = "common/types.rs"]
mod types;


use std::error::Error;
use types::TestResult;
use virt_inventory::error::ParseError;
use virt_inventory::limits::{Limits, DEFAULT_MAX_BYTES};
use virt_inventory::proxmox::{parse_permissions, parse_resources};


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


fn resources_refused(input: &[u8]) -> bool {
    matches!(parse_resources(input, &Limits::default()), Err(ParseError::TooManyItems { .. }))
}


fn paths_refused(input: &[u8]) -> bool {
    matches!(parse_permissions(input, &Limits::default()), Err(ParseError::TooManyItems { .. }))
}


fn privileges_refused(input: &[u8]) -> bool {
    matches!(parse_permissions(input, &Limits::default()), Err(ParseError::TooManyPrivileges { .. }))
}


fn nested_survived(input: &[u8]) -> bool {
    parse_resources(input, &Limits::default()).is_ok_and(|parsed| parsed.items.len() == 1)
}


#[test]
fn hostile_counts_are_refused_before_anything_is_built() -> TestResult {
    assert!(u64::try_from(INPUT_BYTES)? < DEFAULT_MAX_BYTES);
    let bound = u64::try_from(INPUT_BYTES)? * BUFFER_COPIES / KIB + GROWTH_SLACK_KIB;
    let elements = repeated(r#"{"data":["#, "{},", "{}]}");
    let paths = repeated(r#"{"data":{"#, r#""/p":{},"#, r#""/q":{}}}"#);
    let privileges = repeated(r#"{"data":{"/":{"#, r#""P.A":1,"#, r#""P.Z":1}}}"#);
    let nest = format!("{}{}", "[".repeat(NEST_DEPTH), "]".repeat(NEST_DEPTH));
    let nested = format!(r#"{{"data":[{{"type":"qemu","vmid":100,"node":"pve","x":{nest}}}]}}"#);
    let growths = [
        growth_of("elements", &elements, resources_refused)?,
        growth_of("paths", &paths, paths_refused)?,
        growth_of("privileges", &privileges, privileges_refused)?,
        growth_of("nested", &nested, nested_survived)?,
    ];
    growths
        .iter()
        .for_each(|(label, growth)| assert!(*growth < bound, "{label}: growth {growth} KiB above {bound}"));
    Ok(())
}
