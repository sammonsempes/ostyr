use crate::common::types::TestResult;
use std::fs::{read_to_string, write};


pub const TENANT: &str = "tenant-a";


pub const NOW: u64 = 1_700_000_000_000_000_000;


pub const RESOURCE_SPANS_TAG: u8 = 0x0a;


pub const SCOPE_SPANS_TAG: u8 = 0x12;


pub const SPANS_TAG: u8 = 0x12;


pub const RESET_PEAK: &str = "5";


pub fn framed(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    prost::encoding::encode_varint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}


pub fn high_water_kib() -> Result<u64, Box<dyn std::error::Error>> {
    let status = read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM line")?;
    let digits: String = line.chars().filter(char::is_ascii_digit).collect();
    Ok(digits.parse()?)
}


pub fn reset_high_water() -> TestResult {
    Ok(write("/proc/self/clear_refs", RESET_PEAK)?)
}


pub fn report(line: &str) -> TestResult {
    Ok(std::io::Write::write_all(&mut std::io::stdout(), format!("{line}\n").as_bytes())?)
}
