use std::fs::{read_to_string, write};
use std::io::Write;


pub const RESET_PEAK: &str = "5";


pub fn high_water_kib() -> Result<u64, Box<dyn std::error::Error>> {
    let status = read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM line")?;
    let digits: String = line.chars().filter(char::is_ascii_digit).collect();
    Ok(digits.parse()?)
}


pub fn reset_high_water() -> Result<(), Box<dyn std::error::Error>> {
    Ok(write("/proc/self/clear_refs", RESET_PEAK)?)
}


pub fn report(line: &str) -> Result<(), Box<dyn std::error::Error>> {
    Ok(std::io::stdout().write_all(format!("{line}\n").as_bytes())?)
}
