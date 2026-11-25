use std::io;
use std::path::Path;
use std::time::Duration;


pub const POLICY_ZONE: &str = "rpz.example.org.";


pub const SERIAL_INDEX: usize = 5;


/// What Unbound would list once it served the zone file at `path`.
pub fn zone_listing(path: &Path) -> io::Result<String> {
    let text = std::fs::read_to_string(path)?;
    let serial = text
        .lines()
        .find(|line| line.contains(" SOA "))
        .and_then(|line| line.split_whitespace().nth(SERIAL_INDEX))
        .ok_or_else(|| io::Error::other("no SOA"))?;
    Ok(format!("{POLICY_ZONE}\tserial {serial}\n"))
}


/// Unbound still serving a serial that is not the new one.
pub fn stale_readback(_program: &str, _arguments: &[String], _deadline: Duration) -> io::Result<String> {
    Ok(format!("{POLICY_ZONE}\tserial 1\n"))
}
