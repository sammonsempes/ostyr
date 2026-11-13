#[path = "common/types.rs"]
mod types;


use net_topology::error::ParseError;
use net_topology::limits::Limits;
use net_topology::lldp::parse_lldpd;
use std::error::Error;
use types::TestResult;


const GROWTH_BOUND_KIB: u64 = 2_048;


const EMPTY_NEIGHBOURS: usize = 350_000;


fn peak_kib() -> Result<u64, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM")?;
    Ok(line.split_whitespace().nth(1).ok_or("no value")?.parse()?)
}


#[test]
fn empty_neighbours_are_refused_before_any_element_is_built() -> TestResult {
    let unit = "{},";
    let head = r#"{"lldp":[{"interface":[{"name":"eth0","chassis":["#;
    let document = format!("{head}{}{{}}],\"port\":[]}}]}}]}}", unit.repeat(EMPTY_NEIGHBOURS));
    let before = peak_kib()?;
    let outcome = parse_lldpd(document.as_bytes(), "server", 1, &Limits::default());
    let after = peak_kib()?;
    assert!(matches!(outcome, Err(ParseError::TooMany { list: "chassis", .. })));
    assert!(after - before < GROWTH_BOUND_KIB, "growth {} KiB", after - before);
    Ok(())
}
