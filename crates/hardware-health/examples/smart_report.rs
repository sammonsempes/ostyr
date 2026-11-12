//! Reads a smartctl JSON file (first argument) or stdin and prints the verdict and the measures.

use hardware_health::assess::assess;
use hardware_health::limits::default_limits;
use hardware_health::measures::measures;
use hardware_health::parse::parse_smartctl;
use std::io::Write;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let limits = default_limits();
    let report = match std::env::args().nth(1) {
        Some(path) => parse_smartctl(std::fs::File::open(path)?, &limits)?,
        None => parse_smartctl(std::io::stdin(), &limits)?,
    };
    let mut out = std::io::stdout();
    writeln!(out, "verdict={:?}", assess(&report))?;
    writeln!(
        out,
        "rejected_fields={} omitted_attributes={}",
        report.rejected_fields, report.omitted_attributes
    )?;
    measures(&report)
        .iter()
        .try_for_each(|item| writeln!(out, "{} {} {} {:?}", item.name, item.value, item.unit, item.labels))?;
    Ok(())
}
