//! Reads the Redfish chassis, thermal, power and system documents (four file arguments) and prints the verdict and the measures.

use hardware_health::limits::default_redfish_limits;
use hardware_health::redfish::parse_redfish;
use hardware_health::redfish_assess::{assess_redfish, redfish_measures};
use std::io::Write;


const USAGE: &str = "usage: redfish_report <chassis.json> <thermal.json> <power.json> <system.json>";


const DEVICE_NAME: &str = "bmc";


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut chassis = std::fs::File::open(args.next().ok_or(USAGE)?)?;
    let mut thermal = std::fs::File::open(args.next().ok_or(USAGE)?)?;
    let mut power = std::fs::File::open(args.next().ok_or(USAGE)?)?;
    let mut system = std::fs::File::open(args.next().ok_or(USAGE)?)?;
    let report = parse_redfish(
        Some(&mut chassis),
        Some(&mut thermal),
        Some(&mut power),
        Some(&mut system),
        &default_redfish_limits(),
    )?;
    let mut out = std::io::stdout();
    writeln!(out, "verdict={:?}", assess_redfish(&report))?;
    writeln!(out, "unreadable={:?} refused={:?}", report.unreadable, report.refused_collections)?;
    redfish_measures(&report, DEVICE_NAME)
        .iter()
        .try_for_each(|item| writeln!(out, "{} {} {} {:?}", item.name, item.value, item.unit, item.labels))?;
    Ok(())
}
