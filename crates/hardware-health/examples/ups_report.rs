//! Reads a thresholds YAML file (first argument) and an `upsc` capture (second) and a UPS name (third) and prints the verdict and the measures.

use hardware_health::limits::{DEFAULT_MAX_BYTES, DEFAULT_MAX_UPS_LINES};
use hardware_health::ups::{parse_thresholds, parse_upsc};
use hardware_health::ups_assess::{assess_ups, ups_measures};
use std::io::{Read, Write};


const USAGE: &str = "usage: ups_report <thresholds.yaml> <capture> <ups-name>";


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let thresholds_path = args.next().ok_or(USAGE)?;
    let capture_path = args.next().ok_or(USAGE)?;
    let ups_name = args.next().ok_or(USAGE)?;
    let mut thresholds_text = String::new();
    std::fs::File::open(thresholds_path)?
        .take(DEFAULT_MAX_BYTES)
        .read_to_string(&mut thresholds_text)?;
    let thresholds = parse_thresholds(&thresholds_text)?;
    let report = parse_upsc(std::fs::File::open(capture_path)?, DEFAULT_MAX_BYTES, DEFAULT_MAX_UPS_LINES)?;
    let mut out = std::io::stdout();
    writeln!(out, "verdict={:?}", assess_ups(&report, &thresholds))?;
    writeln!(out, "rejected_fields={} unreadable={:?}", report.rejected_fields, report.unreadable)?;
    ups_measures(&report, &ups_name)
        .iter()
        .try_for_each(|item| writeln!(out, "{} {} {} {:?}", item.name, item.value, item.unit, item.labels))?;
    Ok(())
}
