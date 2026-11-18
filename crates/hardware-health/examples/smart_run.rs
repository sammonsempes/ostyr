//! Reads the settings file (first argument), scans the disks with smartctl and prints one line per disk (Unix only).

#[cfg(unix)]
use hardware_health::assess::assess;
#[cfg(unix)]
use hardware_health::limits::MAX_SETTINGS_BYTES;
#[cfg(unix)]
use hardware_health::measures::measures;
#[cfg(unix)]
use hardware_health::smart_exec::check_program;
#[cfg(unix)]
use hardware_health::smart_run::{run_smartctl, scan_and_report};
#[cfg(unix)]
use hardware_health::smart_settings::parse_settings;
#[cfg(unix)]
use std::io::{Read, Write};


#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: smart_run <settings.yaml>")?;
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(u64::try_from(MAX_SETTINGS_BYTES)?.saturating_add(1))
        .read_to_string(&mut text)?;
    let settings = parse_settings(&text)?;
    check_program(&settings.program)?;
    let report = scan_and_report(&settings, run_smartctl);
    let mut out = std::io::stdout();
    writeln!(
        out,
        "scan_failed={:?} refused_devices={} failed={:?}",
        report.scan_failed, report.refused_devices, report.failed
    )?;
    report.reports.iter().try_for_each(|(device, found)| {
        let line = measures(found)
            .iter()
            .map(|item| format!("{}={}", item.name, item.value))
            .collect::<Vec<_>>()
            .join(" ");
        writeln!(out, "{device} verdict={:?} {line}", assess(found))
    })?;
    Ok(())
}


#[cfg(not(unix))]
fn main() {}
