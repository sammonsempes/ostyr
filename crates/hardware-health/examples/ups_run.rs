//! Reads the settings file (first argument) and the thresholds file (second), runs upsc on every target and prints one line per target (Unix only).

#[cfg(unix)]
use hardware_health::limits::{DEFAULT_MAX_BYTES, MAX_UPS_SETTINGS_BYTES};
#[cfg(unix)]
use hardware_health::smart_exec::check_program;
#[cfg(unix)]
use hardware_health::smart_run::run_smartctl;
#[cfg(unix)]
use hardware_health::ups::parse_thresholds;
#[cfg(unix)]
use hardware_health::ups_assess::{assess_ups, ups_target_measures};
#[cfg(unix)]
use hardware_health::ups_run::{run_ups, ups_failure_health, UPSC_PROGRAM};
#[cfg(unix)]
use hardware_health::ups_settings::parse_ups_settings;
#[cfg(unix)]
use std::io::{Read, Write};


#[cfg(unix)]
const USAGE: &str = "usage: ups_run <settings.yaml> <thresholds.yaml>";


#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let settings_path = args.next().ok_or(USAGE)?;
    let thresholds_path = args.next().ok_or(USAGE)?;
    let mut settings_text = String::new();
    std::fs::File::open(settings_path)?
        .take(u64::try_from(MAX_UPS_SETTINGS_BYTES)?.saturating_add(1))
        .read_to_string(&mut settings_text)?;
    let mut thresholds_text = String::new();
    std::fs::File::open(thresholds_path)?
        .take(DEFAULT_MAX_BYTES)
        .read_to_string(&mut thresholds_text)?;
    let settings = parse_ups_settings(&settings_text)?;
    let thresholds = parse_thresholds(&thresholds_text)?;
    check_program(std::path::Path::new(UPSC_PROGRAM))?;
    let report = run_ups(&settings, run_smartctl);
    let mut out = std::io::stdout();
    writeln!(out, "refused_targets={:?}", report.refused_targets)?;
    report
        .failed
        .iter()
        .try_for_each(|(target, class)| writeln!(out, "{} failed={class:?} verdict={:?}", target.text, ups_failure_health(*class)))?;
    report.reports.iter().try_for_each(|(target, found)| {
        let line = ups_target_measures(found, target)
            .iter()
            .map(|item| format!("{}={}", item.name, item.value))
            .collect::<Vec<_>>()
            .join(" ");
        writeln!(out, "{} verdict={:?} {line}", target.text, assess_ups(found, &thresholds))
    })?;
    Ok(())
}


#[cfg(not(unix))]
fn main() {}
