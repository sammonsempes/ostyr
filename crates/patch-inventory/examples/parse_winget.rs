//! Reads the output of `winget upgrade` from stdin (arguments: exit code, source) and prints a summary.

use patch_inventory::limits::default_limits;
use patch_inventory::model::{Device, WingetSource};
use patch_inventory::winget::parse_winget_cli;
use std::io::Write;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let exit_code: i32 = arguments
        .next()
        .ok_or("usage: parse_winget <exit-code> <winget|msstore> < output")?
        .parse()?;
    let source = match arguments.next().as_deref() {
        Some("msstore") => WingetSource::Msstore,
        _ => WingetSource::Winget,
    };
    let device = Device {
        tenant: "lab".to_string(),
        device_id: "lab-device".to_string(),
    };
    let inventory = parse_winget_cli(&device, std::io::stdin(), exit_code, source, &default_limits())?;
    let mut out = std::io::stdout();
    writeln!(
        out,
        "updates={} skipped={:?} preamble_lines={}",
        inventory.updates.len(),
        inventory.skipped,
        inventory.preamble_lines
    )?;
    inventory.updates.iter().try_for_each(|update| {
        writeln!(
            out,
            "{} {} -> {} origin={:?}",
            update.package,
            update.installed_version.as_deref().unwrap_or("-"),
            update.candidate_version,
            update.origin
        )
    })?;
    Ok(())
}
