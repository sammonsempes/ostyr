//! Reads the winget update listing from stdin and prints a summary.

use patch_inventory::limits::default_limits;
use patch_inventory::model::Device;
use patch_inventory::winget::parse_winget_updates;
use std::io::Write;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = Device {
        tenant: "lab".to_string(),
        device_id: "lab-device".to_string(),
    };
    let inventory = parse_winget_updates(&device, std::io::stdin(), &default_limits())?;
    let mut out = std::io::stdout();
    writeln!(out, "updates={} skipped={:?}", inventory.updates.len(), inventory.skipped)?;
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
