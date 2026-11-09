//! Reads `apt list --upgradable` output from stdin and prints a summary.

use patch_inventory::apt::parse_apt;
use patch_inventory::limits::default_limits;
use patch_inventory::model::Device;
use std::io::Write;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = Device {
        tenant: "lab".to_string(),
        device_id: "lab-device".to_string(),
    };
    let inventory = parse_apt(&device, std::io::stdin(), &default_limits())?;
    let security = inventory.updates.iter().filter(|update| update.security).count();
    let mut out = std::io::stdout();
    writeln!(
        out,
        "updates={} security={} skipped={:?}",
        inventory.updates.len(),
        security,
        inventory.skipped
    )?;
    inventory.updates.iter().try_for_each(|update| {
        writeln!(
            out,
            "{} {} {} -> {}",
            update.package,
            update.architecture,
            update.installed_version.as_deref().unwrap_or("?"),
            update.candidate_version
        )
    })?;
    Ok(())
}
