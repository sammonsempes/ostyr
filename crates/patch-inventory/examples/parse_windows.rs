//! Reads the Windows Update Agent search output from stdin and prints a summary.

use patch_inventory::limits::default_limits;
use patch_inventory::model::Device;
use patch_inventory::windows::parse_windows_updates;
use std::io::Write;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = Device {
        tenant: "lab".to_string(),
        device_id: "lab-device".to_string(),
    };
    let inventory = parse_windows_updates(&device, std::io::stdin(), &default_limits())?;
    let security = inventory.updates.iter().filter(|update| update.security).count();
    let mut out = std::io::stdout();
    writeln!(
        out,
        "updates={} security={} partial={} skipped={:?}",
        inventory.updates.len(),
        security,
        inventory.partial,
        inventory.skipped
    )?;
    inventory.updates.iter().try_for_each(|update| {
        writeln!(
            out,
            "{} r{} kb={} security={} hidden={} severity={:?} {}",
            update.update_id,
            update.revision,
            update.kb_ids.join(","),
            update.security,
            update.hidden,
            update.severity,
            update.title
        )
    })?;
    Ok(())
}
