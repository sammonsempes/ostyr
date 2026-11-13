use network_devices::load::load_devices;
use network_devices::plan::polling_plan;
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;


const USAGE: &str = "usage: devices_check <directory>";


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let directory = match arguments.as_slice() {
        [directory] => Ok(directory),
        _ => Err(USAGE),
    }?;
    let loaded = load_devices(Path::new(directory))?;
    let mut out = stdout();
    for device in &loaded.devices {
        writeln!(
            out,
            "device {} tenant {} kind {:?} addresses {:?} agent {}",
            device.name, device.tenant, device.kind, device.addresses, device.agent_managed
        )?;
    }
    for warning in &loaded.warnings {
        writeln!(out, "warning: {warning}")?;
    }
    for entry in polling_plan(&loaded.devices) {
        writeln!(
            out,
            "poll {} {} {:?} credentials {}",
            entry.tenant, entry.name, entry.version, entry.credentials
        )?;
    }
    Ok(())
}
