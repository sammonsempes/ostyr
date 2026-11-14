//! Polls every device of a `redfish_devices.yaml` for one tenant and prints each verdict with its `unverified_tls` and role flags.

use core_pg::scope::tenant_scope;
use hardware_health::limits::{default_redfish_limits, MAX_DEVICES_BYTES};
use hardware_health::model::RoleCheck;
use hardware_health::redfish_devices::parse_devices;
use hardware_health::redfish_fetch::poll_device;
use std::io::{Read, Write};


const USAGE: &str = "usage: redfish_poll <devices.yaml> <tenant>";


fn role_name(role: RoleCheck) -> &'static str {
    match role {
        RoleCheck::NotAdministrator => "not_administrator",
        RoleCheck::Administrator => "administrator",
        RoleCheck::Unknown => "role_unknown",
    }
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or(USAGE)?;
    let tenant = tenant_scope(&args.next().ok_or(USAGE)?)?;
    let mut text = String::new();
    std::fs::File::open(path)?.take(MAX_DEVICES_BYTES as u64 + 1).read_to_string(&mut text)?;
    let limits = default_redfish_limits();
    let mut out = std::io::stdout();
    parse_devices(&text)?
        .iter()
        .try_for_each(|device| match poll_device(device, &tenant, &limits) {
            Ok(report) => writeln!(
                out,
                "device={} tenant={} verdict={:?} unverified_tls={} role={}",
                report.device,
                report.tenant,
                report.health,
                report.unverified_tls,
                role_name(report.role)
            ),
            Err(error) => writeln!(out, "device={} error={error} unverified_tls={}", device.name, device.insecure_skip_verify),
        })?;
    Ok(())
}
