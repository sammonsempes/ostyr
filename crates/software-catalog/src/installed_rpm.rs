//! Reads `rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n'` output, bounded.

use crate::error::InstalledError;
use crate::installed::parse_with;
use crate::limits::Limits;
use crate::model::{Installed, InstalledRow, Line, Manager};
use crate::validate::{rpm_pin_ok, GPG_PUBKEY, RPM_ARCHITECTURES};
use patch_inventory::scan::is_forbidden;
use patch_inventory::validate::{is_plain_text, is_rpm_architecture, is_rpm_name};
use std::io::Read;


pub fn parse_rpm_line(line: &[u8], limits: &Limits) -> Option<Line> {
    let text = std::str::from_utf8(line).ok().filter(|_| line.len() <= limits.max_line_bytes)?;
    match text.split('\t').collect::<Vec<&str>>().as_slice() {
        [package, version, architecture] => rpm_line(package, version, architecture),
        _ => None,
    }
}


pub fn rpm_line(package: &str, version: &str, architecture: &str) -> Option<Line> {
    let named = is_rpm_name(package) && is_plain_text(version) && !version.chars().any(is_forbidden);
    let key = named && package == GPG_PUBKEY;
    let package_ok = named && rpm_pin_ok(version) && is_rpm_architecture(architecture) && RPM_ARCHITECTURES.contains(&architecture);
    match (key, package_ok) {
        (true, _) => Some(Line::NotInstalled),
        (false, true) => Some(Line::Row(InstalledRow {
            manager: Manager::Dnf,
            package: package.to_string(),
            version: version.to_string(),
            held: false,
        })),
        (false, false) => None,
    }
}


pub fn parse_rpm_installed<Source: Read>(reader: Source, limits: &Limits) -> Result<Installed, InstalledError> {
    parse_with(reader, limits, parse_rpm_line)
}
