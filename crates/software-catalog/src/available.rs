//! Reads the package names the device's manager offers (`apt-cache pkgnames`, `dnf repoquery --qf '%{name}\n'`), bounded.

use crate::error::InstalledError;
use crate::installed::read_input;
use crate::limits::Limits;
use crate::model::{Available, Manager};
use patch_inventory::validate::{is_dpkg_name, is_rpm_name};
use std::io::Read;


const NEWLINE: u8 = b'\n';


pub fn name_ok(manager: Manager, text: &str) -> bool {
    match manager {
        Manager::Apt => is_dpkg_name(text),
        Manager::Dnf => is_rpm_name(text),
        Manager::Winget | Manager::Msi => false,
    }
}


pub fn parse_name(line: &[u8], manager: Manager, limits: &Limits) -> Option<String> {
    std::str::from_utf8(line)
        .ok()
        .filter(|text| line.len() <= limits.max_line_bytes && name_ok(manager, text))
        .map(str::to_string)
}


pub fn parse_available<Source: Read>(reader: Source, manager: Manager, limits: &Limits) -> Result<Available, InstalledError> {
    let buffer = read_input(reader, limits)?;
    Ok(buffer
        .split(|byte| *byte == NEWLINE)
        .filter(|line| !line.is_empty())
        .fold(Available::default(), |mut available, line| {
            match parse_name(line, manager, limits) {
                Some(name) if available.names.contains(&(manager, name.clone())) => {}
                Some(name) if available.names.len() < limits.max_available => {
                    available.names.insert((manager, name));
                }
                Some(_) => available.over_limit += 1,
                None => available.malformed += 1,
            }
            available
        }))
}
