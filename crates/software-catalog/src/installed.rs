//! Reads `dpkg-query -W -f '${Package}\t${Version}\t${db:Status-Abbrev}\n'` output (the status column is optional), bounded.

use crate::error::InstalledError;
use crate::limits::Limits;
use crate::model::{Installed, InstalledRow, Line, Manager};
use patch_inventory::scan::is_forbidden;
use patch_inventory::validate::{is_dpkg_name, is_plain_text};
use std::io::Read;


const NEWLINE: u8 = b'\n';


const INSTALLED_STATE: &str = "ii";


pub fn read_input<Source: Read>(reader: Source, limits: &Limits) -> Result<Vec<u8>, InstalledError> {
    let mut buffer = Vec::new();
    reader
        .take((limits.max_installed_bytes as u64).saturating_add(1))
        .read_to_end(&mut buffer)?;
    if buffer.len() > limits.max_installed_bytes {
        Err(InstalledError::TooLarge {
            limit: limits.max_installed_bytes,
        })
    } else {
        Ok(buffer)
    }
}


pub fn parse_line(line: &[u8], limits: &Limits) -> Option<Line> {
    let text = std::str::from_utf8(line).ok().filter(|_| line.len() <= limits.max_line_bytes)?;
    let (package, rest) = text.split_once('\t')?;
    let (version, status) = rest
        .split_once('\t')
        .map_or((rest, None), |(version, status)| (version, Some(status.trim())));
    let valid = is_dpkg_name(package) && is_plain_text(version) && !version.chars().any(is_forbidden);
    valid.then(|| match status {
        Some(state) if state != INSTALLED_STATE => Line::NotInstalled,
        _ => Line::Row(InstalledRow {
            manager: Manager::Apt,
            package: package.to_string(),
            version: version.to_string(),
        }),
    })
}


pub fn parse_installed<Source: Read>(reader: Source, limits: &Limits) -> Result<Installed, InstalledError> {
    let buffer = read_input(reader, limits)?;
    Ok(buffer
        .split(|byte| *byte == NEWLINE)
        .filter(|line| !line.is_empty())
        .fold(Installed::default(), |mut installed, line| {
            match parse_line(line, limits) {
                Some(Line::Row(row)) if installed.rows.len() < limits.max_installed => installed.rows.push(row),
                Some(Line::Row(_)) => installed.over_limit += 1,
                Some(Line::NotInstalled) => installed.not_installed += 1,
                None => installed.malformed += 1,
            }
            installed
        }))
}
