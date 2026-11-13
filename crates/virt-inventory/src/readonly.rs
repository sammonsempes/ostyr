use crate::error::ReadOnlyError;
use crate::model::Permissions;
use std::collections::BTreeSet;


pub const ALLOWED_PRIVILEGES: [&str; 6] = ["VM.Audit", "Sys.Audit", "Datastore.Audit", "SDN.Audit", "Pool.Audit", "Mapping.Audit"];


pub const MAX_REPORTED: usize = 32;


/// Every privilege on every path must be in `ALLOWED_PRIVILEGES` whatever its flag; no privilege at all is refused too (a token that reads nothing is a misconfiguration).
pub fn check_read_only(permissions: &Permissions) -> Result<(), ReadOnlyError> {
    let granted = permissions
        .paths
        .iter()
        .flat_map(|entry| entry.privileges.keys().map(String::as_str))
        .collect::<BTreeSet<_>>();
    let refused = granted
        .iter()
        .filter(|name| !ALLOWED_PRIVILEGES.contains(name))
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    if granted.is_empty() {
        Err(ReadOnlyError::NoRights)
    } else if refused.is_empty() {
        Ok(())
    } else {
        Err(ReadOnlyError::HasWriteRights {
            omitted: refused.len().saturating_sub(MAX_REPORTED),
            privileges: refused.into_iter().take(MAX_REPORTED).collect(),
        })
    }
}
