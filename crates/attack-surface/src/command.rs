use crate::error::CommandError;
use crate::model::{PortRange, Scope};
use crate::text::{shown, valid_argument};
use crate::types::ArgsResult;
use std::ffi::OsString;


pub const MAX_VALUE_BYTES: usize = 4096;


pub const FIXED_ARGUMENTS: [&str; 2] = ["-json", "-silent"];


/// The port list in naabu's `-p` syntax: `22,80,8000-8100`.
pub fn ports_text(ranges: &[PortRange]) -> String {
    ranges
        .iter()
        .map(|range| {
            if range.first == range.last {
                range.first.to_string()
            } else {
                format!("{}-{}", range.first, range.last)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}


fn safe_value(value: &str) -> Result<(), CommandError> {
    valid_argument(value, MAX_VALUE_BYTES)
        .then_some(())
        .ok_or_else(|| CommandError::BadValue { shown: shown(value) })
}


/// The argument vector of one naabu run (never a shell string): `target` must be one of `scope.targets` and no value may start with `-`.
pub fn naabu_args(scope: &Scope, target: &str) -> ArgsResult {
    scope
        .targets
        .iter()
        .any(|listed| listed == target)
        .then_some(())
        .ok_or_else(|| CommandError::UnknownTarget { shown: shown(target) })?;
    let ports = ports_text(&scope.ports);
    safe_value(target)?;
    safe_value(&ports)?;
    let rate = scope.rate_per_second.to_string();
    Ok(FIXED_ARGUMENTS
        .iter()
        .copied()
        .chain(["-rate", &rate, "-p", &ports, "-host", target])
        .map(OsString::from)
        .collect())
}
