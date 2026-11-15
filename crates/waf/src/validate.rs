use crate::limits::{
    ADMIN_PORT, DEFAULT_HEALTH_PATH, DEFAULT_INTERVAL_SECONDS, DOUBLE_SLASH, MAX_BACKENDS, MAX_HOSTS, MAX_HOST_BYTES, MAX_INTERVAL_SECONDS,
    MAX_LABEL_BYTES, MAX_PATHS, MAX_PATH_BYTES, MAX_PORT_DIGITS,
};
use crate::model::{RawHealth, RawRoute, Route};
use serde_json::Value;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;


pub const MALFORMED: &str = "malformed route";


pub const TOO_MANY_HOSTS: &str = "too many hosts";


pub const TOO_MANY_PATHS: &str = "too many paths";


pub const TOO_MANY_BACKENDS: &str = "too many backends";


pub const NO_HOST: &str = "no host";


pub const NO_BACKEND: &str = "no backend";


pub const BAD_HOST: &str = "invalid host";


pub const BAD_PATH: &str = "invalid path";


pub const BAD_BACKEND: &str = "invalid backend";


pub const BAD_HEALTH: &str = "invalid health check";


/// A route whose host list repeats a host.
pub const REPEATED_HOST: &str = "repeated host";


/// A route overlapping an earlier one.
pub const SHADOWED: &str = "shadowed by route";


const LIST_LIMITS: [(&str, usize, &str); 3] = [
    ("hosts", MAX_HOSTS, TOO_MANY_HOSTS),
    ("paths", MAX_PATHS, TOO_MANY_PATHS),
    ("backends", MAX_BACKENDS, TOO_MANY_BACKENDS),
];


fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_BYTES
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|character| character.is_ascii_alphanumeric() || character == '-')
}


/// An ASCII DNS name: labels of letters, digits and inner hyphens, lowercased.
pub fn check_host(host: &str) -> Result<String, &'static str> {
    if host.len() <= MAX_HOST_BYTES && host.split('.').all(valid_label) {
        Ok(host.to_ascii_lowercase())
    } else {
        Err(BAD_HOST)
    }
}


/// A path starting with `/` made of letters, digits and `-._~/`, with no segment ending in a dot.
pub fn check_raw_path(path: &str) -> Result<&str, &'static str> {
    let allowed = path
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-._~/".contains(character));
    let dotted = path.split('/').any(|segment| segment.ends_with('.'));
    if path.starts_with('/') && path.len() <= MAX_PATH_BYTES && allowed && !dotted {
        Ok(path)
    } else {
        Err(BAD_PATH)
    }
}


/// A path prefix: a valid path without `//`, lowercased because Caddy matches paths case-insensitively.
pub fn check_path(path: &str) -> Result<String, &'static str> {
    let checked = check_raw_path(path)?;
    if checked.contains(DOUBLE_SLASH) {
        Err(BAD_PATH)
    } else {
        Ok(checked.to_ascii_lowercase())
    }
}


/// A name or address that reaches the local machine, numeric forms such as `2130706433` or `0x7f.0.0.1` included.
pub fn is_local(host: &str) -> bool {
    let numeric = host
        .rsplit('.')
        .next()
        .is_some_and(|label| label.starts_with(|character: char| character.is_ascii_digit()));
    if numeric {
        host.parse::<Ipv4Addr>()
            .map_or(true, |address| address.is_loopback() || address.is_unspecified())
    } else {
        host == "localhost" || host.ends_with(".localhost")
    }
}


/// `host:port` with a valid host and a port from 1 to 65535, never the local admin API port.
pub fn check_backend(backend: &str) -> Result<String, &'static str> {
    let (host, port) = backend.rsplit_once(':').ok_or(BAD_BACKEND)?;
    let digits = port.len() <= MAX_PORT_DIGITS && port.chars().all(|character| character.is_ascii_digit());
    let number = port.parse::<u16>().ok().filter(|value| digits && *value > 0).ok_or(BAD_BACKEND)?;
    let name = check_host(host).map_err(|_| BAD_BACKEND)?;
    if number == ADMIN_PORT && is_local(&name) {
        Err(BAD_BACKEND)
    } else {
        Ok(format!("{name}:{number}"))
    }
}


/// The prefix without its trailing slashes: the empty string stands for the root.
pub fn prefix_key(prefix: &str) -> &str {
    prefix.trim_end_matches('/')
}


/// The path prefix as Caddy path patterns: the prefix itself and everything under it.
pub fn path_patterns(prefix: &str) -> Vec<String> {
    let trimmed = prefix_key(prefix);
    if trimmed.is_empty() {
        vec!["/*".to_string()]
    } else {
        vec![trimmed.to_string(), format!("{trimmed}/*")]
    }
}


/// The health check path and interval, defaults applied.
pub fn check_health(health: Option<RawHealth>) -> Result<(String, u64), &'static str> {
    let (path, interval) = health.map_or((None, None), |value| (value.path, value.interval_seconds));
    let checked = check_raw_path(path.as_deref().unwrap_or(DEFAULT_HEALTH_PATH)).map_err(|_| BAD_HEALTH)?;
    let authority = checked.starts_with(DOUBLE_SLASH);
    let seconds = interval.unwrap_or(DEFAULT_INTERVAL_SECONDS);
    if !authority && (1..=MAX_INTERVAL_SECONDS).contains(&seconds) {
        Ok((checked.to_string(), seconds))
    } else {
        Err(BAD_HEALTH)
    }
}


/// Each list is counted on the value before any element is converted.
pub fn check_counts(value: &Value) -> Result<(), &'static str> {
    LIST_LIMITS.iter().try_for_each(|(key, max, reason)| {
        let length = value.get(key).and_then(Value::as_array).map_or(0, Vec::len);
        if length > *max {
            Err(*reason)
        } else {
            Ok(())
        }
    })
}


/// Converts one route value, or says why the route is refused.
pub fn convert_route(value: Value) -> Result<Route, &'static str> {
    check_counts(&value)?;
    let raw: RawRoute = serde_json::from_value(value).map_err(|_| MALFORMED)?;
    if raw.hosts.is_empty() {
        Err(NO_HOST)
    } else if raw.backends.is_empty() {
        Err(NO_BACKEND)
    } else {
        let hosts = raw.hosts.iter().map(|host| check_host(host)).collect::<Result<Vec<_>, _>>()?;
        let distinct_hosts = hosts.iter().collect::<BTreeSet<_>>().len();
        if distinct_hosts != hosts.len() {
            Err(REPEATED_HOST)?;
        }
        let checked_paths = raw.paths.iter().map(|path| check_path(path)).collect::<Result<Vec<_>, _>>()?;
        let backends = raw.backends.iter().map(|backend| check_backend(backend)).collect::<Result<Vec<_>, _>>()?;
        let (health_path, interval_seconds) = check_health(raw.health)?;
        Ok(Route {
            hosts,
            prefixes: checked_paths,
            backends,
            health_path,
            interval_seconds,
        })
    }
}
