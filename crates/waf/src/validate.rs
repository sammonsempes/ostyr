use crate::limits::{
    DEFAULT_HEALTH_PATH, DEFAULT_INTERVAL_SECONDS, MAX_BACKENDS, MAX_HOSTS, MAX_HOST_BYTES, MAX_INTERVAL_SECONDS, MAX_LABEL_BYTES, MAX_PATHS,
    MAX_PATH_BYTES, MAX_PORT_DIGITS,
};
use crate::model::{RawHealth, RawRoute, Route};
use serde_json::Value;


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


/// A prefix starting with `/` made of letters, digits and `-._~/`, without `..`.
pub fn check_path(path: &str) -> Result<String, &'static str> {
    let allowed = path
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-._~/".contains(character));
    if path.starts_with('/') && path.len() <= MAX_PATH_BYTES && allowed && !path.contains("..") {
        Ok(path.to_string())
    } else {
        Err(BAD_PATH)
    }
}


/// `host:port` with a valid host and a port from 1 to 65535.
pub fn check_backend(backend: &str) -> Result<String, &'static str> {
    let (host, port) = backend.rsplit_once(':').ok_or(BAD_BACKEND)?;
    let digits = port.len() <= MAX_PORT_DIGITS && port.chars().all(|character| character.is_ascii_digit());
    let number = port.parse::<u16>().ok().filter(|value| digits && *value > 0).ok_or(BAD_BACKEND)?;
    let name = check_host(host).map_err(|_| BAD_BACKEND)?;
    Ok(format!("{name}:{number}"))
}


/// The path prefix as Caddy path patterns: the prefix itself and everything under it.
pub fn path_patterns(prefix: &str) -> Vec<String> {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        vec!["/*".to_string()]
    } else {
        vec![trimmed.to_string(), format!("{trimmed}/*")]
    }
}


/// The health check path and interval, defaults applied.
pub fn check_health(health: Option<RawHealth>) -> Result<(String, u64), &'static str> {
    let (path, interval) = health.map_or((None, None), |value| (value.path, value.interval_seconds));
    let checked = check_path(path.as_deref().unwrap_or(DEFAULT_HEALTH_PATH)).map_err(|_| BAD_HEALTH)?;
    let seconds = interval.unwrap_or(DEFAULT_INTERVAL_SECONDS);
    if (1..=MAX_INTERVAL_SECONDS).contains(&seconds) {
        Ok((checked, seconds))
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
        let checked_paths = raw.paths.iter().map(|path| check_path(path)).collect::<Result<Vec<_>, _>>()?;
        let backends = raw.backends.iter().map(|backend| check_backend(backend)).collect::<Result<Vec<_>, _>>()?;
        let (health_path, interval_seconds) = check_health(raw.health)?;
        Ok(Route {
            hosts,
            paths: checked_paths.iter().flat_map(|prefix| path_patterns(prefix)).collect(),
            backends,
            health_path,
            interval_seconds,
        })
    }
}
