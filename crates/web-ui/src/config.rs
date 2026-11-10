use crate::error::{ConfigIssue, MAX_API_CONNECTIONS, MAX_TIMEOUT_SECONDS, MIN_TIMEOUT_SECONDS};
use crate::model::{ApiSection, RawApiSection, WebConfig, WebLimits};
use core_api::model::TlsFiles;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::types::ConfigState;
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::{Host, Url};


pub const DEFAULT_LIMITS: WebLimits = WebLimits {
    max_sessions: 10_000,
    session_seconds: 28_800,
    form_timeout: Duration::from_secs(10),
    form_bytes: 8_192,
    login_max: 10,
    login_window_seconds: 60,
    max_sources: 10_000,
};


pub fn is_loopback(url: &Url) -> bool {
    url.host().is_some_and(|host| match host {
        Host::Domain(name) => name == "localhost",
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    })
}


pub fn check_scheme(url: &Url) -> Result<(), ConfigIssue> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(url) => Ok(()),
        _ => Err(ConfigIssue::Scheme),
    }
}


pub fn check_plain(url: &Url) -> Result<(), ConfigIssue> {
    if url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        Err(ConfigIssue::Decorated)
    } else {
        Ok(())
    }
}


pub fn check_timeout(seconds: u64) -> Result<(), ConfigIssue> {
    if (MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&seconds) {
        Ok(())
    } else {
        Err(ConfigIssue::Timeout)
    }
}


pub fn check_connections(count: usize) -> Result<(), ConfigIssue> {
    if (1..=MAX_API_CONNECTIONS).contains(&count) {
        Ok(())
    } else {
        Err(ConfigIssue::Connections)
    }
}


pub fn with_trailing_slash(url: &Url) -> String {
    let text = url.as_str();
    if text.ends_with('/') {
        text.to_owned()
    } else {
        format!("{text}/")
    }
}


impl TryFrom<RawApiSection> for ApiSection {
    type Error = ConfigIssue;

    fn try_from(raw: RawApiSection) -> Result<Self, ConfigIssue> {
        let url = Url::parse(&raw.base_url)?;
        check_scheme(&url)?;
        check_plain(&url)?;
        check_timeout(raw.timeout_seconds)?;
        check_connections(raw.max_connections)?;
        Ok(ApiSection {
            base_url: with_trailing_slash(&url),
            ca: raw.ca,
            timeout_seconds: raw.timeout_seconds,
            max_connections: raw.max_connections,
        })
    }
}


pub fn load_web_config(path: &Path) -> Result<WebConfig, ConfigError> {
    load_file(path)
}


pub fn tls_files(config: &WebConfig) -> Option<TlsFiles> {
    config.tls.as_ref().map(|section| TlsFiles {
        certificate: section.certificate.clone(),
        key: section.key.clone(),
    })
}


/// The settings as `key to text`, the form the reload engine diffs.
pub fn config_state(config: &WebConfig) -> ConfigState {
    let tls = config.tls.iter().flat_map(|section| {
        [
            ("tls.certificate", section.certificate.display().to_string()),
            ("tls.key", section.key.display().to_string()),
        ]
    });
    let ca = config.api.ca.iter().map(|path| ("api.ca", path.display().to_string()));
    [
        ("listen", config.listen.to_string()),
        ("api.base_url", config.api.base_url.clone()),
        ("api.timeout_seconds", config.api.timeout_seconds.to_string()),
        ("api.max_connections", config.api.max_connections.to_string()),
        ("max_sessions_per_user", config.max_sessions_per_user.to_string()),
        ("audit_file", config.audit_file.display().to_string()),
    ]
    .into_iter()
    .chain(tls)
    .chain(ca)
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// The files the watcher follows: the settings file, the certificate pair and the API CA.
pub fn watched_files(settings_file: &Path, config: &WebConfig) -> Vec<PathBuf> {
    let tls = config.tls.iter().flat_map(|section| [section.certificate.clone(), section.key.clone()]);
    std::iter::once(settings_file.to_path_buf())
        .chain(tls)
        .chain(config.api.ca.iter().cloned())
        .collect()
}
