use crate::error::StartupError;
use crate::model::{ApiConfig, Limits, OidcFiles, TlsFiles};
use crate::state::{MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_MAX_REQUESTS, RATE_WINDOW_SECONDS};
use core_config::model::ModuleConfig;
use core_config::types::BoxError;
use ipnet::IpNet;
use std::error::Error;
use std::fmt::Display;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use tracing::level_filters::LevelFilter;


pub const SETTING_TLS_CERTIFICATE: &str = "tls_certificate";


pub const SETTING_TLS_KEY: &str = "tls_key";


pub const SETTING_ACCOUNTS_STORE: &str = "accounts_store";


pub const SETTING_AUDIT_LOG: &str = "audit_log";


pub const SETTING_KEY_FILE: &str = "key_file";


pub const SETTING_COMPROMISED_LIST: &str = "compromised_list";


pub const SETTING_OIDC: &str = "oidc";


pub const SETTING_OIDC_CA_FILE: &str = "oidc_ca_file";


pub const SETTING_OIDC_SECRET_FILE: &str = "oidc_secret_file";


pub const SETTING_RATE_MAX_REQUESTS: &str = "rate_max_requests";


pub const SETTING_RATE_WINDOW_SECONDS: &str = "rate_window_seconds";


pub const SETTING_MAX_SOURCES: &str = "max_sources";


pub const SETTING_MAX_ATTEMPTS: &str = "max_attempts";


pub const SETTING_MAX_CONNECTIONS: &str = "max_connections_per_source";


pub const SETTING_HEADER_TIMEOUT: &str = "header_read_timeout_seconds";


pub const SETTING_BODY_TIMEOUT: &str = "body_read_timeout_seconds";


pub const SETTING_LOG_LEVEL: &str = "log_level";


pub const HEADER_READ_TIMEOUT_SECONDS: u64 = 10;


pub const BODY_READ_TIMEOUT_SECONDS: u64 = 10;


pub const MAX_CONNECTIONS_PER_SOURCE: usize = 64;


pub const MAX_RATE_REQUESTS: u32 = 1_000_000;


pub const MAX_WINDOW_SECONDS: i64 = 86_400;


pub const MAX_TABLE_ENTRIES: usize = 1_000_000;


pub const MAX_CONNECTIONS_CAP: usize = 65_536;


pub const MAX_TIMEOUT_SECONDS: u64 = 3_600;


pub const SETTING_TRUSTED_FORWARDERS: &str = "trusted_forwarders";


pub const MAX_TRUSTED_FORWARDERS: usize = 64;


pub const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::INFO;


pub const DEFAULT_TENANT: &str = "default";


pub fn required_setting<'a>(module: &'a ModuleConfig, name: &'static str) -> Result<&'a String, StartupError> {
    module.settings.get(name).ok_or(StartupError::MissingSetting(name))
}


/// The setting parsed as a number, `default` when absent; a value outside `range` is refused.
pub fn number_setting<Number>(
    module: &ModuleConfig,
    name: &'static str,
    default: Number,
    range: RangeInclusive<Number>,
) -> Result<Number, StartupError>
where
    Number: FromStr + PartialOrd + Display,
    Number::Err: Error + Send + Sync + 'static,
{
    let value = module.settings.get(name).map_or(Ok(default), |text| {
        text.parse::<Number>().map_err(|source| StartupError::InvalidSetting {
            name,
            value: text.clone(),
            source: BoxError::from(source),
        })
    })?;
    if range.contains(&value) {
        Ok(value)
    } else {
        Err(StartupError::OutOfRange {
            name,
            minimum: range.start().to_string(),
            maximum: range.end().to_string(),
        })
    }
}


pub fn log_level(module: &ModuleConfig) -> Result<LevelFilter, StartupError> {
    module.settings.get(SETTING_LOG_LEVEL).map_or(Ok(DEFAULT_LOG_LEVEL), |text| {
        text.parse().map_err(|source| StartupError::InvalidSetting {
            name: SETTING_LOG_LEVEL,
            value: text.clone(),
            source: BoxError::from(source),
        })
    })
}


pub fn limits(module: &ModuleConfig) -> Result<Limits, StartupError> {
    Ok(Limits {
        rate_max_requests: number_setting(module, SETTING_RATE_MAX_REQUESTS, RATE_MAX_REQUESTS, 1..=MAX_RATE_REQUESTS)?,
        rate_window_seconds: number_setting(module, SETTING_RATE_WINDOW_SECONDS, RATE_WINDOW_SECONDS, 1..=MAX_WINDOW_SECONDS)?,
        max_sources: number_setting(module, SETTING_MAX_SOURCES, MAX_TRACKED_SOURCES, 1..=MAX_TABLE_ENTRIES)?,
        max_attempts: number_setting(module, SETTING_MAX_ATTEMPTS, MAX_TRACKED_ATTEMPTS, 1..=MAX_TABLE_ENTRIES)?,
        body_read_timeout: Duration::from_secs(number_setting(
            module,
            SETTING_BODY_TIMEOUT,
            BODY_READ_TIMEOUT_SECONDS,
            1..=MAX_TIMEOUT_SECONDS,
        )?),
        max_connections_per_source: number_setting(module, SETTING_MAX_CONNECTIONS, MAX_CONNECTIONS_PER_SOURCE, 1..=MAX_CONNECTIONS_CAP)?,
    })
}


/// One forwarder entry: a CIDR, or a single address (a host network).
pub fn parse_forwarder(text: &str) -> Result<IpNet, StartupError> {
    text.parse::<IpNet>()
        .or_else(|_| text.parse::<IpAddr>().map(IpNet::from))
        .map_err(|source| StartupError::InvalidSetting {
            name: SETTING_TRUSTED_FORWARDERS,
            value: text.to_owned(),
            source: BoxError::from(source),
        })
}


/// The comma separated `trusted_forwarders` setting (default empty); more than `MAX_TRUSTED_FORWARDERS` entries or an empty entry is refused.
pub fn forwarders(module: &ModuleConfig) -> Result<Vec<IpNet>, StartupError> {
    let text = module.settings.get(SETTING_TRUSTED_FORWARDERS).map_or("", |value| value.trim());
    let entries: Vec<&str> = text.split(',').map(str::trim).filter(|_| !text.is_empty()).collect();
    if entries.len() > MAX_TRUSTED_FORWARDERS {
        Err(StartupError::OutOfRange {
            name: SETTING_TRUSTED_FORWARDERS,
            minimum: "0".to_owned(),
            maximum: MAX_TRUSTED_FORWARDERS.to_string(),
        })
    } else {
        entries.into_iter().map(parse_forwarder).collect()
    }
}


pub fn parse_address(module: &ModuleConfig) -> Result<SocketAddr, StartupError> {
    let value = module.listen.as_ref().ok_or(StartupError::MissingSetting("listen"))?;
    value.parse().map_err(|source| StartupError::InvalidAddress {
        value: value.clone(),
        source,
    })
}


pub fn tls_files(module: &ModuleConfig) -> Result<Option<TlsFiles>, StartupError> {
    match (module.settings.get(SETTING_TLS_CERTIFICATE), module.settings.get(SETTING_TLS_KEY)) {
        (Some(certificate), Some(key)) => Ok(Some(TlsFiles {
            certificate: PathBuf::from(certificate),
            key: PathBuf::from(key),
        })),
        (None, None) => Ok(None),
        _ => Err(StartupError::IncompleteTls),
    }
}


pub fn oidc_files(module: &ModuleConfig) -> Result<Option<OidcFiles>, StartupError> {
    match (module.settings.get(SETTING_OIDC), module.settings.get(SETTING_OIDC_SECRET_FILE)) {
        (Some(config), Some(secret)) => Ok(Some(OidcFiles {
            config: PathBuf::from(config),
            ca_file: module.settings.get(SETTING_OIDC_CA_FILE).map(PathBuf::from),
            secret_file: PathBuf::from(secret),
        })),
        (None, None) => Ok(None),
        _ => Err(StartupError::IncompleteOidc),
    }
}


pub fn api_config(module: &ModuleConfig) -> Result<ApiConfig, StartupError> {
    Ok(ApiConfig {
        module: module.name.clone(),
        tenant: module.tenant.clone().unwrap_or_else(|| DEFAULT_TENANT.to_owned()),
        address: parse_address(module)?,
        tls: tls_files(module)?,
        accounts_store: PathBuf::from(required_setting(module, SETTING_ACCOUNTS_STORE)?),
        audit_log: PathBuf::from(required_setting(module, SETTING_AUDIT_LOG)?),
        key_file: required_setting(module, SETTING_KEY_FILE)?.clone(),
        compromised_list: PathBuf::from(required_setting(module, SETTING_COMPROMISED_LIST)?),
        header_read_timeout: Duration::from_secs(number_setting(
            module,
            SETTING_HEADER_TIMEOUT,
            HEADER_READ_TIMEOUT_SECONDS,
            1..=MAX_TIMEOUT_SECONDS,
        )?),
        limits: limits(module)?,
        log_level: log_level(module)?,
        oidc: oidc_files(module)?,
    })
}
