use crate::error::StartupError;
use crate::model::{ApiConfig, TlsFiles};
use core_config::model::ModuleConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;


pub const SETTING_TLS_CERTIFICATE: &str = "tls_certificate";


pub const SETTING_TLS_KEY: &str = "tls_key";


pub const SETTING_ACCOUNTS_STORE: &str = "accounts_store";


pub const SETTING_AUDIT_LOG: &str = "audit_log";


pub const SETTING_KEY_FILE: &str = "key_file";


pub const SETTING_COMPROMISED_LIST: &str = "compromised_list";


pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);


pub const MAX_CONNECTIONS_PER_SOURCE: usize = 64;


pub const DEFAULT_TENANT: &str = "default";


pub fn required_setting<'a>(module: &'a ModuleConfig, name: &'static str) -> Result<&'a String, StartupError> {
    module.settings.get(name).ok_or(StartupError::MissingSetting(name))
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
        header_read_timeout: HEADER_READ_TIMEOUT,
        max_connections_per_source: MAX_CONNECTIONS_PER_SOURCE,
    })
}
