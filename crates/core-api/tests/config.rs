#[path = "support/types.rs"]
mod types;


use core_api::config::{api_config, parse_address, tls_files, DEFAULT_TENANT};
use core_api::error::StartupError;
use core_config::model::ModuleConfig;
use std::path::PathBuf;
use types::TestResult;


fn module(listen: Option<&str>, tenant: Option<&str>, settings: &[(&str, &str)]) -> ModuleConfig {
    ModuleConfig {
        name: "example".to_owned(),
        version: "1.0.0".to_owned(),
        tenant: tenant.map(str::to_owned),
        listen: listen.map(str::to_owned),
        secrets: Default::default(),
        settings: settings.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect(),
    }
}


const REQUIRED: [(&str, &str); 4] = [
    ("accounts_store", "/var/lib/x/accounts.json"),
    ("audit_log", "/var/lib/x/audit.log"),
    ("key_file", "/etc/x/store.key"),
    ("compromised_list", "/etc/x/compromised.txt"),
];


fn with_required(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    REQUIRED.iter().chain(extra.iter()).copied().collect()
}


#[test]
fn a_full_configuration_is_read() -> TestResult {
    let settings = with_required(&[("tls_certificate", "/etc/x/cert.pem"), ("tls_key", "/etc/x/key.pem")]);
    let config = api_config(&module(Some("0.0.0.0:8443"), Some("acme"), &settings))?;
    assert_eq!(config.module, "example");
    assert_eq!(config.tenant, "acme");
    assert_eq!(config.address, "0.0.0.0:8443".parse()?);
    assert_eq!(config.accounts_store, PathBuf::from("/var/lib/x/accounts.json"));
    assert_eq!(config.audit_log, PathBuf::from("/var/lib/x/audit.log"));
    assert_eq!(config.key_file, "/etc/x/store.key");
    assert_eq!(config.compromised_list, PathBuf::from("/etc/x/compromised.txt"));
    let tls = config.tls.ok_or("no tls")?;
    assert_eq!(tls.certificate, PathBuf::from("/etc/x/cert.pem"));
    assert_eq!(tls.key, PathBuf::from("/etc/x/key.pem"));
    Ok(())
}


#[test]
fn the_tenant_defaults_and_tls_is_optional() -> TestResult {
    let config = api_config(&module(Some("127.0.0.1:8443"), None, &with_required(&[])))?;
    assert_eq!(config.tenant, DEFAULT_TENANT);
    assert!(config.tls.is_none());
    Ok(())
}


#[test]
fn tls_files_come_in_pairs() -> TestResult {
    let certificate_only = module(Some("127.0.0.1:1"), None, &[("tls_certificate", "/c")]);
    let key_only = module(Some("127.0.0.1:1"), None, &[("tls_key", "/k")]);
    assert!(matches!(tls_files(&certificate_only), Err(StartupError::IncompleteTls)));
    assert!(matches!(tls_files(&key_only), Err(StartupError::IncompleteTls)));
    Ok(())
}


#[test]
fn missing_and_invalid_settings_are_named() -> TestResult {
    let no_listen = api_config(&module(None, None, &with_required(&[])));
    assert!(matches!(no_listen, Err(StartupError::MissingSetting("listen"))));
    let bad_address = parse_address(&module(Some("not an address"), None, &[]));
    assert!(matches!(bad_address, Err(StartupError::InvalidAddress { .. })));
    assert!(bad_address.is_err_and(|error| error.to_string().contains("not an address")));
    REQUIRED.iter().for_each(|(missing, _)| {
        let others: Vec<(&str, &str)> = REQUIRED.iter().filter(|(name, _)| name != missing).copied().collect();
        let result = api_config(&module(Some("127.0.0.1:1"), None, &others));
        assert!(matches!(result, Err(StartupError::MissingSetting(name)) if name == *missing));
    });
    Ok(())
}
