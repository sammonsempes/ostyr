#[path = "common/types.rs"]
mod types;


use std::fs;
use tempfile::tempdir;
use types::TestResult;
use virt_inventory::error::FetchError;
use virt_inventory::settings::{check_url, load_settings, validate_settings, FetchSettings, MAX_BYTES_CAP, MAX_TIMEOUT_MS, MIN_TIMEOUT_MS};


const TUNED_BYTES: u64 = 4096;


const LONG_HOST: usize = 300;


const GOOD: &str =
    "api_url: https://pve.example:8006\nca_file: /etc/pve/pve-root-ca.pem\ntoken_file: /run/token\ntenant: acme\ncluster: pve-1\ntimeout_ms: 20000\n";


fn good() -> FetchSettings {
    FetchSettings {
        api_url: "https://pve.example:8006".to_owned(),
        ca_file: "/ca".into(),
        token_file: "/token".into(),
        tenant: "acme".to_owned(),
        cluster: "pve-1".to_owned(),
        timeout_ms: MIN_TIMEOUT_MS,
        limits: Default::default(),
    }
}


fn load(text: &str) -> Result<FetchSettings, FetchError> {
    let directory = tempdir().map_err(FetchError::Body)?;
    let path = directory.path().join("settings.yaml");
    fs::write(&path, text).map_err(FetchError::Body)?;
    load_settings(&path)
}


#[test]
fn a_good_file_loads_with_default_limits() -> TestResult {
    let settings = load(GOOD)?;
    assert_eq!(settings.api_url, "https://pve.example:8006");
    assert_eq!(settings.limits, Default::default());
    let tuned = load(&format!("{GOOD}limits:\n  max_bytes: {TUNED_BYTES}\n"))?;
    assert_eq!(tuned.limits.max_bytes, TUNED_BYTES);
    Ok(())
}


#[test]
fn plain_http_is_refused() -> TestResult {
    let text = GOOD.replace("https://", "http://");
    assert!(matches!(load(&text), Err(FetchError::Url)));
    Ok(())
}


#[test]
fn unknown_fields_and_unknown_limits_are_refused() -> TestResult {
    assert!(matches!(load(&format!("{GOOD}extra: 1\n")), Err(FetchError::Config(_))));
    assert!(matches!(load(&format!("{GOOD}limits:\n  nope: 1\n")), Err(FetchError::Config(_))));
    Ok(())
}


#[test]
fn urls_outside_host_and_port_are_refused() -> TestResult {
    ["https://h:8006", "https://h:8006/", "https://10.0.0.1:8006"]
        .iter()
        .try_for_each(|url| check_url(url))?;
    let refused = [
        "http://h:8006",
        "https://u:p@h:8006",
        "https://h:8006/x",
        "https://h:8006/?a=b",
        "https://h:8006/#f",
        "ftp://h",
        "h:8006",
        "/path",
        "not a url",
        "",
    ];
    refused
        .iter()
        .for_each(|url| assert!(matches!(check_url(url), Err(FetchError::Url)), "{url} was accepted"));
    let long = format!("https://{}", "h".repeat(LONG_HOST));
    assert!(matches!(check_url(&long), Err(FetchError::Url)));
    Ok(())
}


#[test]
fn scope_timeout_and_byte_cap_are_checked() -> TestResult {
    validate_settings(&good())?;
    let mut bad_tenant = good();
    bad_tenant.tenant = "-x".to_owned();
    assert!(matches!(validate_settings(&bad_tenant), Err(FetchError::Scope(_))));
    let mut bad_cluster = good();
    bad_cluster.cluster = "-x".to_owned();
    assert!(matches!(validate_settings(&bad_cluster), Err(FetchError::Scope(_))));
    [MIN_TIMEOUT_MS - 1, MAX_TIMEOUT_MS + 1].iter().for_each(|timeout| {
        let mut settings = good();
        settings.timeout_ms = *timeout;
        assert!(matches!(validate_settings(&settings), Err(FetchError::Timeout)));
    });
    let mut at_max = good();
    at_max.timeout_ms = MAX_TIMEOUT_MS;
    at_max.limits.max_bytes = MAX_BYTES_CAP;
    validate_settings(&at_max)?;
    [0, MAX_BYTES_CAP + 1].iter().for_each(|bytes| {
        let mut settings = good();
        settings.limits.max_bytes = *bytes;
        assert!(matches!(validate_settings(&settings), Err(FetchError::MaxBytes)));
    });
    Ok(())
}
