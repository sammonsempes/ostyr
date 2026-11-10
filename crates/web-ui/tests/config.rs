#[path = "support/types.rs"]
mod types;


use rcgen::generate_simple_self_signed;
use std::error::Error;
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use types::TestResult;
use web_ui::client::{add_bundle, build_client, client_tls, MAX_CA_CERTIFICATES};
use web_ui::config::{config_state, load_web_config, tls_files, watched_files};
use web_ui::error::WebError;
use web_ui::model::{ApiSection, RawApiSection, WebConfig};


const CONNECTIONS: usize = 4;


const SET_CONNECTIONS: usize = 7;


const SET_SESSIONS: usize = 3;


const TIMEOUT: u64 = 5;


const WATCHED_WITH_TLS: usize = 4;


const PLAIN_KEYS: usize = 6;


const GOOD_COUNT: usize = 2;


const HUGE_BYTES: usize = 1_048_577;


const BASE: &str = "https://api.example.test:8443/v1";


fn yaml(extra_api: &str, tls: &str) -> String {
    format!("listen: 127.0.0.1:8443\n{tls}api:\n  base_url: {BASE}\n  timeout_seconds: 5\n{extra_api}audit_file: /var/lib/web-ui/audit.log\n")
}


fn load(text: &str) -> Result<WebConfig, Box<dyn Error>> {
    let dir = tempdir()?;
    let file = dir.path().join("web-ui.yaml");
    fs::write(&file, text)?;
    Ok(load_web_config(&file)?)
}


fn refused(base_url: &str, timeout_seconds: &str) -> bool {
    let text = format!("listen: 127.0.0.1:1\napi:\n  base_url: \"{base_url}\"\n  timeout_seconds: {timeout_seconds}\naudit_file: /a\n");
    load(&text).is_err()
}


fn bundle(dir: &Path, name: &str, count: usize) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let pem: String = (0..count)
        .map(|_| generate_simple_self_signed(vec!["localhost".to_owned()]).map(|made| made.cert.pem()))
        .collect::<Result<Vec<_>, _>>()?
        .concat();
    let path = dir.join(name);
    fs::write(&path, pem)?;
    Ok(path)
}


#[test]
fn a_full_file_loads_with_a_normalised_base_url() -> TestResult {
    let config = load(&yaml("  ca: /etc/ca.pem\n", "tls:\n  certificate: /c.pem\n  key: /k.pem\n"))?;
    assert_eq!(config.api.base_url, format!("{BASE}/"));
    assert_eq!(config.api.timeout_seconds, TIMEOUT);
    assert_eq!(config.api.ca.as_deref(), Some(Path::new("/etc/ca.pem")));
    let files = tls_files(&config).ok_or("no tls")?;
    assert_eq!(files.key, Path::new("/k.pem"));
    let state = config_state(&config);
    assert_eq!(state.get("api.ca").map(String::as_str), Some("/etc/ca.pem"));
    assert_eq!(state.get("tls.key").map(String::as_str), Some("/k.pem"));
    assert_eq!(state.get("listen").map(String::as_str), Some("127.0.0.1:8443"));
    let watched = watched_files(Path::new("/s.yaml"), &config);
    assert_eq!(watched.len(), WATCHED_WITH_TLS);
    let plain = load(&yaml("", ""))?;
    assert!(tls_files(&plain).is_none());
    assert_eq!(watched_files(Path::new("/s.yaml"), &plain).len(), 1);
    assert_eq!(config_state(&plain).len(), PLAIN_KEYS);
    Ok(())
}


#[test]
fn api_section_rules() -> TestResult {
    assert!(!refused("https://api.example.test/", "5"));
    assert!(!refused("http://127.0.0.1:9/", "5"));
    assert!(!refused("http://localhost:9/x/", "60"));
    assert!(!refused("http://[::1]:9/", "1"));
    assert!(refused("http://api.example.test/", "5"));
    assert!(refused("ftp://127.0.0.1/", "5"));
    assert!(refused("not a url", "5"));
    assert!(refused("https://user:pw@api.example.test/", "5"));
    assert!(refused("https://user@api.example.test/", "5"));
    assert!(refused("https://:pw@api.example.test/", "5"));
    assert!(refused("https://api.example.test/?x=1", "5"));
    assert!(refused("https://api.example.test/#frag", "5"));
    assert!(refused("https://api.example.test/", "0"));
    assert!(refused("https://api.example.test/", "61"));
    Ok(())
}


#[test]
fn unknown_keys_are_refused() -> TestResult {
    assert!(load("listen: 127.0.0.1:1\nsurprise: 1\napi:\n  base_url: https://a.test/\n  timeout_seconds: 5\naudit_file: /a\n").is_err());
    Ok(())
}


#[test]
fn raw_section_converts() -> TestResult {
    let converted = ApiSection::try_from(RawApiSection {
        base_url: "https://a.test/v1/".to_owned(),
        ca: None,
        timeout_seconds: TIMEOUT,
        max_connections: CONNECTIONS,
    })?;
    assert_eq!(converted.base_url, "https://a.test/v1/");
    Ok(())
}


#[test]
fn ca_bundles_are_checked() -> TestResult {
    let dir = tempdir()?;
    let good = bundle(dir.path(), "good.pem", GOOD_COUNT)?;
    assert!(client_tls(Some(&good)).is_ok());
    assert!(client_tls(None).is_ok());
    let empty = dir.path().join("empty.pem");
    fs::write(&empty, "")?;
    assert!(matches!(client_tls(Some(&empty)), Err(WebError::NoCertificate { .. })));
    let many = bundle(dir.path(), "many.pem", MAX_CA_CERTIFICATES + 1)?;
    assert!(matches!(client_tls(Some(&many)), Err(WebError::TooManyCertificates { .. })));
    assert!(matches!(client_tls(Some(&dir.path().join("absent.pem"))), Err(WebError::Io(_))));
    let garbage = dir.path().join("garbage.pem");
    fs::write(&garbage, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")?;
    assert!(matches!(client_tls(Some(&garbage)), Err(WebError::Tls(_))));
    let broken = dir.path().join("broken.pem");
    fs::write(&broken, "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")?;
    assert!(matches!(client_tls(Some(&broken)), Err(WebError::Pem(_))));
    let huge = dir.path().join("huge.pem");
    fs::write(&huge, vec![b'#'; HUGE_BYTES])?;
    assert!(matches!(client_tls(Some(&huge)), Err(WebError::Config(_))));
    let mut roots = rustls::RootCertStore::empty();
    assert!(add_bundle(&mut roots, &good).is_ok());
    assert_eq!(roots.len(), GOOD_COUNT);
    Ok(())
}


#[test]
fn clients_are_built() -> TestResult {
    let dir = tempdir()?;
    let ca = bundle(dir.path(), "ca.pem", 1)?;
    let api = ApiSection {
        base_url: "https://a.test/".to_owned(),
        ca: Some(ca),
        timeout_seconds: TIMEOUT,
        max_connections: CONNECTIONS,
    };
    assert_eq!(build_client(&api)?.base, "https://a.test/");
    Ok(())
}


#[test]
fn connection_and_session_caps_are_settings_with_ranges() -> TestResult {
    let defaults = load(&yaml("", ""))?;
    assert_eq!(defaults.api.max_connections, web_ui::model::DEFAULT_API_CONNECTIONS);
    assert_eq!(defaults.max_sessions_per_user, web_ui::model::DEFAULT_USER_SESSIONS);
    let set = load(
        &yaml(&format!("  max_connections: {SET_CONNECTIONS}\n"), "")
            .replace("audit_file", &format!("max_sessions_per_user: {SET_SESSIONS}\naudit_file")),
    )?;
    assert_eq!((set.api.max_connections, set.max_sessions_per_user), (SET_CONNECTIONS, SET_SESSIONS));
    assert!(load(&yaml("  max_connections: 0\n", "")).is_err());
    assert!(load(&yaml("  max_connections: 61\n", "")).is_err());
    assert!(web_ui::client::check_user_sessions(1).is_ok());
    assert!(web_ui::client::check_user_sessions(0).is_err());
    assert!(web_ui::client::check_user_sessions(web_ui::error::MAX_USER_SESSIONS + 1).is_err());
    let invalid = WebConfig {
        max_sessions_per_user: 0,
        ..defaults
    };
    assert!(web_ui::client::prepare(&invalid).is_err());
    Ok(())
}
