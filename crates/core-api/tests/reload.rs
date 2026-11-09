#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/types.rs"]
mod types;


use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use core_api::config::{
    api_config, limits, log_level, DEFAULT_LOG_LEVEL, MAX_CONNECTIONS_CAP, MAX_CONNECTIONS_PER_SOURCE, MAX_RATE_REQUESTS, MAX_TABLE_ENTRIES,
    MAX_TIMEOUT_SECONDS, MAX_WINDOW_SECONDS,
};
use core_api::error::StartupError;
use core_api::logging::reloadable_dispatch;
use core_api::middleware::admit_source;
use core_api::model::{ApiConfig, ApiState, Bound, ListenerSetup, OidcFiles, PreparedAudit, Rewatch, StateInputs, Watching};
use core_api::model::{ApiError, ApiSettings};
use core_api::oidc::{fingerprint_salt, oidc_fingerprint, settle, store_pending, take_login};
#[cfg(unix)]
use core_api::previous::{check_previous_slot, read_previous_key};
use core_api::previous::{
    remove_synced, retire_previous, retire_previous_with, write_previous_key, PREVIOUS_KEY_REMOVAL_FAILED, PREVIOUS_KEY_REMOVED, PREVIOUS_KEY_SAVED,
    ROTATION_RESUMED,
};
use core_api::reload::{
    accept, build_settings, check_store, content_digest, first_then_file, follow_files, load_settings, open_reload, prepare_key, read_store_handle,
    reseal_accounts, rewatch, settings_state, store_sealed_under, switch_audit, switch_identity, switch_key, switch_store, watched_files,
    FINGERPRINT_COMPROMISED, FINGERPRINT_KEY, FINGERPRINT_OIDC, FINGERPRINT_TLS_CERTIFICATE, FINGERPRINT_TLS_KEY,
};
use core_api::routes::build_router;
use core_api::server::{
    bind_socket, current_handle, finish, listening_address, load_tls, new_listener, retire_socket, run_module, start_first, stop_listener,
    wait_finished,
};
use core_api::state::{
    build_state, lock_auth, previous_key_path, read_compromised_digested, MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_MAX_REQUESTS,
    RATE_WINDOW_SECONDS,
};
use core_api::types::{LogLevelHandle, SharedListener, SharedState};
use core_audit::log::LogState;
use core_audit::model::GENESIS_HASH;
use core_audit::verify::verify;
use core_auth::model::{Account, Session, TotpEnrolment};
use core_auth::oidc::{Callback, Identity};
use core_auth::password::hash_password;
use core_auth::random::os_random;
use core_auth::secretbox::{open_secret, seal_secret};
use core_auth::session::hash_token;
use core_auth::store::{load_store_file, lock_path, save_store_file, update_store_file};
use core_auth::totp::{code_for_step, unix_seconds, TOTP_STEP_SECONDS};
use core_auth::types::{AccountMap, CredentialMap, StoreKey};
use core_config::error::ConfigError;
use core_config::load::load_module;
use core_config::model::ModuleConfig;
use core_config::reload::{reload, ReloadContext, ReloadEngine, ReloadOutcome};
use fixture::{extra_access, extra_router, fixture, private_file, set_mode};
use rcgen::generate_simple_self_signed;
use rustls::crypto::ring::default_provider;
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName};
use secrecy::{ExposeSecret, SecretSlice};
use std::fs;
use std::future::Future;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tower::ServiceExt;
use tracing::level_filters::LevelFilter;
use types::{TestError, TestResult};


const LOCALHOST_NAME: &str = "localhost";


const LOOPBACK: &str = "127.0.0.1:0";


const HEALTH_REQUEST: &str = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";


const LOW_LIMIT: u32 = 2;


const ALT_REQUESTS: u32 = 7;


const ALT_WINDOW: i64 = 9;


const ALT_SOURCES: usize = 11;


const ALT_ATTEMPTS: usize = 13;


const ALT_CONNECTIONS: usize = 15;


const PLAIN_FILES: usize = 3;


const WITHOUT_CA_FILES: usize = 7;


const WITH_CA_FILES: usize = 8;


const TWO_RECORDS: usize = 2;


const FOUR_RECORDS: usize = 4;


const HIGH_LIMIT: u32 = 1000;


const SOURCES: usize = 3;


const POLLS: usize = 100;


const POLL_PAUSE: Duration = Duration::from_millis(100);


const BODY_SECONDS: u64 = 3;


const WORLD_READABLE: u32 = 0o644;


const OWNER_ONLY: u32 = 0o600;


#[cfg(unix)]
const PERMISSION_BITS: u32 = 0o777;


const OIDC_TEXT: &str = "issuer: https://idp.example\nclient_id: test-client\nclient_secret: vault://kv/oidc\nredirect_url: https://ostyr.example/auth/oidc/callback\nrole_map:\n  soc-analysts: [analyst]\n";


const OTHER_OIDC_TEXT: &str = "issuer: https://other.example\nclient_id: test-client\nclient_secret: vault://kv/oidc\nredirect_url: https://ostyr.example/auth/oidc/callback\nrole_map:\n  soc-analysts: [analyst]\n";


struct Pki {
    certificate: String,
    key: String,
    der: CertificateDer<'static>,
}


struct Live {
    dir: TempDir,
    module_file: PathBuf,
    state: SharedState,
    engine: Arc<ReloadEngine<ApiSettings>>,
    tls: Option<axum_server::tls_rustls::RustlsConfig>,
    _runtime: tokio::runtime::Runtime,
    listener: SharedListener,
    setup: ListenerSetup,
}


fn pki() -> Result<Pki, TestError> {
    let generated = generate_simple_self_signed(vec![LOCALHOST_NAME.to_owned()])?;
    Ok(Pki {
        certificate: generated.cert.pem(),
        key: generated.signing_key.serialize_pem(),
        der: generated.cert.der().clone(),
    })
}


fn write_pki(dir: &Path, material: &Pki) -> Result<(), TestError> {
    private_file(&dir.join("server.key"), material.key.as_bytes())?;
    fs::write(dir.join("server.pem"), &material.certificate)?;
    Ok(())
}


fn tls_extra(dir: &Path) -> String {
    format!(
        "  tls_certificate: {}\n  tls_key: {}\n",
        dir.join("server.pem").display(),
        dir.join("server.key").display()
    )
}


fn module_text(dir: &Path, name: &str, listen: &str, extra: &str) -> Result<String, TestError> {
    let key_file = dir.join("store.key");
    private_file(&key_file, &[fixture::KEY_FILL; fixture::KEY_BYTES])?;
    let compromised = dir.join("compromised.txt");
    if !compromised.exists() {
        fs::write(&compromised, "passwordpassword\n")?;
    }
    Ok(format!(
        "name: {name}\nversion: 1.0.0\nlisten: \"{listen}\"\nsettings:\n  accounts_store: {}\n  audit_log: {}\n  key_file: {}\n  compromised_list: {}\n{extra}",
        dir.join("accounts.json").display(),
        dir.join("audit.log").display(),
        key_file.display(),
        compromised.display(),
    ))
}


fn write_module(dir: &Path, extra: &str) -> Result<PathBuf, TestError> {
    let path = dir.join("module.yaml");
    fs::write(&path, module_text(dir, "example", LOOPBACK, extra)?)?;
    Ok(path)
}


fn module_in(dir: &Path, extra: &str) -> Result<ModuleConfig, TestError> {
    Ok(load_module(&write_module(dir, extra)?)?)
}


fn live_with(dir: TempDir, extra: &str, log: Option<LogLevelHandle>) -> Result<Live, TestError> {
    let module_file = write_module(dir.path(), extra)?;
    let settings = build_settings(load_module(&module_file)?)?;
    let inputs = StateInputs {
        key: settings.key.clone(),
        compromised: settings.compromised.clone(),
        oidc: settings.oidc.clone(),
    };
    let state: SharedState = Arc::new(build_state(&settings.config, &inputs, extra_access(), Vec::new())?);
    let tls = settings.tls.clone().map(axum_server::tls_rustls::RustlsConfig::from_config);
    let runtime = tokio::runtime::Runtime::new()?;
    let listener = new_listener();
    let setup = ListenerSetup {
        listener: listener.clone(),
        router: build_router(state.clone(), extra_router()),
        limits: state.limits.clone(),
        runtime: runtime.handle().clone(),
        rewatch: Arc::new(Rewatch::default()),
    };
    let config = settings.config.clone();
    let engine = open_reload(&state, settings, &module_file, setup.clone(), log)?;
    *setup.rewatch.watching.lock().map_err(|_| "poisoned")? = Some(Watching {
        files: watched_files(&module_file, &config),
        guard: Box::new(()),
    });
    start_first(&setup, &config, tls.clone())?;
    Ok(Live {
        dir,
        module_file,
        state,
        engine,
        tls,
        _runtime: runtime,
        listener,
        setup,
    })
}


fn live(extra: &str) -> Result<Live, TestError> {
    live_with(tempdir()?, extra, None)
}


fn rewrite(live: &Live, extra: &str) -> Result<(), TestError> {
    fs::write(&live.module_file, module_text(live.dir.path(), "example", LOOPBACK, extra)?)?;
    Ok(())
}


fn reload_records(dir: &Path) -> Result<Vec<String>, TestError> {
    Ok(fs::read_to_string(dir.join("audit.log"))?
        .lines()
        .filter(|line| line.contains("config.reload"))
        .map(str::to_owned)
        .collect())
}


fn peer() -> Result<IpAddr, TestError> {
    Ok("10.0.0.1".parse()?)
}


#[test]
fn limits_default_to_the_constants_and_read_the_settings() -> TestResult {
    let dir = tempdir()?;
    let defaults = limits(&module_in(dir.path(), "")?)?;
    assert_eq!(defaults.rate_max_requests, RATE_MAX_REQUESTS);
    assert_eq!(defaults.rate_window_seconds, RATE_WINDOW_SECONDS);
    assert_eq!(defaults.max_sources, MAX_TRACKED_SOURCES);
    assert_eq!(defaults.max_attempts, MAX_TRACKED_ATTEMPTS);
    assert_eq!(defaults.max_connections_per_source, MAX_CONNECTIONS_PER_SOURCE);
    assert_eq!(log_level(&module_in(dir.path(), "")?)?, DEFAULT_LOG_LEVEL);
    let extra = "  rate_max_requests: 7\n  rate_window_seconds: 9\n  max_sources: 11\n  max_attempts: 13\n  max_connections_per_source: 15\n  body_read_timeout_seconds: 3\n  log_level: debug\n";
    let module = module_in(dir.path(), extra)?;
    let changed = limits(&module)?;
    assert_eq!((changed.rate_max_requests, changed.rate_window_seconds), (ALT_REQUESTS, ALT_WINDOW));
    assert_eq!(
        (changed.max_sources, changed.max_attempts, changed.max_connections_per_source),
        (ALT_SOURCES, ALT_ATTEMPTS, ALT_CONNECTIONS)
    );
    assert_eq!(changed.body_read_timeout, Duration::from_secs(BODY_SECONDS));
    assert_eq!(log_level(&module)?, LevelFilter::DEBUG);
    Ok(())
}


#[test]
fn bad_numbers_zero_and_unknown_levels_are_refused() -> TestResult {
    let dir = tempdir()?;
    let invalid = limits(&module_in(dir.path(), "  rate_max_requests: many\n")?);
    assert!(matches!(
        invalid,
        Err(StartupError::InvalidSetting {
            name: "rate_max_requests",
            ..
        })
    ));
    assert!(invalid.is_err_and(|error| error.to_string().contains("many")));
    let zero = limits(&module_in(dir.path(), "  max_sources: 0\n")?);
    assert!(matches!(zero, Err(StartupError::OutOfRange { name: "max_sources", .. })));
    let level = log_level(&module_in(dir.path(), "  log_level: loud\n")?);
    assert!(matches!(level, Err(StartupError::InvalidSetting { name: "log_level", .. })));
    Ok(())
}


#[test]
fn every_numeric_setting_has_a_valid_range() -> TestResult {
    let dir = tempdir()?;
    let over_requests = MAX_RATE_REQUESTS + 1;
    let over_window = MAX_WINDOW_SECONDS + 1;
    let over_entries = MAX_TABLE_ENTRIES + 1;
    let over_connections = MAX_CONNECTIONS_CAP + 1;
    let over_timeout = MAX_TIMEOUT_SECONDS + 1;
    let bad = [
        ("rate_max_requests", over_requests.to_string()),
        ("rate_window_seconds", over_window.to_string()),
        ("rate_window_seconds", "-5".to_owned()),
        ("rate_window_seconds", "0".to_owned()),
        ("max_sources", over_entries.to_string()),
        ("max_sources", "-1".to_owned()),
        ("max_attempts", over_entries.to_string()),
        ("max_attempts", "0".to_owned()),
        ("max_attempts", "-1".to_owned()),
        ("max_connections_per_source", over_connections.to_string()),
        ("max_connections_per_source", "0".to_owned()),
        ("body_read_timeout_seconds", over_timeout.to_string()),
        ("body_read_timeout_seconds", "0".to_owned()),
        ("header_read_timeout_seconds", over_timeout.to_string()),
        ("header_read_timeout_seconds", "0".to_owned()),
        ("rate_max_requests", "0".to_owned()),
        ("rate_max_requests", "-3".to_owned()),
    ];
    bad.iter().try_for_each(|(name, value)| -> TestResult {
        let module = module_in(dir.path(), &format!("  {name}: {value}\n"))?;
        assert!(api_config(&module).is_err(), "{name}: {value}");
        Ok(())
    })?;
    let negative = module_in(dir.path(), "  rate_window_seconds: -5\n")?;
    assert!(matches!(
        api_config(&negative),
        Err(StartupError::OutOfRange {
            name: "rate_window_seconds",
            ..
        })
    ));
    let edge = format!(
        "  rate_max_requests: {MAX_RATE_REQUESTS}\n  rate_window_seconds: {MAX_WINDOW_SECONDS}\n  max_sources: {MAX_TABLE_ENTRIES}\n  max_attempts: 1\n  max_connections_per_source: {MAX_CONNECTIONS_CAP}\n  body_read_timeout_seconds: {MAX_TIMEOUT_SECONDS}\n  header_read_timeout_seconds: 1\n"
    );
    assert!(api_config(&module_in(dir.path(), &edge)?).is_ok());
    Ok(())
}


#[test]
fn a_reload_with_a_negative_window_is_refused_and_the_old_limit_kept() -> TestResult {
    let running = live("")?;
    rewrite(&running, "  rate_window_seconds: -5\n")?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { .. }));
    assert_eq!(running.state.limits.load().rate_window_seconds, RATE_WINDOW_SECONDS);
    Ok(())
}


#[test]
fn digests_come_from_the_bytes_that_were_parsed() -> TestResult {
    let dir = tempdir()?;
    let list = dir.path().join("list.txt");
    fs::write(&list, "hunter2\n")?;
    let (first_set, first_digest) = read_compromised_digested(&list)?;
    assert!(first_set.contains("hunter2"));
    assert_eq!(first_digest, content_digest(b"hunter2\n"));
    fs::write(&list, "swordfish\n")?;
    let (second_set, second_digest) = read_compromised_digested(&list)?;
    assert!(second_set.contains("swordfish") && !second_set.contains("hunter2"));
    assert_eq!(second_digest, content_digest(b"swordfish\n"));
    assert!(read_compromised_digested(&dir.path().join("missing")).is_err());
    Ok(())
}


#[test]
fn a_tls_pair_is_read_once_and_digested_as_read() -> TestResult {
    let dir = tempdir()?;
    let material = pki()?;
    write_pki(dir.path(), &material)?;
    let module = module_in(dir.path(), &tls_extra(dir.path()))?;
    let files = api_config(&module)?.tls.ok_or("no tls")?;
    let loaded = load_tls(&files)?;
    assert_eq!(loaded.certificate_digest, content_digest(&fs::read(&files.certificate)?));
    assert_eq!(loaded.key_digest, content_digest(&fs::read(&files.key)?));
    Ok(())
}


#[test]
fn the_oidc_fingerprint_is_keyed_and_follows_every_input() -> TestResult {
    let files = OidcFiles {
        config: PathBuf::from("oidc.yaml"),
        ca_file: Some(PathBuf::from("ca.pem")),
        secret_file: PathBuf::from("oidc.secret"),
    };
    let base = oidc_fingerprint(b"salt", &files, b"yaml", Some(b"ca"), b"secret");
    assert_eq!(base, oidc_fingerprint(b"salt", &files, b"yaml", Some(b"ca"), b"secret"));
    assert_ne!(base, oidc_fingerprint(b"other", &files, b"yaml", Some(b"ca"), b"secret"));
    assert_ne!(base, oidc_fingerprint(b"salt", &files, b"yaml", Some(b"ca"), b"rotated"));
    assert_ne!(base, oidc_fingerprint(b"salt", &files, b"yaml", None, b"secret"));
    assert_eq!(fingerprint_salt()?, fingerprint_salt()?);
    Ok(())
}


#[test]
fn the_audit_log_holds_nothing_recomputable_from_the_oidc_secret() -> TestResult {
    let guesses = ["hunter2", "password", "secret", "swordfish", "rotated"];
    let dir = tempdir()?;
    let yaml = dir.path().join("oidc.yaml");
    fs::write(&yaml, OIDC_TEXT)?;
    let secret_file = dir.path().join("guessed.secret");
    private_file(&secret_file, b"hunter2")?;
    let settings = format!("  oidc: {}\n  oidc_secret_file: {}\n", yaml.display(), secret_file.display());
    let running = live_with(dir, &settings, None)?;
    let first = running.state.oidc.load_full().ok_or("no oidc")?;
    private_file(&secret_file, b"swordfish")?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    let rotated = running.state.oidc.load_full().ok_or("no oidc")?;
    assert!(!Arc::ptr_eq(&first, &rotated));
    let files = OidcFiles {
        config: yaml,
        ca_file: None,
        secret_file,
    };
    let log = fs::read_to_string(running.dir.path().join("audit.log"))?;
    assert!(log.contains("config.reload"));
    guesses.iter().try_for_each(|guess| -> TestResult {
        let unsalted = oidc_fingerprint(&[], &files, OIDC_TEXT.as_bytes(), None, guess.as_bytes());
        let candidates = [
            content_digest(guess.as_bytes()),
            unsalted,
            content_digest(format!("{guess}\n").as_bytes()),
        ];
        candidates
            .iter()
            .for_each(|candidate| assert!(!log.contains(candidate.as_str()), "{guess}"));
        assert!(!log.contains(guess));
        Ok(())
    })?;
    assert!(!settings_state_text(&running)?.contains("hunter2"));
    Ok(())
}


fn settings_state_text(running: &Live) -> Result<String, TestError> {
    let settings = build_settings(load_module(&running.module_file)?)?;
    Ok(format!("{:?}", settings_state(&settings)))
}


#[test]
fn settings_are_checked_and_fingerprinted_before_they_exist() -> TestResult {
    let dir = tempdir()?;
    let plain = build_settings(module_in(dir.path(), "")?)?;
    assert!(plain.tls.is_none() && plain.oidc.is_none());
    assert_eq!(plain.fingerprints.keys().collect::<Vec<_>>(), [FINGERPRINT_COMPROMISED, FINGERPRINT_KEY]);
    write_pki(dir.path(), &pki()?)?;
    let secured = build_settings(module_in(dir.path(), &tls_extra(dir.path()))?)?;
    assert!(secured.tls.is_some());
    assert!(secured.fingerprints.contains_key(FINGERPRINT_TLS_CERTIFICATE) && secured.fingerprints.contains_key(FINGERPRINT_TLS_KEY));
    let state = settings_state(&secured);
    assert!(state.contains_key(FINGERPRINT_TLS_KEY) && state.contains_key("name"));
    assert!(!state.values().any(|value| value.contains("PRIVATE KEY")));
    Ok(())
}


#[test]
fn settings_refuse_what_cannot_run() -> TestResult {
    let dir = tempdir()?;
    let exposed_file = dir.path().join("exposed.yaml");
    fs::write(&exposed_file, module_text(dir.path(), "example", "0.0.0.0:0", "")?)?;
    assert!(matches!(
        build_settings(load_module(&exposed_file)?),
        Err(StartupError::PlainHttpRefused(_))
    ));
    let absent = module_in(dir.path(), "")?;
    fs::remove_file(dir.path().join("compromised.txt"))?;
    assert!(matches!(build_settings(absent), Err(StartupError::Io(_))));
    let pair = pki()?;
    write_pki(dir.path(), &pair)?;
    fs::write(dir.path().join("server.key"), pki()?.key)?;
    set_mode(&dir.path().join("server.key"), fixture::OWNER_ONLY)?;
    assert!(matches!(
        build_settings(module_in(dir.path(), &tls_extra(dir.path()))?),
        Err(StartupError::Tls(_))
    ));
    Ok(())
}


#[test]
fn the_loader_names_the_file_and_keeps_the_cause() -> TestResult {
    let dir = tempdir()?;
    assert!(matches!(load_settings(&dir.path().join("none.yaml")), Err(ConfigError::Io { .. })));
    let path = write_module(dir.path(), "  rate_max_requests: 0\n")?;
    let refused = load_settings(&path);
    assert!(refused.is_err_and(|error| error.to_string().contains("must be between 1 and")));
    Ok(())
}


#[test]
fn the_first_load_is_handed_over_then_the_file_is_read() -> TestResult {
    let dir = tempdir()?;
    let path = write_module(dir.path(), "")?;
    let loader = first_then_file(build_settings(load_module(&path)?)?, path.clone());
    fs::write(&path, module_text(dir.path(), "example", LOOPBACK, "  rate_max_requests: 7\n")?)?;
    assert_eq!(loader()?.config.limits.rate_max_requests, RATE_MAX_REQUESTS);
    assert_eq!(loader()?.config.limits.rate_max_requests, ALT_REQUESTS);
    fs::remove_file(&path)?;
    assert!(loader().is_err());
    Ok(())
}


#[test]
fn every_file_the_module_points_at_is_watched() -> TestResult {
    let dir = tempdir()?;
    let plain = build_settings(module_in(dir.path(), "")?)?;
    assert_eq!(watched_files(&dir.path().join("module.yaml"), &plain.config).len(), PLAIN_FILES);
    write_pki(dir.path(), &pki()?)?;
    let oidc_yaml = dir.path().join("oidc.yaml");
    fs::write(&oidc_yaml, OIDC_TEXT)?;
    private_file(&dir.path().join("oidc.secret"), b"secret")?;
    let base = format!(
        "{}  oidc: {}\n  oidc_secret_file: {}\n",
        tls_extra(dir.path()),
        oidc_yaml.display(),
        dir.path().join("oidc.secret").display()
    );
    let without_ca = build_settings(module_in(dir.path(), &base)?)?;
    assert_eq!(watched_files(&dir.path().join("module.yaml"), &without_ca.config).len(), WITHOUT_CA_FILES);
    fs::write(dir.path().join("ca.pem"), pki()?.certificate)?;
    let with_ca = build_settings(module_in(
        dir.path(),
        &format!("{base}  oidc_ca_file: {}\n", dir.path().join("ca.pem").display()),
    )?)?;
    assert_eq!(watched_files(&dir.path().join("module.yaml"), &with_ca.config).len(), WITH_CA_FILES);
    assert!(with_ca.fingerprints.contains_key(FINGERPRINT_OIDC));
    Ok(())
}


#[test]
fn a_listen_address_that_cannot_be_bound_refuses_the_reload_and_nothing_else_applies() -> TestResult {
    let running = live("")?;
    let taken = std::net::TcpListener::bind(LOOPBACK)?;
    let both = module_text(
        running.dir.path(),
        "example",
        &taken.local_addr()?.to_string(),
        "  rate_max_requests: 2\n",
    )?;
    fs::write(&running.module_file, both)?;
    let outcome = reload(&running.engine);
    assert!(matches!(outcome, ReloadOutcome::Refused { ref reason } if reason.contains("`listener`")));
    assert_eq!(running.state.limits.load().rate_max_requests, RATE_MAX_REQUESTS);
    let records = reload_records(running.dir.path())?;
    assert_eq!(records.len(), 1);
    assert!(records.iter().all(|line| line.contains("refused")));
    let current = running.listener.current.lock().map_err(|_| "poisoned")?;
    assert_eq!(current.bound.as_ref().map(|bound| bound.generation), Some(0));
    Ok(())
}


#[test]
fn a_valid_change_applies_and_an_invalid_one_keeps_the_old_value() -> TestResult {
    let running = live("")?;
    rewrite(
        &running,
        "  rate_max_requests: 2\n  max_attempts: 13\n  max_connections_per_source: 15\n  body_read_timeout_seconds: 3\n",
    )?;
    assert_eq!(
        reload(&running.engine),
        ReloadOutcome::Applied {
            keys: vec![
                "settings.body_read_timeout_seconds".to_owned(),
                "settings.max_attempts".to_owned(),
                "settings.max_connections_per_source".to_owned(),
                "settings.rate_max_requests".to_owned()
            ]
        }
    );
    let applied = running.state.limits.load_full();
    assert_eq!(
        (applied.rate_max_requests, applied.max_attempts, applied.max_connections_per_source),
        (LOW_LIMIT, ALT_ATTEMPTS, ALT_CONNECTIONS)
    );
    assert_eq!(applied.body_read_timeout, Duration::from_secs(BODY_SECONDS));
    rewrite(&running, "  rate_max_requests: 0\n")?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { .. }));
    assert_eq!(running.state.limits.load().rate_max_requests, LOW_LIMIT);
    let records = reload_records(running.dir.path())?;
    assert_eq!(records.len(), TWO_RECORDS);
    assert!(records.iter().any(|line| line.contains("applied")) && records.iter().any(|line| line.contains("refused")));
    Ok(())
}


#[test]
fn a_lowered_rate_limit_applies_to_the_next_request() -> TestResult {
    let running = live("")?;
    let source = peer()?;
    assert!(admit_source(&running.state, source));
    rewrite(&running, &format!("  rate_max_requests: {LOW_LIMIT}\n"))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert!(admit_source(&running.state, source));
    assert!(!admit_source(&running.state, source));
    rewrite(&running, &format!("  rate_max_requests: {HIGH_LIMIT}\n"))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert!(admit_source(&running.state, source));
    Ok(())
}


#[test]
fn a_lowered_max_sources_refuses_only_new_keys() -> TestResult {
    let running = live("")?;
    let sources: Vec<IpAddr> = (1..=SOURCES).map(|index| format!("10.0.0.{index}").parse()).collect::<Result<_, _>>()?;
    assert!(sources.iter().all(|source| admit_source(&running.state, *source)));
    rewrite(&running, "  max_sources: 1\n")?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert!(sources.iter().all(|source| admit_source(&running.state, *source)));
    assert_eq!(running.state.limiter.lock().map_err(|_| "poisoned")?.len(), SOURCES);
    assert!(!admit_source(&running.state, "10.9.9.9".parse()?));
    assert_eq!(running.state.limiter.lock().map_err(|_| "poisoned")?.len(), SOURCES);
    Ok(())
}


#[test]
fn a_new_compromised_list_applies_and_a_missing_one_is_refused() -> TestResult {
    let running = live("")?;
    assert!(running.state.compromised.load().contains("passwordpassword"));
    fs::write(running.dir.path().join("compromised.txt"), "differentpassword\n")?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert!(running.state.compromised.load().contains("differentpassword"));
    assert!(!running.state.compromised.load().contains("passwordpassword"));
    fs::remove_file(running.dir.path().join("compromised.txt"))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { .. }));
    assert!(running.state.compromised.load().contains("differentpassword"));
    Ok(())
}


#[test]
fn the_log_level_follows_the_file_and_a_gone_handle_is_only_logged() -> TestResult {
    let (dispatch, handle) = reloadable_dispatch(tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::io::sink), DEFAULT_LOG_LEVEL);
    let probe = handle.clone();
    let running = live_with(tempdir()?, "", Some(handle))?;
    rewrite(&running, "  log_level: debug\n")?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(probe.with_current(|level| *level)?, LevelFilter::DEBUG);
    drop(dispatch);
    rewrite(&running, "  log_level: warn\n")?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    rewrite(&running, "  log_level: shout\n")?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { .. }));
    Ok(())
}


#[test]
fn the_oidc_runtime_is_swapped_only_when_its_files_change() -> TestResult {
    let dir = tempdir()?;
    let oidc_yaml = dir.path().join("oidc.yaml");
    fs::write(&oidc_yaml, OIDC_TEXT)?;
    private_file(&dir.path().join("oidc.secret"), b"secret")?;
    let oidc = format!(
        "  oidc: {}\n  oidc_secret_file: {}\n",
        oidc_yaml.display(),
        dir.path().join("oidc.secret").display()
    );
    let running = live_with(dir, &oidc, None)?;
    let first = running.state.oidc.load_full().ok_or("no oidc")?;
    rewrite(&running, &format!("{oidc}  rate_max_requests: 9\n"))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert!(Arc::ptr_eq(&first, &running.state.oidc.load_full().ok_or("no oidc")?));
    fs::write(&oidc_yaml, OTHER_OIDC_TEXT)?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    let swapped = running.state.oidc.load_full().ok_or("no oidc")?;
    assert!(!Arc::ptr_eq(&first, &swapped));
    assert_eq!(swapped.config.issuer, "https://other.example");
    fs::write(&oidc_yaml, "issuer: http://insecure.example\n")?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { .. }));
    assert!(Arc::ptr_eq(&swapped, &running.state.oidc.load_full().ok_or("no oidc")?));
    rewrite(&running, "")?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert!(running.state.oidc.load().is_none());
    rewrite(&running, &oidc)?;
    fs::write(&oidc_yaml, OIDC_TEXT)?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert!(running.state.oidc.load().is_some());
    Ok(())
}


fn oidc_settings(dir: &Path, secret: &str) -> Result<String, TestError> {
    let oidc_yaml = dir.join("oidc.yaml");
    if !oidc_yaml.exists() {
        fs::write(&oidc_yaml, OIDC_TEXT)?;
    }
    let secret_file = dir.join(secret);
    if !secret_file.exists() {
        private_file(&secret_file, b"secret")?;
    }
    Ok(format!(
        "  oidc: {}\n  oidc_secret_file: {}\n",
        oidc_yaml.display(),
        secret_file.display()
    ))
}


#[test]
fn a_changed_oidc_secret_path_or_content_swaps_the_runtime() -> TestResult {
    let dir = tempdir()?;
    let first_settings = oidc_settings(dir.path(), "first.secret")?;
    let second_settings = oidc_settings(dir.path(), "second.secret")?;
    let running = live_with(dir, &first_settings, None)?;
    let first = running.state.oidc.load_full().ok_or("no oidc")?;
    rewrite(&running, &second_settings)?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    let moved = running.state.oidc.load_full().ok_or("no oidc")?;
    assert!(!Arc::ptr_eq(&first, &moved));
    assert_ne!(first.fingerprint, moved.fingerprint);
    private_file(&running.dir.path().join("second.secret"), b"rotated")?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    let rotated = running.state.oidc.load_full().ok_or("no oidc")?;
    assert!(!Arc::ptr_eq(&moved, &rotated));
    assert_ne!(moved.fingerprint, rotated.fingerprint);
    let secret = (rotated.resolve)(&rotated.config.client_secret)?;
    assert_eq!(secrecy::ExposeSecret::expose_secret(&secret), "rotated");
    assert!(matches!(reload(&running.engine), ReloadOutcome::Unchanged));
    Ok(())
}


#[test]
fn a_group_readable_oidc_secret_refuses_the_reload_and_names_the_file() -> TestResult {
    let dir = tempdir()?;
    let first_settings = oidc_settings(dir.path(), "first.secret")?;
    let loose_settings = oidc_settings(dir.path(), "loose.secret")?;
    set_mode(&dir.path().join("loose.secret"), WORLD_READABLE)?;
    let running = live_with(dir, &first_settings, None)?;
    let first = running.state.oidc.load_full().ok_or("no oidc")?;
    rewrite(&running, &loose_settings)?;
    let outcome = reload(&running.engine);
    if cfg!(unix) {
        assert!(matches!(outcome, ReloadOutcome::Refused { ref reason } if reason.contains("loose.secret")));
        assert!(Arc::ptr_eq(&first, &running.state.oidc.load_full().ok_or("no oidc")?));
    }
    Ok(())
}


#[test]
fn a_group_readable_tls_key_is_refused_by_name() -> TestResult {
    let dir = tempdir()?;
    write_pki(dir.path(), &pki()?)?;
    set_mode(&dir.path().join("server.key"), WORLD_READABLE)?;
    let refused = build_settings(module_in(dir.path(), &tls_extra(dir.path()))?);
    if cfg!(unix) {
        let message = refused.err().ok_or("accepted")?.to_string();
        assert!(message.contains("server.key") && !message.contains("audit log"), "{message}");
    }
    Ok(())
}


#[test]
fn a_new_certificate_pair_is_swapped_and_a_bad_one_is_refused() -> TestResult {
    let dir_again = tempdir()?;
    write_pki(dir_again.path(), &pki()?)?;
    let extra = tls_extra(dir_again.path());
    let running_again = live_with(dir_again, &extra, None)?;
    let live_tls = running_again.tls.clone().ok_or("no tls")?;
    let before = live_tls.get_inner();
    write_pki(running_again.dir.path(), &pki()?)?;
    assert!(matches!(reload(&running_again.engine), ReloadOutcome::Applied { .. }));
    let after = live_tls.get_inner();
    assert!(!Arc::ptr_eq(&before, &after));
    fs::write(running_again.dir.path().join("server.key"), pki()?.key)?;
    set_mode(&running_again.dir.path().join("server.key"), fixture::OWNER_ONLY)?;
    assert!(matches!(reload(&running_again.engine), ReloadOutcome::Refused { .. }));
    assert!(Arc::ptr_eq(&after, &live_tls.get_inner()));
    write_pki(running_again.dir.path(), &pki()?)?;
    set_mode(&running_again.dir.path().join("server.key"), WORLD_READABLE)?;
    let outcome = reload(&running_again.engine);
    assert_eq!(matches!(outcome, ReloadOutcome::Refused { .. }), cfg!(unix));
    assert_eq!(Arc::ptr_eq(&after, &live_tls.get_inner()), cfg!(unix));
    Ok(())
}


#[test]
fn state_built_from_a_fixture_still_reads_default_limits() -> TestResult {
    let fx = fixture()?;
    assert_eq!(
        fx.state.limits.load().max_connections_per_source,
        fx.config.limits.max_connections_per_source
    );
    assert!(fx.dir.path().is_dir());
    drop(fx.router.clone());
    Ok(())
}


async fn eventually<Check, Pending>(mut check: Check) -> Result<bool, TestError>
where
    Check: FnMut() -> Pending,
    Pending: Future<Output = Result<bool, TestError>>,
{
    let mut done = false;
    let mut attempts = 0;
    while !done && attempts < POLLS {
        done = check().await?;
        attempts += 1;
        if !done {
            tokio::time::sleep(POLL_PAUSE).await;
        }
    }
    Ok(done)
}


async fn status_of(address: SocketAddr) -> Result<String, TestError> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(HEALTH_REQUEST.as_bytes()).await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    Ok(String::from_utf8_lossy(&bytes).lines().next().map_or_else(String::new, str::to_owned))
}


fn start_module(path: &Path) -> (SharedListener, tokio::task::JoinHandle<Result<(), StartupError>>) {
    let listener = new_listener();
    let running = listener.clone();
    let arguments = vec![path.display().to_string()];
    (
        listener,
        tokio::spawn(async move { run_module(&arguments, extra_router(), extra_access(), vec![], running, None).await }),
    )
}


async fn listening(listener: &SharedListener) -> Result<SocketAddr, TestError> {
    Ok(listening_address(listener).await.ok_or("server did not start")?)
}


#[tokio::test]
async fn editing_the_module_file_changes_the_running_server() -> TestResult {
    let dir = tempdir()?;
    let path = write_module(dir.path(), &format!("  rate_max_requests: {HIGH_LIMIT}\n"))?;
    let (listener, task) = start_module(&path);
    let address = listening(&listener).await?;
    assert!(status_of(address).await?.contains("200"));
    let taken = std::net::TcpListener::bind(LOOPBACK)?;
    fs::write(
        &path,
        module_text(
            dir.path(),
            "example",
            &taken.local_addr()?.to_string(),
            &format!("  rate_max_requests: {LOW_LIMIT}\n"),
        )?,
    )?;
    let directory = dir.path();
    let refused = eventually(|| async move { Ok(reload_records(directory)?.iter().any(|line| line.contains("refused"))) }).await?;
    assert!(refused);
    assert!(status_of(address).await?.contains("200"));
    assert!(status_of(address).await?.contains("200"));
    assert!(status_of(address).await?.contains("200"));
    fs::write(
        &path,
        module_text(dir.path(), "example", LOOPBACK, &format!("  rate_max_requests: {LOW_LIMIT}\n"))?,
    )?;
    let limited = eventually(|| async move { Ok(status_of(address).await?.contains("429")) }).await?;
    assert!(limited);
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    Ok(())
}


#[cfg(unix)]
#[tokio::test]
async fn sighup_reloads_the_module_file() -> TestResult {
    let dir = tempdir()?;
    let path = write_module(dir.path(), &format!("  rate_max_requests: {HIGH_LIMIT}\n"))?;
    let (listener, task) = start_module(&path);
    let address = listening(&listener).await?;
    assert!(status_of(address).await?.contains("200"));
    fs::write(
        &path,
        module_text(dir.path(), "example", LOOPBACK, &format!("  rate_max_requests: {LOW_LIMIT}\n"))?,
    )?;
    signal_hook::low_level::raise(signal_hook::consts::SIGHUP)?;
    let limited = eventually(|| async move { Ok(status_of(address).await?.contains("429")) }).await?;
    assert!(limited);
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    Ok(())
}


async fn presented_certificate(address: SocketAddr, trusted: &[&Pki]) -> Result<(TlsStream<TcpStream>, CertificateDer<'static>), TestError> {
    let mut roots = RootCertStore::empty();
    trusted.iter().try_for_each(|material| roots.add(material.der.clone()))?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let stream = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(LOCALHOST_NAME)?, TcpStream::connect(address).await?)
        .await?;
    let certificate = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or("no certificate")?
        .clone();
    Ok((stream, certificate))
}


#[tokio::test]
async fn a_replaced_certificate_serves_new_handshakes_and_spares_open_connections() -> TestResult {
    let dir = tempdir()?;
    let (first, second) = (pki()?, pki()?);
    write_pki(dir.path(), &first)?;
    let path = write_module(dir.path(), &tls_extra(dir.path()))?;
    let (listener, task) = start_module(&path);
    let address = listening(&listener).await?;
    let (mut open, seen) = presented_certificate(address, &[&first, &second]).await?;
    assert_eq!(seen, first.der);
    write_pki(dir.path(), &second)?;
    let (first_ref, second_ref) = (&first, &second);
    let swapped = eventually(|| async move { Ok(presented_certificate(address, &[first_ref, second_ref]).await?.1 == second_ref.der) }).await?;
    assert!(swapped);
    open.write_all(HEALTH_REQUEST.as_bytes()).await?;
    let mut bytes = Vec::new();
    open.read_to_end(&mut bytes).await?;
    assert!(String::from_utf8_lossy(&bytes).starts_with("HTTP/1.1 200 OK"));
    let directory = dir.path();
    let before = reload_records(directory)?.iter().filter(|line| line.contains("refused")).count();
    fs::write(directory.join("server.key"), first.key.as_bytes())?;
    let refused =
        eventually(|| async move { Ok(reload_records(directory)?.iter().filter(|line| line.contains("refused")).count() > before) }).await?;
    assert!(refused);
    assert_eq!(presented_certificate(address, &[&first, &second]).await?.1, second.der);
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    Ok(())
}


const PLAIN_AGAIN: u64 = 2;


const RETIRED: u64 = 2;


const NEWEST: u64 = 3;


const SLOW_LOGIN: &str =
    "POST /auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n";


const PARTIAL_HEADERS: &str = "GET /health HTTP/1.1\r\nHost: localhost\r\n";


const PATIENT: &str = "  header_read_timeout_seconds: 3600\n  body_read_timeout_seconds: 3600\n";


const SHORT_HEADER_TIMEOUT: &str = "  header_read_timeout_seconds: 1\n";


const PROBE_PAUSE: Duration = Duration::from_secs(5);


fn free_address() -> Result<String, TestError> {
    Ok(std::net::TcpListener::bind(LOOPBACK)?.local_addr()?.to_string())
}


fn generation_of(listener: &SharedListener) -> Result<Option<u64>, TestError> {
    let current = listener.current.lock().map_err(|_| "poisoned")?;
    Ok(current.bound.as_ref().map(|bound| bound.generation))
}


async fn moved_to(listener: &SharedListener, old: SocketAddr) -> Result<SocketAddr, TestError> {
    let watched = listener;
    let changed = eventually(|| async move { Ok(listening_address(watched).await != Some(old)) }).await?;
    assert!(changed);
    listening(listener).await
}


async fn at_generation(listener: &SharedListener, wanted: u64) -> Result<(), TestError> {
    let watched = listener;
    let reached = eventually(|| async move { Ok(generation_of(watched)? == Some(wanted)) }).await?;
    assert!(reached);
    Ok(())
}


#[tokio::test]
async fn a_moved_listen_serves_on_the_new_port_and_frees_the_old_one() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    fs::write(&path, module_text(dir.path(), "example", &free_address()?, "")?)?;
    let (listener, task) = start_module(&path);
    let old = listening(&listener).await?;
    assert!(status_of(old).await?.contains("200"));
    let second = free_address()?;
    fs::write(&path, module_text(dir.path(), "example", &second, "")?)?;
    let new = moved_to(&listener, old).await?;
    assert_eq!(new.to_string(), second);
    assert!(status_of(new).await?.contains("200"));
    let freed = eventually(|| async move { Ok(TcpStream::connect(old).await.is_err()) }).await?;
    assert!(freed);
    assert_eq!(generation_of(&listener)?, Some(1));
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    Ok(())
}


#[tokio::test]
async fn a_request_in_flight_finishes_on_the_old_listener() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    fs::write(&path, module_text(dir.path(), "example", &free_address()?, PATIENT)?)?;
    let (listener, task) = start_module(&path);
    let old = listening(&listener).await?;
    let mut open = TcpStream::connect(old).await?;
    open.write_all(SLOW_LOGIN.as_bytes()).await?;
    let held = current_handle(&listener);
    let held_ref = &held;
    let accepted = eventually(|| async move { Ok(held_ref.connection_count() == 1) }).await?;
    assert!(accepted);
    fs::write(&path, module_text(dir.path(), "example", &free_address()?, PATIENT)?)?;
    let new = moved_to(&listener, old).await?;
    assert!(status_of(new).await?.contains("200"));
    let refused = eventually(|| async move { Ok(TcpStream::connect(old).await.is_err()) }).await?;
    assert!(refused);
    open.write_all(b"{}").await?;
    let mut bytes = Vec::new();
    open.read_to_end(&mut bytes).await?;
    assert!(String::from_utf8_lossy(&bytes).starts_with("HTTP/1.1 4"));
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    Ok(())
}


async fn closes_a_partial_request(address: SocketAddr) -> Result<bool, TestError> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(PARTIAL_HEADERS.as_bytes()).await?;
    let mut bytes = Vec::new();
    Ok(tokio::time::timeout(PROBE_PAUSE, stream.read_to_end(&mut bytes)).await.is_ok())
}


#[tokio::test]
async fn a_changed_header_timeout_applies_to_new_connections_on_the_same_address() -> TestResult {
    let dir = tempdir()?;
    let path = write_module(dir.path(), PATIENT)?;
    let (listener, task) = start_module(&path);
    let address = listening(&listener).await?;
    fs::write(&path, module_text(dir.path(), "example", LOOPBACK, SHORT_HEADER_TIMEOUT)?)?;
    at_generation(&listener, 1).await?;
    let closed = eventually(|| async move { closes_a_partial_request(address).await }).await?;
    assert!(closed);
    assert!(status_of(address).await?.contains("200"));
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    Ok(())
}


#[tokio::test]
async fn tls_turned_on_then_off_changes_what_new_connections_get() -> TestResult {
    let dir = tempdir()?;
    let pair = pki()?;
    write_pki(dir.path(), &pair)?;
    let path = write_module(dir.path(), "")?;
    let (listener, task) = start_module(&path);
    let address = listening(&listener).await?;
    assert!(status_of(address).await?.contains("200"));
    fs::write(&path, module_text(dir.path(), "example", LOOPBACK, &tls_extra(dir.path()))?)?;
    let pair_ref = &pair;
    let secured = eventually(|| async move {
        Ok(presented_certificate(address, &[pair_ref])
            .await
            .is_ok_and(|(_, seen)| seen == pair_ref.der))
    })
    .await?;
    assert!(secured);
    fs::write(&path, module_text(dir.path(), "example", LOOPBACK, "")?)?;
    let plain = eventually(|| async move { Ok(status_of(address).await.is_ok_and(|line| line.contains("200"))) }).await?;
    assert!(plain);
    assert_eq!(generation_of(&listener)?, Some(PLAIN_AGAIN));
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    Ok(())
}


#[tokio::test]
async fn a_moved_watched_file_is_watched_from_the_next_reload_on() -> TestResult {
    let dir = tempdir()?;
    let lists = dir.path().join("lists");
    fs::create_dir(&lists)?;
    fs::write(lists.join("moved.txt"), "passwordpassword\n")?;
    let path = write_module(dir.path(), "")?;
    let (listener, task) = start_module(&path);
    listening(&listener).await?;
    let text = module_text(dir.path(), "example", LOOPBACK, "")?.replace("compromised.txt", "lists/moved.txt");
    fs::write(&path, text)?;
    let directory = dir.path();
    let moved = eventually(|| async move { Ok(reload_records(directory)?.iter().any(|line| line.contains("applied"))) }).await?;
    assert!(moved);
    let moved_list = lists.join("moved.txt");
    let mut attempt = usize::MIN;
    let followed = eventually(|| {
        attempt += 1;
        let (file, entry) = (moved_list.clone(), format!("another-password-entry-{attempt}\n"));
        async move {
            fs::write(&file, entry)?;
            Ok(reload_records(directory)?.iter().filter(|line| line.contains("applied")).count() > 1)
        }
    })
    .await?;
    assert!(followed);
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    Ok(())
}


#[test]
fn the_file_watch_needs_its_engine_and_reports_unwatchable_directories() -> TestResult {
    let empty = Rewatch::default();
    assert!(matches!(rewatch(&empty, vec![PathBuf::from("x")]), Err(StartupError::EngineGone)));
    let running = live("")?;
    let missing = vec![running.dir.path().join("absent").join("file.txt")];
    assert!(matches!(rewatch(&running.setup.rewatch, missing), Err(StartupError::Watch(_))));
    let settings = build_settings(load_module(&running.module_file)?)?;
    follow_files(&empty, &running.module_file, &settings);
    assert!(rewatch(&running.setup.rewatch, watched_files(&running.module_file, &settings.config)).is_ok());
    Ok(())
}


#[test]
fn a_moved_accounts_store_is_checked_first_and_a_bad_one_is_refused() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    let original = running.state.store_path.load_full();
    private_file(&directory.join("bad.json"), b"not json")?;
    let plain = module_text(directory, "example", LOOPBACK, "")?;
    fs::write(&running.module_file, plain.replace("accounts.json", "bad.json"))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { ref reason } if reason.contains("`accounts_store`")));
    assert_eq!(running.state.store_path.load_full(), original);
    fs::write(&running.module_file, plain.replace("accounts.json", "absent.json"))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { ref reason } if reason.contains("`accounts_store`")));
    assert!(!directory.join("absent.json").exists() && !directory.join("absent.json.lock").exists());
    assert_eq!(running.state.store_path.load_full(), original);
    save_store_file(&directory.join("moved.json"), &AccountMap::new(), &CredentialMap::new(), os_random)?;
    set_mode(&directory.join("moved.json"), OWNER_ONLY)?;
    fs::write(&running.module_file, plain.replace("accounts.json", "moved.json"))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(*running.state.store_path.load_full(), directory.join("moved.json"));
    assert_eq!(reload_records(directory)?.len(), FOUR_RECORDS);
    Ok(())
}


#[test]
fn a_moved_audit_log_is_recorded_in_both_files_and_a_bad_one_is_refused() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    private_file(&directory.join("bad.log"), b"not a record\n")?;
    let plain = module_text(directory, "example", LOOPBACK, "")?;
    fs::write(&running.module_file, plain.replace("audit.log", "bad.log"))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { ref reason } if reason.contains("`audit_log`")));
    fs::write(&running.module_file, plain.replace("audit.log", "moved.log"))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    let old_log = fs::read_to_string(directory.join("audit.log"))?;
    assert!(old_log.contains("refused") && old_log.contains("applied") && !old_log.contains("audit_log moved"));
    let new_log = fs::read_to_string(directory.join("moved.log"))?;
    assert!(new_log.contains("audit_log moved from") && new_log.contains("moved.log"));
    fs::write(&running.module_file, plain.replace("audit.log", "moved.log") + "  rate_max_requests: 2\n")?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(fs::read_to_string(directory.join("audit.log"))?, old_log);
    assert_eq!(fs::read_to_string(directory.join("moved.log"))?.lines().count(), TWO_RECORDS);
    assert!(verify(BufReader::new(fs::File::open(directory.join("moved.log"))?), None).is_ok());
    Ok(())
}


#[test]
fn a_switch_without_a_matching_prepared_log_changes_nothing_and_a_failing_new_log_is_only_logged() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    let settings = build_settings(load_module(&running.module_file)?)?;
    let context = ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "default".to_owned(),
        module: "example".to_owned(),
        target: "module.yaml".to_owned(),
        request_id: "test".to_owned(),
    };
    let current = Mutex::new(directory.join("audit.log"));
    switch_audit(&running.state, &context, &current, &Mutex::new(None), &settings);
    assert_eq!(*current.lock().map_err(|_| "poisoned")?, directory.join("audit.log"));
    let read_only = PreparedAudit {
        path: settings.config.audit_log.clone(),
        state: LogState {
            writer: fs::File::open(directory.join("compromised.txt"))?,
            head: GENESIS_HASH.to_owned(),
            poisoned: false,
        },
    };
    switch_audit(&running.state, &context, &current, &Mutex::new(Some(read_only)), &settings);
    assert_eq!(*current.lock().map_err(|_| "poisoned")?, settings.config.audit_log);
    Ok(())
}


#[test]
fn the_first_server_refuses_a_plain_public_address_and_an_address_in_use() -> TestResult {
    let running = live("")?;
    let fx = fixture()?;
    let exposed = ApiConfig {
        address: "0.0.0.0:0".parse()?,
        ..fx.config.clone()
    };
    assert!(matches!(
        start_first(&running.setup, &exposed, None),
        Err(StartupError::PlainHttpRefused(_))
    ));
    let taken = std::net::TcpListener::bind(LOOPBACK)?;
    let busy = ApiConfig {
        address: taken.local_addr()?,
        ..fx.config
    };
    assert!(matches!(start_first(&running.setup, &busy, None), Err(StartupError::Io(_))));
    Ok(())
}


#[tokio::test]
async fn only_the_newest_generation_ends_the_run() -> TestResult {
    let listener = new_listener();
    finish(&listener, 0, Err(StartupError::Usage("before any server".to_owned())));
    listener.current.lock().map_err(|_| "poisoned")?.bound = Some(Bound {
        socket: bind_socket(LOOPBACK.parse()?)?,
        tls: None,
        address: LOOPBACK.parse()?,
        header_read_timeout: Duration::from_secs(1),
        generation: NEWEST,
    });
    finish(&listener, RETIRED, Err(StartupError::Usage("retired".to_owned())));
    finish(&listener, NEWEST, Err(StartupError::Usage("newest".to_owned())));
    assert!(matches!(wait_finished(&listener).await, Err(StartupError::Usage(ref text)) if text == "newest"));
    finish(&listener, NEWEST, Ok(()));
    assert!(wait_finished(&listener).await.is_ok());
    Ok(())
}


#[test]
fn a_listening_socket_that_cannot_be_shut_down_is_only_logged() -> TestResult {
    let socket = bind_socket(LOOPBACK.parse()?)?;
    retire_socket(&socket);
    retire_socket(&socket);
    Ok(())
}


fn audit_chain_is_intact(path: &Path) -> Result<bool, TestError> {
    Ok(verify(BufReader::new(fs::File::open(path)?), None).is_ok())
}


fn reload_with_audit_path(running: &Live, audit_path: &Path) -> Result<(), TestError> {
    let plain = module_text(running.dir.path(), "example", LOOPBACK, "")?;
    let original = running.dir.path().join("audit.log").display().to_string();
    fs::write(&running.module_file, plain.replace(&original, &audit_path.display().to_string()))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    Ok(())
}


#[test]
fn the_same_audit_file_through_dot_dot_is_not_a_move_and_keeps_the_chain() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    fs::create_dir(directory.join("sub"))?;
    reload_with_audit_path(&running, &directory.join("sub").join("..").join("audit.log"))?;
    let log = fs::read_to_string(directory.join("audit.log"))?;
    assert!(!log.contains("audit_log moved"));
    assert!(audit_chain_is_intact(&directory.join("audit.log"))?);
    Ok(())
}


#[cfg(unix)]
#[test]
fn the_same_audit_file_through_a_symlink_is_not_a_move_and_keeps_the_chain() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    std::os::unix::fs::symlink(directory.join("audit.log"), directory.join("link.log"))?;
    reload_with_audit_path(&running, &directory.join("link.log"))?;
    let log = fs::read_to_string(directory.join("audit.log"))?;
    assert!(!log.contains("audit_log moved"));
    assert!(audit_chain_is_intact(&directory.join("audit.log"))?);
    Ok(())
}


#[test]
fn a_moved_accounts_store_revokes_the_sessions_and_audits_it_once() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    let context = ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "default".to_owned(),
        module: "example".to_owned(),
        target: "module.yaml".to_owned(),
        request_id: "test".to_owned(),
    };
    running
        .state
        .callback_accounts
        .lock()
        .map_err(|_| "poisoned")?
        .insert("oidc:someone".to_owned());
    add_session(&running, "someone")?;
    assert_eq!(lock_auth(&running.state).sessions.len(), 1);
    let plain = module_text(directory, "example", LOOPBACK, "")?;
    save_store_file(&directory.join("moved.json"), &AccountMap::new(), &CredentialMap::new(), os_random)?;
    set_mode(&directory.join("moved.json"), OWNER_ONLY)?;
    fs::write(&running.module_file, plain.replace("accounts.json", "moved.json"))?;
    let settings = build_settings(load_module(&running.module_file)?)?;
    switch_store(&running.state, &context, &settings);
    assert!(running.state.callback_accounts.lock().map_err(|_| "poisoned")?.is_empty());
    assert!(lock_auth(&running.state).sessions.is_empty());
    switch_store(&running.state, &context, &settings);
    let log = fs::read_to_string(directory.join("audit.log"))?;
    assert_eq!(log.matches("every session revoked").count(), 1);
    running.state.audit.state.lock().map_err(|_| "poisoned")?.poisoned = true;
    fs::write(&running.module_file, plain)?;
    let back = build_settings(load_module(&running.module_file)?)?;
    switch_store(&running.state, &context, &back);
    assert_eq!(*running.state.store_path.load_full(), back.config.accounts_store);
    Ok(())
}


#[test]
fn a_reload_after_a_stop_starts_no_new_generation() -> TestResult {
    let running = live("")?;
    stop_listener(&running.listener, None);
    fs::write(&running.module_file, module_text(running.dir.path(), "example", &free_address()?, "")?)?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(generation_of(&running.listener)?, Some(0));
    Ok(())
}


const CLIENT_PORT: u16 = 40_000;


const BODY_READ_LIMIT: usize = 1_048_576;


const NEW_TENANT: &str = "elsewhere";


const NEW_NAME: &str = "renamed";


const TOTP_USER: &str = "totp-user";


const SECOND_TOTP_USER: &str = "second-totp-user";


const OLD_KEY_FILL: u8 = fixture::KEY_FILL;


const NEW_KEY_FILL: u8 = 9;


const THIRD_KEY_FILL: u8 = 11;


#[cfg(unix)]
const FOREIGN_UID: u32 = 12345;


const FIXED_RANDOM_BYTE: u8 = 0xab;


const SHORT_KEY_BYTES: usize = 16;


const TOTP_SECRET_FILL: u8 = 5;


const TOTP_SECRET_BYTES: usize = 20;


fn store_key(fill: u8) -> StoreKey {
    SecretSlice::from(vec![fill; fixture::KEY_BYTES])
}


fn password_account(name: &str, totp: Option<TotpEnrolment>) -> Result<Account, TestError> {
    Ok(Account {
        username: name.to_owned(),
        password_hash: hash_password(fixture::PASSWORD, os_random)?,
        roles: ["reader".to_owned()].into(),
        totp,
        sessions_valid_after: None,
    })
}


fn totp_enrolment(fill: u8) -> Result<TotpEnrolment, TestError> {
    totp_enrolment_for(TOTP_USER, fill)
}


fn totp_enrolment_for(name: &str, fill: u8) -> Result<TotpEnrolment, TestError> {
    Ok(TotpEnrolment {
        encrypted_secret: seal_secret(&store_key(fill), name, &[TOTP_SECRET_FILL; TOTP_SECRET_BYTES], os_random)?,
        last_step: 0,
        backup_code_hashes: Vec::new(),
    })
}


fn seed(running: &Live, accounts: Vec<Account>) -> TestResult {
    update_store_file(&running.state.store_path.load(), os_random, |stored, _| {
        accounts.into_iter().for_each(|account| {
            stored.insert(account.username.clone(), account);
        });
        Ok(())
    })?
    .saved?;
    Ok(())
}


fn add_session(running: &Live, user: &str) -> TestResult {
    let now = OffsetDateTime::now_utc();
    lock_auth(&running.state).sessions.insert(
        hash_token("planted"),
        Session {
            user: user.to_owned(),
            created_at: now,
            last_seen: now,
        },
    );
    Ok(())
}


fn current_totp_code() -> Result<String, TestError> {
    Ok(code_for_step(
        &[TOTP_SECRET_FILL; TOTP_SECRET_BYTES],
        unix_seconds(OffsetDateTime::now_utc())? / TOTP_STEP_SECONDS,
    ))
}


async fn send(router: &axum::Router, mut request: Request<Body>) -> Result<axum::http::Response<Body>, TestError> {
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(peer()?, CLIENT_PORT)));
    Ok(router.clone().oneshot(request).await?)
}


async fn get(router: &axum::Router, path: &str, token: Option<&str>) -> Result<axum::http::Response<Body>, TestError> {
    let base = Request::builder().method("GET").uri(path);
    let request = token.map_or(base, |value| {
        Request::builder()
            .method("GET")
            .uri(path)
            .header("authorization", format!("Bearer {value}"))
    });
    send(router, request.body(Body::empty())?).await
}


async fn body_json(response: axum::http::Response<Body>) -> Result<serde_json::Value, TestError> {
    Ok(serde_json::from_slice(&to_bytes(response.into_body(), BODY_READ_LIMIT).await?)?)
}


async fn login(running: &Live, user: &str, totp: Option<String>) -> Result<(StatusCode, serde_json::Value), TestError> {
    login_router(&running.setup.router, user, totp).await
}


async fn login_router(router: &axum::Router, user: &str, totp: Option<String>) -> Result<(StatusCode, serde_json::Value), TestError> {
    let body = serde_json::json!({ "username": user, "password": fixture::PASSWORD, "totp_code": totp }).to_string();
    let response = send(router, Request::builder().method("POST").uri("/auth/login").body(Body::from(body))?).await?;
    let status = response.status();
    Ok((status, body_json(response).await?))
}


async fn token_status(running: &Live, token: &str) -> Result<StatusCode, TestError> {
    Ok(get(&running.setup.router, "/auth/me", Some(token)).await?.status())
}


fn token_of(reply: &serde_json::Value) -> Result<String, TestError> {
    Ok(reply.get("token").and_then(serde_json::Value::as_str).ok_or("no token")?.to_owned())
}


fn audit_records(dir: &Path) -> Result<Vec<serde_json::Value>, TestError> {
    fs::read_to_string(dir.join("audit.log"))?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}


fn field<'a>(record: &'a serde_json::Value, name: &str) -> &'a str {
    record.get(name).and_then(serde_json::Value::as_str).map_or("", |text| text)
}


fn diff_of(record: &serde_json::Value) -> &str {
    record
        .get("parameters")
        .and_then(|parameters| parameters.get("diff"))
        .and_then(serde_json::Value::as_str)
        .map_or("", |text| text)
}


fn identity_records(dir: &Path) -> Result<Vec<serde_json::Value>, TestError> {
    Ok(audit_records(dir)?
        .into_iter()
        .filter(|record| diff_of(record).contains("every session revoked"))
        .collect())
}


fn module_with_key(dir: &Path, key_path: &Path) -> Result<String, TestError> {
    Ok(module_text(dir, "example", LOOPBACK, "")?.replace(&dir.join("store.key").display().to_string(), &key_path.display().to_string()))
}


fn stored_secret(running: &Live) -> Result<String, TestError> {
    let (accounts, _) = load_store_file(&running.state.store_path.load())?;
    Ok(accounts
        .get(TOTP_USER)
        .and_then(|account| account.totp.as_ref())
        .ok_or("no totp account")?
        .encrypted_secret
        .clone())
}


fn test_context() -> ReloadContext {
    ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "default".to_owned(),
        module: "example".to_owned(),
        target: "module.yaml".to_owned(),
        request_id: "test".to_owned(),
    }
}


#[test]
fn a_changed_tenant_drops_the_pending_oidc_logins() -> TestResult {
    let dir = tempdir()?;
    let oidc = oidc_settings(dir.path(), "oidc.secret")?;
    let running = live_with(dir, &oidc, None)?;
    let runtime = running.state.oidc.load_full().ok_or("no oidc")?;
    runtime.pending.lock().map_err(|_| "poisoned")?.insert(
        "state".to_owned(),
        core_auth::model::PendingLogin {
            nonce: "nonce".to_owned(),
            verifier: secrecy::SecretString::from("verifier"),
            created_at: time::OffsetDateTime::now_utc(),
            source: "10.0.0.1".to_owned(),
        },
    );
    fs::write(
        &running.module_file,
        format!("tenant: {NEW_TENANT}\n{}", module_text(running.dir.path(), "example", LOOPBACK, &oidc)?),
    )?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert!(runtime.pending.lock().map_err(|_| "poisoned")?.is_empty());
    assert!(identity_records(running.dir.path())?
        .iter()
        .any(|record| diff_of(record).contains("pending OIDC logins dropped")));
    Ok(())
}


#[test]
fn a_changed_tenant_is_audited_before_the_swap_and_carried_after_it() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    seed(&running, vec![password_account(fixture::READER, None)?])?;
    let (status, reply) = running._runtime.block_on(login(&running, fixture::READER, None))?;
    let old_token = token_of(&reply)?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(running._runtime.block_on(token_status(&running, &old_token))?, StatusCode::OK);
    fs::write(
        &running.module_file,
        format!("tenant: {NEW_TENANT}\n{}", module_text(directory, "example", LOOPBACK, "")?),
    )?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    let records = audit_records(directory)?;
    let engine_record = records
        .iter()
        .find(|record| field(record, "action") == "config.reload" && diff_of(record).contains(NEW_TENANT))
        .ok_or("no engine record")?;
    assert_eq!(field(engine_record, "tenant"), "default");
    assert_eq!(identity_records(directory)?.len(), 1);
    assert!(identity_records(directory)?.iter().all(|record| field(record, "tenant") == NEW_TENANT));
    assert_eq!(running._runtime.block_on(token_status(&running, &old_token))?, StatusCode::UNAUTHORIZED);
    let (new_status, new_reply) = running._runtime.block_on(login(&running, fixture::READER, None))?;
    assert_eq!(new_status, StatusCode::OK);
    assert_eq!(running._runtime.block_on(token_status(&running, &token_of(&new_reply)?))?, StatusCode::OK);
    let after: Vec<serde_json::Value> = audit_records(directory)?.into_iter().skip(records.len()).collect();
    assert!(!after.is_empty() && after.iter().all(|record| field(record, "tenant") == NEW_TENANT));
    Ok(())
}


#[test]
fn a_changed_name_is_carried_by_the_records_the_document_and_ends_the_sessions() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    seed(&running, vec![password_account(fixture::READER, None)?])?;
    let (_, reply) = running._runtime.block_on(login(&running, fixture::READER, None))?;
    let old_token = token_of(&reply)?;
    fs::write(&running.module_file, module_text(directory, NEW_NAME, LOOPBACK, "")?)?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(running._runtime.block_on(token_status(&running, &old_token))?, StatusCode::UNAUTHORIZED);
    let (status, _) = running._runtime.block_on(login(&running, fixture::READER, None))?;
    assert_eq!(status, StatusCode::OK);
    let records = audit_records(directory)?;
    let revoked = identity_records(directory)?;
    assert_eq!(revoked.len(), 1);
    assert!(revoked.iter().all(|record| field(record, "module") == NEW_NAME));
    assert!(records
        .iter()
        .any(|record| field(record, "action") == "api.request" && field(record, "module") == NEW_NAME));
    let document = running
        ._runtime
        .block_on(async { body_json(get(&running.setup.router, "/openapi.json", None).await?).await })?;
    assert_eq!(document.pointer("/info/title").and_then(serde_json::Value::as_str), Some("renamed API"));
    Ok(())
}


#[test]
fn an_unchanged_identity_revokes_nothing() -> TestResult {
    let running = live("")?;
    add_session(&running, fixture::READER)?;
    let settings = build_settings(load_module(&running.module_file)?)?;
    assert!(accept(&settings).is_ok());
    switch_identity(&running.state, &test_context(), &settings);
    assert_eq!(lock_auth(&running.state).sessions.len(), 1);
    assert!(identity_records(running.dir.path())?.is_empty());
    Ok(())
}


#[test]
fn an_identity_change_with_a_failing_audit_still_swaps_and_is_only_logged() -> TestResult {
    let running = live("")?;
    add_session(&running, fixture::READER)?;
    fs::write(&running.module_file, module_text(running.dir.path(), NEW_NAME, LOOPBACK, "")?)?;
    let settings = build_settings(load_module(&running.module_file)?)?;
    running.state.audit.state.lock().map_err(|_| "poisoned")?.poisoned = true;
    switch_identity(&running.state, &test_context(), &settings);
    assert_eq!(running.state.identity.load().module, NEW_NAME);
    assert!(lock_auth(&running.state).sessions.is_empty());
    Ok(())
}


#[test]
fn a_rotated_key_reencrypts_the_store_and_totp_logins_keep_working() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    seed(
        &running,
        vec![
            password_account(fixture::READER, None)?,
            password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?,
        ],
    )?;
    let before = stored_secret(&running)?;
    let new_key_file = directory.join("new.key");
    private_file(&new_key_file, &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    fs::write(&running.module_file, module_with_key(directory, &new_key_file)?)?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    let after = stored_secret(&running)?;
    assert_ne!(before, after);
    assert!(open_secret(&store_key(OLD_KEY_FILL), TOTP_USER, &after).is_err());
    assert_eq!(
        open_secret(&store_key(NEW_KEY_FILL), TOTP_USER, &after)?,
        vec![TOTP_SECRET_FILL; TOTP_SECRET_BYTES]
    );
    assert_eq!(running.state.key.load().expose_secret(), store_key(NEW_KEY_FILL).expose_secret());
    let (status, _) = running._runtime.block_on(login(&running, TOTP_USER, Some(current_totp_code()?)))?;
    assert_eq!(status, StatusCode::OK);
    let log = fs::read_to_string(directory.join("audit.log"))?;
    assert!(log.contains("1 stored secrets re-encrypted"));
    assert!(!log.contains(&after) && !log.contains(&before));
    Ok(())
}


#[test]
fn a_key_rewritten_in_place_is_rotated_and_the_same_bytes_are_not() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    let key_file = directory.join("store.key");
    private_file(&key_file, &[OLD_KEY_FILL; fixture::KEY_BYTES])?;
    let unchanged = stored_secret(&running)?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Unchanged));
    assert_eq!(stored_secret(&running)?, unchanged);
    private_file(&key_file, &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    let after = stored_secret(&running)?;
    assert!(open_secret(&store_key(OLD_KEY_FILL), TOTP_USER, &after).is_err());
    assert_eq!(
        open_secret(&store_key(NEW_KEY_FILL), TOTP_USER, &after)?,
        vec![TOTP_SECRET_FILL; TOTP_SECRET_BYTES]
    );
    assert_eq!(running.state.key.load().expose_secret(), store_key(NEW_KEY_FILL).expose_secret());
    let (status, _) = running._runtime.block_on(login(&running, TOTP_USER, Some(current_totp_code()?)))?;
    assert_eq!(status, StatusCode::OK);
    assert!(matches!(reload(&running.engine), ReloadOutcome::Unchanged));
    let log = fs::read_to_string(directory.join("audit.log"))?;
    assert!(log.contains("1 stored secrets re-encrypted") && log.contains(FINGERPRINT_KEY));
    assert!(!log.contains(&after) && !log.contains(&unchanged));
    Ok(())
}


#[test]
fn the_key_file_is_watched() -> TestResult {
    let running = live("")?;
    let settings = build_settings(load_module(&running.module_file)?)?;
    assert!(watched_files(&running.module_file, &settings.config).contains(&running.dir.path().join("store.key")));
    Ok(())
}


#[test]
fn a_bad_new_key_refuses_the_reload_and_keeps_the_old_key_and_store() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    let stored = fs::read(directory.join("accounts.json"))?;
    let short = directory.join("short.key");
    private_file(&short, &[NEW_KEY_FILL; SHORT_KEY_BYTES])?;
    let loose = directory.join("loose.key");
    private_file(&loose, &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    set_mode(&loose, WORLD_READABLE)?;
    let candidates = if cfg!(unix) {
        vec![short, directory.join("absent.key"), loose]
    } else {
        vec![short, directory.join("absent.key")]
    };
    candidates.iter().try_for_each(|path| -> TestResult {
        fs::write(&running.module_file, module_with_key(directory, path)?)?;
        assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { .. }));
        assert_eq!(running.state.key.load().expose_secret(), store_key(OLD_KEY_FILL).expose_secret());
        assert_eq!(fs::read(directory.join("accounts.json"))?, stored);
        Ok(())
    })?;
    let refusals = reload_records(directory)?.iter().filter(|line| line.contains("refused")).count();
    assert_eq!(refusals, candidates.len());
    Ok(())
}


#[test]
fn a_secret_that_does_not_decrypt_refuses_the_rotation_and_changes_nothing() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(THIRD_KEY_FILL)?))?])?;
    let stored = fs::read(directory.join("accounts.json"))?;
    let new_key_file = directory.join("new.key");
    private_file(&new_key_file, &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    fs::write(&running.module_file, module_with_key(directory, &new_key_file)?)?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { ref reason } if reason.contains("could not be decrypted")));
    assert_eq!(fs::read(directory.join("accounts.json"))?, stored);
    assert_eq!(running.state.key.load().expose_secret(), store_key(OLD_KEY_FILL).expose_secret());
    assert!(reload_records(directory)?.iter().any(|line| line.contains("refused")));
    Ok(())
}


fn block_store_lock(live: &Live) -> Result<PathBuf, TestError> {
    let lock = lock_path(&live.state.store_path.load());
    fs::remove_file(&lock)?;
    fs::create_dir(&lock)?;
    Ok(lock)
}


fn unblock_store_lock(lock: &Path) -> TestResult {
    fs::remove_dir(lock)?;
    Ok(())
}


#[test]
fn a_rotation_that_fails_after_validation_keeps_the_old_key_and_is_audited() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    let new_key_file = directory.join("new.key");
    private_file(&new_key_file, &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    fs::write(&running.module_file, module_with_key(directory, &new_key_file)?)?;
    let settings = build_settings(load_module(&running.module_file)?)?;
    let prepared = Arc::new(Mutex::new(None));
    switch_key(&running.state, &test_context(), &prepared, &settings);
    assert!(reload_records(directory)?.is_empty());
    prepare_key(&running.state, &prepared, &settings).map_err(|error| error.to_string())?;
    assert!(prepared.lock().map_err(|_| "poisoned")?.is_some());
    let stored = fs::read(directory.join("accounts.json"))?;
    block_store_lock(&running)?;
    switch_key(&running.state, &test_context(), &prepared, &settings);
    assert_eq!(fs::read(directory.join("accounts.json"))?, stored);
    assert_eq!(running.state.key.load().expose_secret(), store_key(OLD_KEY_FILL).expose_secret());
    assert!(reload_records(directory)?.iter().any(|line| line.contains("key_rotation_failed")));
    Ok(())
}


#[test]
fn a_failed_rotation_is_retried_by_the_next_reload_with_the_same_bytes() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    let new_key_file = directory.join("new.key");
    private_file(&new_key_file, &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    fs::write(&running.module_file, module_with_key(directory, &new_key_file)?)?;
    let lock = block_store_lock(&running)?;
    let failed = reload(&running.engine);
    unblock_store_lock(&lock)?;
    assert!(matches!(failed, ReloadOutcome::Applied { .. }));
    assert_eq!(running.state.key.load().expose_secret(), store_key(OLD_KEY_FILL).expose_secret());
    let failures = |records: Vec<String>| records.iter().filter(|line| line.contains("key_rotation_failed")).count();
    assert_eq!(failures(reload_records(directory)?), 1);
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(running.state.key.load().expose_secret(), store_key(NEW_KEY_FILL).expose_secret());
    assert_eq!(failures(reload_records(directory)?), 1);
    assert_eq!(reload(&running.engine), ReloadOutcome::Unchanged);
    Ok(())
}


#[test]
fn a_rotation_that_keeps_failing_is_retried_and_audited_each_time() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    let new_key_file = directory.join("new.key");
    private_file(&new_key_file, &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    fs::write(&running.module_file, module_with_key(directory, &new_key_file)?)?;
    block_store_lock(&running)?;
    let outcomes = [reload(&running.engine), reload(&running.engine)];
    assert!(outcomes.iter().all(|outcome| matches!(outcome, ReloadOutcome::Applied { .. })));
    let failures = reload_records(directory)?
        .iter()
        .filter(|line| line.contains("key_rotation_failed"))
        .count();
    assert_eq!(failures, outcomes.len());
    Ok(())
}


#[test]
fn a_store_with_one_unreadable_secret_among_readable_ones_is_refused_at_startup_with_the_count() -> TestResult {
    let running = live("")?;
    seed(
        &running,
        vec![
            password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?,
            password_account(SECOND_TOTP_USER, Some(totp_enrolment_for(SECOND_TOTP_USER, THIRD_KEY_FILL)?))?,
        ],
    )?;
    let settings = build_settings(load_module(&running.module_file)?)?;
    let inputs = StateInputs {
        key: settings.key.clone(),
        compromised: settings.compromised.clone(),
        oidc: settings.oidc.clone(),
    };
    let refused = build_state(&settings.config, &inputs, extra_access(), Vec::new())
        .err()
        .ok_or("started")?;
    let message = refused.to_string();
    assert!(
        message.contains("1 of 2 stored TOTP secrets") && !message.contains(SECOND_TOTP_USER),
        "{message}"
    );
    Ok(())
}


#[test]
fn a_key_that_does_not_decrypt_the_store_is_refused_at_startup_naming_the_previous_key_path() -> TestResult {
    let running = live("")?;
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(THIRD_KEY_FILL)?))?])?;
    let settings = build_settings(load_module(&running.module_file)?)?;
    let inputs = StateInputs {
        key: settings.key.clone(),
        compromised: settings.compromised.clone(),
        oidc: settings.oidc.clone(),
    };
    let refused = build_state(&settings.config, &inputs, extra_access(), Vec::new())
        .err()
        .ok_or("started")?;
    let message = refused.to_string();
    assert!(
        message.contains("store.key.previous") && message.contains("does not decrypt"),
        "{message}"
    );
    Ok(())
}


#[test]
fn a_key_rotation_with_a_failing_audit_still_swaps_and_is_only_logged() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    let new_key_file = directory.join("new.key");
    private_file(&new_key_file, &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    fs::write(&running.module_file, module_with_key(directory, &new_key_file)?)?;
    let settings = build_settings(load_module(&running.module_file)?)?;
    let prepared = Arc::new(Mutex::new(None));
    prepare_key(&running.state, &prepared, &settings).map_err(|error| error.to_string())?;
    running.state.audit.state.lock().map_err(|_| "poisoned")?.poisoned = true;
    switch_key(&running.state, &test_context(), &prepared, &settings);
    assert_eq!(running.state.key.load().expose_secret(), store_key(NEW_KEY_FILL).expose_secret());
    Ok(())
}


#[test]
fn resealing_counts_the_secrets_and_a_bad_account_fails_the_whole_change() -> TestResult {
    let mut accounts = AccountMap::new();
    accounts.insert(TOTP_USER.to_owned(), password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?);
    accounts.insert(fixture::READER.to_owned(), password_account(fixture::READER, None)?);
    assert_eq!(
        reseal_accounts(&mut accounts, &store_key(OLD_KEY_FILL), &store_key(NEW_KEY_FILL), os_random)?,
        1
    );
    assert!(reseal_accounts(&mut accounts, &store_key(OLD_KEY_FILL), &store_key(NEW_KEY_FILL), os_random).is_err());
    Ok(())
}


#[test]
fn a_group_readable_moved_store_is_refused_through_the_handle_that_is_parsed() -> TestResult {
    let dir = tempdir()?;
    let loose = dir.path().join("loose.json");
    save_store_file(&loose, &AccountMap::new(), &CredentialMap::new(), os_random)?;
    set_mode(&loose, WORLD_READABLE)?;
    assert_eq!(read_store_handle(&loose).is_err(), cfg!(unix));
    set_mode(&loose, OWNER_ONLY)?;
    assert!(read_store_handle(&loose).is_ok());
    assert!(read_store_handle(&dir.path().join("absent.json")).is_err());
    Ok(())
}


fn failing_random(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


#[test]
fn a_failing_random_source_fails_the_resealing() -> TestResult {
    let mut accounts = AccountMap::new();
    accounts.insert(TOTP_USER.to_owned(), password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?);
    assert!(reseal_accounts(&mut accounts, &store_key(OLD_KEY_FILL), &store_key(NEW_KEY_FILL), failing_random).is_err());
    Ok(())
}


#[cfg(unix)]
#[test]
fn an_unreadable_store_refuses_the_key_rotation_and_a_secret_that_stops_opening_fails_the_apply() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    let new_key_file = directory.join("new.key");
    private_file(&new_key_file, &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    fs::write(&running.module_file, module_with_key(directory, &new_key_file)?)?;
    let settings = build_settings(load_module(&running.module_file)?)?;
    let prepared = Arc::new(Mutex::new(None));
    set_mode(&directory.join("accounts.json"), WORLD_READABLE)?;
    assert!(prepare_key(&running.state, &prepared, &settings).is_err());
    set_mode(&directory.join("accounts.json"), OWNER_ONLY)?;
    prepare_key(&running.state, &prepared, &settings).map_err(|error| error.to_string())?;
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(THIRD_KEY_FILL)?))?])?;
    switch_key(&running.state, &test_context(), &prepared, &settings);
    assert_eq!(running.state.key.load().expose_secret(), store_key(OLD_KEY_FILL).expose_secret());
    assert!(reload_records(directory)?.iter().any(|line| line.contains("could not be decrypted")));
    Ok(())
}


fn pending_login(source: &str) -> core_auth::model::PendingLogin {
    core_auth::model::PendingLogin {
        nonce: "nonce".to_owned(),
        verifier: secrecy::SecretString::from("verifier"),
        created_at: time::OffsetDateTime::now_utc(),
        source: source.to_owned(),
    }
}


fn callback_for(state: &str) -> Callback {
    Callback {
        state: state.to_owned(),
        code: secrecy::SecretString::from("code"),
        source: "10.0.0.1".to_owned(),
    }
}


fn bare_identity() -> Identity {
    Identity {
        subject: "subject".to_owned(),
        groups: Default::default(),
        amr: Default::default(),
        acr: None,
    }
}


fn renamed_settings(running: &Live, oidc: &str) -> Result<ApiSettings, TestError> {
    fs::write(
        &running.module_file,
        format!("tenant: {NEW_TENANT}\n{}", module_text(running.dir.path(), "example", LOOPBACK, oidc)?),
    )?;
    Ok(build_settings(load_module(&running.module_file)?)?)
}


const GENERATION_POLLS: usize = 20_000;


const GENERATION_POLL_MILLIS: u64 = 1;


#[test]
fn a_login_taken_while_the_identity_switch_waits_is_refused_at_settle() -> TestResult {
    let dir = tempdir()?;
    let oidc = oidc_settings(dir.path(), "oidc.secret")?;
    let running = live_with(dir, &oidc, None)?;
    let runtime = running.state.oidc.load_full().ok_or("no oidc")?;
    let before = running.state.identity.load().generation;
    runtime
        .pending
        .lock()
        .map_err(|_| "poisoned")?
        .insert(hash_token("state"), pending_login("10.0.0.1"));
    runtime.generations.lock().map_err(|_| "poisoned")?.insert(hash_token("state"), before);
    let settings = renamed_settings(&running, &oidc)?;
    let held = lock_auth(&running.state);
    let started = std::thread::scope(|scope| -> Result<_, TestError> {
        scope.spawn(|| switch_identity(&running.state, &test_context(), &settings));
        let changed = (0..GENERATION_POLLS).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(GENERATION_POLL_MILLIS));
            running.state.identity.load().generation != before
        });
        assert!(changed);
        let (_, started) = take_login(&running.state, &runtime, "test", &callback_for("state")).map_err(|_| "login not taken")?;
        drop(held);
        Ok(started)
    })?;
    assert_eq!(started, before);
    let refused = settle(&running.state, &runtime, "test", &bare_identity(), &callback_for("state"), started);
    assert!(matches!(refused, Err(ApiError::InvalidCredentials)));
    assert!(lock_auth(&running.state).sessions.is_empty());
    assert!(runtime.pending.lock().map_err(|_| "poisoned")?.is_empty());
    assert!(runtime.generations.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}


#[test]
fn a_login_stored_after_the_identity_switch_is_refused() -> TestResult {
    let dir = tempdir()?;
    let oidc = oidc_settings(dir.path(), "oidc.secret")?;
    let running = live_with(dir, &oidc, None)?;
    let runtime = running.state.oidc.load_full().ok_or("no oidc")?;
    let started = running.state.identity.load().generation;
    let settings = renamed_settings(&running, &oidc)?;
    switch_identity(&running.state, &test_context(), &settings);
    let fresh = core_auth::types::PendingMap::from([("late".to_owned(), pending_login("10.0.0.1"))]);
    let refused = store_pending(&running.state, &runtime, "test", "10.0.0.1", started, fresh);
    assert!(matches!(refused, Err(ApiError::InvalidCredentials)));
    assert!(runtime.pending.lock().map_err(|_| "poisoned")?.is_empty());
    let current = running.state.identity.load().generation;
    let kept = core_auth::types::PendingMap::from([("kept".to_owned(), pending_login("10.0.0.1"))]);
    assert!(store_pending(&running.state, &runtime, "test", "10.0.0.1", current, kept).is_ok());
    assert_eq!(runtime.generations.lock().map_err(|_| "poisoned")?.get("kept"), Some(&current));
    Ok(())
}


#[test]
fn a_login_without_a_recorded_generation_is_refused_at_settle() -> TestResult {
    let dir = tempdir()?;
    let oidc = oidc_settings(dir.path(), "oidc.secret")?;
    let running = live_with(dir, &oidc, None)?;
    let runtime = running.state.oidc.load_full().ok_or("no oidc")?;
    runtime
        .pending
        .lock()
        .map_err(|_| "poisoned")?
        .insert(hash_token("bare"), pending_login("10.0.0.1"));
    let (_, started) = take_login(&running.state, &runtime, "test", &callback_for("bare")).map_err(|_| "login not taken")?;
    let refused = settle(&running.state, &runtime, "test", &bare_identity(), &callback_for("bare"), started);
    assert!(matches!(refused, Err(ApiError::InvalidCredentials)));
    Ok(())
}


fn previous_of(running: &Live) -> PathBuf {
    previous_key_path(&running.dir.path().join("store.key"))
}


fn restarted(running: &Live) -> Result<ApiState, StartupError> {
    let settings = build_settings(load_module(&running.module_file)?)?;
    let inputs = StateInputs {
        key: settings.key.clone(),
        compromised: settings.compromised.clone(),
        oidc: settings.oidc.clone(),
    };
    build_state(&settings.config, &inputs, extra_access(), Vec::new())
}


fn audit_text(running: &Live) -> Result<Vec<u8>, TestError> {
    Ok(fs::read(running.dir.path().join("audit.log"))?)
}


#[cfg(unix)]
fn assert_private(path: &Path) -> TestResult {
    assert_eq!(fs::metadata(path)?.permissions().mode() & PERMISSION_BITS, OWNER_ONLY);
    Ok(())
}


#[cfg(not(unix))]
fn assert_private(_path: &Path) -> TestResult {
    Ok(())
}


fn holds_key(bytes: &[u8], fill: u8) -> bool {
    bytes.windows(fixture::KEY_BYTES).any(|window| window.iter().all(|byte| *byte == fill))
}


fn fail_rotation_in_place(running: &Live) -> TestResult {
    seed(running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    private_file(&running.dir.path().join("store.key"), &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    let lock = block_store_lock(running)?;
    let failed = reload(&running.engine);
    unblock_store_lock(&lock)?;
    assert!(matches!(failed, ReloadOutcome::Applied { .. }));
    Ok(())
}


#[test]
fn a_failed_rotation_keeps_the_previous_key_and_a_restart_finishes_it() -> TestResult {
    let running = live("")?;
    fail_rotation_in_place(&running)?;
    let previous = previous_of(&running);
    assert_eq!(fs::read(&previous)?, vec![OLD_KEY_FILL; fixture::KEY_BYTES]);
    assert_private(&previous)?;
    assert_eq!(running.state.key.load().expose_secret(), store_key(OLD_KEY_FILL).expose_secret());
    let state = Arc::new(restarted(&running)?);
    assert!(!previous.exists());
    let (accounts, _) = load_store_file(&running.state.store_path.load())?;
    let stored = &accounts
        .get(TOTP_USER)
        .and_then(|account| account.totp.as_ref())
        .ok_or("no totp")?
        .encrypted_secret;
    assert_eq!(
        open_secret(&store_key(NEW_KEY_FILL), TOTP_USER, stored)?,
        vec![TOTP_SECRET_FILL; TOTP_SECRET_BYTES]
    );
    let router = build_router(state, extra_router());
    let (status, _) = running._runtime.block_on(login_router(&router, TOTP_USER, Some(current_totp_code()?)))?;
    assert_eq!(status, StatusCode::OK);
    let audit = audit_text(&running)?;
    let text = String::from_utf8(audit.clone())?;
    assert!(text.contains(PREVIOUS_KEY_SAVED) && text.contains(ROTATION_RESUMED) && text.contains(PREVIOUS_KEY_REMOVED));
    assert!(!holds_key(&audit, OLD_KEY_FILL) && !holds_key(&audit, NEW_KEY_FILL));
    Ok(())
}


#[test]
fn a_successful_rotation_saves_then_removes_the_previous_key_and_audits_both() -> TestResult {
    let running = live("")?;
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    private_file(&running.dir.path().join("store.key"), &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert!(!previous_of(&running).exists());
    let text = String::from_utf8(audit_text(&running)?)?;
    assert!(text.contains(PREVIOUS_KEY_SAVED) && text.contains(PREVIOUS_KEY_REMOVED));
    assert!(!holds_key(text.as_bytes(), OLD_KEY_FILL) && !holds_key(text.as_bytes(), NEW_KEY_FILL));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_symlinked_or_foreign_previous_key_is_refused_for_writing_and_for_reading() -> TestResult {
    let running = live("")?;
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    let directory = running.dir.path();
    let decoy = directory.join("decoy.key");
    private_file(&decoy, &[OLD_KEY_FILL; fixture::KEY_BYTES])?;
    let previous = previous_of(&running);
    std::os::unix::fs::symlink(&decoy, &previous)?;
    private_file(&directory.join("store.key"), &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(running.state.key.load().expose_secret(), store_key(OLD_KEY_FILL).expose_secret());
    assert!(fs::symlink_metadata(&previous)?.file_type().is_symlink());
    assert!(matches!(restarted(&running), Err(StartupError::PreviousKey { .. })));
    fs::remove_file(&previous)?;
    private_file(&previous, &[OLD_KEY_FILL; fixture::KEY_BYTES])?;
    match std::os::unix::fs::chown(&previous, Some(FOREIGN_UID), None) {
        Ok(()) => {
            assert!(matches!(restarted(&running), Err(StartupError::PreviousKey { .. })));
            assert!(write_previous_key(&directory.join("store.key"), &store_key(OLD_KEY_FILL), os_random).is_err());
            assert_eq!(std::os::unix::fs::MetadataExt::uid(&fs::metadata(&previous)?), FOREIGN_UID);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(error.into()),
    }
}


#[cfg(unix)]
#[test]
fn a_previous_key_that_is_loose_short_or_a_directory_is_refused() -> TestResult {
    let running = live("")?;
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    private_file(&running.dir.path().join("store.key"), &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    let previous = previous_of(&running);
    private_file(&previous, &[OLD_KEY_FILL; fixture::KEY_BYTES])?;
    set_mode(&previous, WORLD_READABLE)?;
    assert!(matches!(restarted(&running), Err(StartupError::PreviousKey { .. })));
    private_file(&previous, &[OLD_KEY_FILL; SHORT_KEY_BYTES])?;
    assert!(matches!(restarted(&running), Err(StartupError::PreviousKey { .. })));
    fs::remove_file(&previous)?;
    fs::create_dir(&previous)?;
    assert!(matches!(restarted(&running), Err(StartupError::PreviousKey { .. })));
    assert!(write_previous_key(&running.dir.path().join("store.key"), &store_key(OLD_KEY_FILL), os_random).is_err());
    let blocked = running.dir.path().join("store.key");
    assert!(check_previous_slot(&blocked.join("below")).is_err());
    assert!(read_previous_key(&blocked.join("below")).is_err());
    Ok(())
}


#[test]
fn a_store_that_neither_key_opens_stays_refused_and_untouched() -> TestResult {
    let running = live("")?;
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(THIRD_KEY_FILL)?))?])?;
    private_file(&running.dir.path().join("store.key"), &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    private_file(&previous_of(&running), &[OLD_KEY_FILL; fixture::KEY_BYTES])?;
    let stored = fs::read(running.dir.path().join("accounts.json"))?;
    assert!(matches!(restarted(&running), Err(StartupError::StoreKeyMismatch { .. })));
    assert_eq!(fs::read(running.dir.path().join("accounts.json"))?, stored);
    assert!(previous_of(&running).exists());
    Ok(())
}


#[test]
fn a_store_sealed_under_the_new_key_while_the_live_key_is_old_is_adopted() -> TestResult {
    let running = live("")?;
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    private_file(&running.dir.path().join("store.key"), &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    let settings = build_settings(load_module(&running.module_file)?)?;
    let prepared = Arc::new(Mutex::new(None));
    prepare_key(&running.state, &prepared, &settings).map_err(|error| error.to_string())?;
    update_store_file(&running.state.store_path.load(), os_random, |accounts, _| {
        reseal_accounts(accounts, &store_key(OLD_KEY_FILL), &store_key(NEW_KEY_FILL), os_random)
    })?
    .saved?;
    switch_key(&running.state, &test_context(), &prepared, &settings);
    assert_eq!(running.state.key.load().expose_secret(), store_key(NEW_KEY_FILL).expose_secret());
    assert!(!previous_of(&running).exists());
    let again = Arc::new(Mutex::new(None));
    prepare_key(&running.state, &again, &settings).map_err(|error| error.to_string())?;
    assert!(again.lock().map_err(|_| "poisoned")?.is_none());
    Ok(())
}


#[test]
fn a_reload_that_already_finds_the_store_sealed_under_the_new_key_is_accepted() -> TestResult {
    let running = live("")?;
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    update_store_file(&running.state.store_path.load(), os_random, |accounts, _| {
        reseal_accounts(accounts, &store_key(OLD_KEY_FILL), &store_key(NEW_KEY_FILL), os_random)
    })?
    .saved?;
    private_file(&running.dir.path().join("store.key"), &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(running.state.key.load().expose_secret(), store_key(NEW_KEY_FILL).expose_secret());
    let (status, _) = running._runtime.block_on(login(&running, TOTP_USER, Some(current_totp_code()?)))?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}


fn write_moved_store(directory: &Path, fill: u8) -> TestResult {
    let mut accounts = AccountMap::new();
    accounts.insert(TOTP_USER.to_owned(), password_account(TOTP_USER, Some(totp_enrolment(fill)?))?);
    let path = directory.join("moved.json");
    save_store_file(&path, &accounts, &CredentialMap::new(), os_random)?;
    set_mode(&path, OWNER_ONLY)
}


#[test]
fn a_moved_store_must_open_under_the_live_or_the_new_key() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    let plain = module_text(directory, "example", LOOPBACK, "")?;
    write_moved_store(directory, THIRD_KEY_FILL)?;
    fs::write(&running.module_file, plain.replace("accounts.json", "moved.json"))?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Refused { ref reason } if reason.contains("does not decrypt")));
    write_moved_store(directory, OLD_KEY_FILL)?;
    assert!(matches!(reload(&running.engine), ReloadOutcome::Applied { .. }));
    Ok(())
}


#[test]
fn a_moved_store_sealed_under_the_new_key_is_accepted_with_the_new_key() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    let plain = module_text(directory, "example", LOOPBACK, "")?;
    write_moved_store(directory, NEW_KEY_FILL)?;
    fs::write(&running.module_file, plain.replace("accounts.json", "moved.json"))?;
    private_file(&directory.join("store.key"), &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    let settings = build_settings(load_module(&running.module_file)?)?;
    assert!(check_store(&running.state, &settings).is_ok());
    Ok(())
}


fn failing_remove(_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other("injected"))
}


fn fixed_random(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    buffer.fill(FIXED_RANDOM_BYTE);
    Ok(())
}


#[test]
fn a_previous_key_that_cannot_be_removed_is_logged_and_audited() -> TestResult {
    let running = live("")?;
    let key_file = running.dir.path().join("store.key");
    retire_previous_with(&running.state.audit, &test_context(), &key_file, failing_remove);
    let text = String::from_utf8(audit_text(&running)?)?;
    assert!(text.contains(PREVIOUS_KEY_REMOVAL_FAILED) && text.contains("injected"));
    assert!(remove_synced(&previous_of(&running)).is_err());
    retire_previous(&running.state.audit, &test_context(), &key_file);
    assert_eq!(
        String::from_utf8(audit_text(&running)?)?.matches(PREVIOUS_KEY_REMOVAL_FAILED).count(),
        TWO_RECORDS
    );
    Ok(())
}


#[test]
fn a_failed_temporary_write_is_cleaned_up_or_logged_and_a_failing_random_is_refused() -> TestResult {
    let running = live("")?;
    let key_file = running.dir.path().join("store.key");
    let temporary = running.dir.path().join("store.key.previous.abababababababab.tmp");
    fs::write(&temporary, b"stale")?;
    assert!(write_previous_key(&key_file, &store_key(OLD_KEY_FILL), fixed_random).is_err());
    assert!(!temporary.exists());
    fs::create_dir(&temporary)?;
    assert!(write_previous_key(&key_file, &store_key(OLD_KEY_FILL), fixed_random).is_err());
    assert!(temporary.is_dir());
    assert!(write_previous_key(&key_file, &store_key(OLD_KEY_FILL), failing_random).is_err());
    assert!(!previous_of(&running).exists());
    Ok(())
}


#[test]
fn a_stale_previous_key_is_removed_at_startup_and_audited() -> TestResult {
    let running = live("")?;
    seed(&running, vec![password_account(TOTP_USER, Some(totp_enrolment(OLD_KEY_FILL)?))?])?;
    let previous = previous_of(&running);
    private_file(&previous, &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    restarted(&running)?;
    assert!(!previous.exists());
    let audit = audit_text(&running)?;
    assert!(String::from_utf8(audit.clone())?.contains(PREVIOUS_KEY_REMOVED));
    assert!(!holds_key(&audit, OLD_KEY_FILL) && !holds_key(&audit, NEW_KEY_FILL));
    restarted(&running)?;
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_stale_previous_that_is_not_a_regular_file_is_left_and_the_start_goes_on() -> TestResult {
    let running = live("")?;
    let previous = previous_of(&running);
    fs::create_dir(&previous)?;
    restarted(&running)?;
    assert!(previous.is_dir());
    fs::remove_dir(&previous)?;
    let decoy = running.dir.path().join("decoy.key");
    private_file(&decoy, &[OLD_KEY_FILL; fixture::KEY_BYTES])?;
    std::os::unix::fs::symlink(&decoy, &previous)?;
    restarted(&running)?;
    assert!(previous.symlink_metadata().is_ok() && decoy.exists());
    assert!(!String::from_utf8(audit_text(&running)?)?.contains(PREVIOUS_KEY_REMOVED));
    Ok(())
}


#[test]
fn a_moved_store_sealed_under_the_new_key_is_adopted_even_when_the_previous_cannot_be_written() -> TestResult {
    let running = live("")?;
    let directory = running.dir.path();
    write_moved_store(directory, NEW_KEY_FILL)?;
    fs::create_dir(previous_of(&running))?;
    let plain = module_text(directory, "example", LOOPBACK, "")?;
    private_file(&directory.join("store.key"), &[NEW_KEY_FILL; fixture::KEY_BYTES])?;
    fs::write(&running.module_file, plain.replace("accounts.json", "moved.json"))?;
    let outcome = reload(&running.engine);
    assert!(matches!(outcome, ReloadOutcome::Applied { .. }), "{outcome:?}");
    assert_eq!(*running.state.store_path.load_full(), directory.join("moved.json"));
    assert_eq!(running.state.key.load().expose_secret(), store_key(NEW_KEY_FILL).expose_secret());
    assert!(!reload_records(directory)?.iter().any(|line| line.contains("key_rotation_failed")));
    Ok(())
}


#[test]
fn an_unreadable_live_store_is_not_taken_for_one_sealed_under_the_new_key() -> TestResult {
    let running = live("")?;
    running.state.store_path.store(Arc::new(running.dir.path().to_path_buf()));
    assert!(!store_sealed_under(&running.state, &store_key(NEW_KEY_FILL)));
    Ok(())
}
