#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/types.rs"]
mod types;


use core_api::config::{limits, log_level, DEFAULT_LOG_LEVEL, MAX_CONNECTIONS_PER_SOURCE};
use core_api::error::StartupError;
use core_api::logging::reloadable_dispatch;
use core_api::middleware::admit_source;
use core_api::model::ApiSettings;
use core_api::reload::{
    accept, build_settings, content_digest, file_digest, first_then_file, load_settings, open_reload, settings_state, validate_fixed, watched_files,
    FINGERPRINT_COMPROMISED, FINGERPRINT_OIDC, FINGERPRINT_TLS_CERTIFICATE, FINGERPRINT_TLS_KEY,
};
use core_api::server::run_module;
use core_api::state::{build_state, MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_MAX_REQUESTS, RATE_WINDOW_SECONDS};
use core_api::types::{LogLevelHandle, ServerHandle, SharedState};
use core_config::error::ConfigError;
use core_config::load::load_module;
use core_config::model::ModuleConfig;
use core_config::reload::{reload, ReloadEngine, ReloadOutcome};
use fixture::{extra_access, extra_router, fixture, private_file, set_mode};
use rcgen::generate_simple_self_signed;
use rustls::crypto::ring::default_provider;
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName};
use std::fs;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
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


const PLAIN_FILES: usize = 2;


const WITHOUT_CA_FILES: usize = 5;


const WITH_CA_FILES: usize = 6;


const TWO_RECORDS: usize = 2;


const HIGH_LIMIT: u32 = 1000;


const SOURCES: usize = 3;


const POLLS: usize = 100;


const POLL_PAUSE: Duration = Duration::from_millis(100);


const BODY_SECONDS: u64 = 3;


const WORLD_READABLE: u32 = 0o644;


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
    let state: SharedState = Arc::new(build_state(&settings.config, extra_access(), Vec::new())?);
    let tls = settings.tls.clone().map(axum_server::tls_rustls::RustlsConfig::from_config);
    let engine = open_reload(&state, settings, &module_file, tls.clone(), log)?;
    Ok(Live {
        dir,
        module_file,
        state,
        engine,
        tls,
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
    assert!(matches!(zero, Err(StartupError::ZeroSetting("max_sources"))));
    let level = log_level(&module_in(dir.path(), "  log_level: loud\n")?);
    assert!(matches!(level, Err(StartupError::InvalidSetting { name: "log_level", .. })));
    Ok(())
}


#[test]
fn digests_follow_the_content() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("file.txt");
    fs::write(&path, "one")?;
    let first = file_digest(&path)?;
    assert_eq!(first, content_digest(b"one"));
    fs::write(&path, "two")?;
    assert_ne!(file_digest(&path)?, first);
    assert!(file_digest(&dir.path().join("missing")).is_err());
    Ok(())
}


#[test]
fn settings_are_checked_and_fingerprinted_before_they_exist() -> TestResult {
    let dir = tempdir()?;
    let plain = build_settings(module_in(dir.path(), "")?)?;
    assert!(plain.tls.is_none() && plain.oidc.is_none());
    assert_eq!(plain.fingerprints.keys().collect::<Vec<_>>(), [FINGERPRINT_COMPROMISED]);
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
    assert!(refused.is_err_and(|error| error.to_string().contains("must not be zero")));
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
fn things_fixed_at_start_are_named_in_the_refusal() -> TestResult {
    let dir = tempdir()?;
    write_pki(dir.path(), &pki()?)?;
    let start = build_settings(module_in(dir.path(), "")?)?;
    assert!(accept(&start).is_ok());
    assert!(validate_fixed(&start.config, &start).is_ok());
    let other = dir.path().join("other");
    let cases = [
        ("listen", module_text(dir.path(), "example", "127.0.0.1:1", "")?),
        (
            "header_read_timeout_seconds",
            module_text(dir.path(), "example", LOOPBACK, "  header_read_timeout_seconds: 11\n")?,
        ),
        (
            "enabling or disabling TLS",
            module_text(dir.path(), "example", LOOPBACK, &tls_extra(dir.path()))?,
        ),
        ("name", module_text(dir.path(), "renamed", LOOPBACK, "")?),
        (
            "tenant",
            format!("tenant: elsewhere\n{}", module_text(dir.path(), "example", LOOPBACK, "")?),
        ),
        (
            "accounts_store",
            module_text(dir.path(), "example", LOOPBACK, "").map(|text| text.replace("accounts.json", "other.json"))?,
        ),
        (
            "audit_log",
            module_text(dir.path(), "example", LOOPBACK, "").map(|text| text.replace("audit.log", "other.log"))?,
        ),
        (
            "key_file",
            module_text(dir.path(), "example", LOOPBACK, "").map(|text| text.replace("store.key", &other.display().to_string()))?,
        ),
    ];
    cases.iter().try_for_each(|(expected, text)| -> TestResult {
        let path = dir.path().join("candidate.yaml");
        fs::write(&path, text)?;
        let candidate = build_settings(load_module(&path)?)?;
        let refusal = validate_fixed(&start.config, &candidate).err().ok_or("accepted")?;
        assert_eq!(refusal.to_string(), format!("{expected} needs a restart"));
        Ok(())
    })
}


#[test]
fn a_changed_listen_is_refused_audited_and_nothing_else_applies() -> TestResult {
    let running = live("")?;
    let both = module_text(running.dir.path(), "example", "127.0.0.1:1", "  rate_max_requests: 2\n")?;
    fs::write(&running.module_file, both)?;
    let outcome = reload(&running.engine);
    assert!(matches!(outcome, ReloadOutcome::Refused { ref reason } if reason.contains("listen needs a restart")));
    assert_eq!(running.state.limits.load().rate_max_requests, RATE_MAX_REQUESTS);
    let records = reload_records(running.dir.path())?;
    assert_eq!(records.len(), 1);
    assert!(records
        .iter()
        .all(|line| line.contains("refused") && line.contains("listen needs a restart")));
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


fn start_module(path: &Path) -> (ServerHandle, tokio::task::JoinHandle<Result<(), StartupError>>) {
    let handle = ServerHandle::new();
    let running = handle.clone();
    let arguments = vec![path.display().to_string()];
    (
        handle,
        tokio::spawn(async move { run_module(&arguments, extra_router(), extra_access(), vec![], running, None).await }),
    )
}


async fn listening(handle: &ServerHandle) -> Result<SocketAddr, TestError> {
    Ok(handle.listening().await.ok_or("server did not start")?)
}


#[tokio::test]
async fn editing_the_module_file_changes_the_running_server() -> TestResult {
    let dir = tempdir()?;
    let path = write_module(dir.path(), &format!("  rate_max_requests: {HIGH_LIMIT}\n"))?;
    let (handle, task) = start_module(&path);
    let address = listening(&handle).await?;
    assert!(status_of(address).await?.contains("200"));
    fs::write(
        &path,
        module_text(dir.path(), "example", "127.0.0.1:1", &format!("  rate_max_requests: {LOW_LIMIT}\n"))?,
    )?;
    let directory = dir.path();
    let refused = eventually(|| async move { Ok(reload_records(directory)?.iter().any(|line| line.contains("listen needs a restart"))) }).await?;
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
    handle.shutdown();
    assert!(task.await?.is_ok());
    Ok(())
}


#[cfg(unix)]
#[tokio::test]
async fn sighup_reloads_the_module_file() -> TestResult {
    let dir = tempdir()?;
    let path = write_module(dir.path(), &format!("  rate_max_requests: {HIGH_LIMIT}\n"))?;
    let (handle, task) = start_module(&path);
    let address = listening(&handle).await?;
    assert!(status_of(address).await?.contains("200"));
    fs::write(
        &path,
        module_text(dir.path(), "example", LOOPBACK, &format!("  rate_max_requests: {LOW_LIMIT}\n"))?,
    )?;
    signal_hook::low_level::raise(signal_hook::consts::SIGHUP)?;
    let limited = eventually(|| async move { Ok(status_of(address).await?.contains("429")) }).await?;
    assert!(limited);
    handle.shutdown();
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
    let (handle, task) = start_module(&path);
    let address = listening(&handle).await?;
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
    handle.shutdown();
    assert!(task.await?.is_ok());
    Ok(())
}
