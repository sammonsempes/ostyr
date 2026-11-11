#[path = "common/pki.rs"]
mod pki;
#[path = "common/sink.rs"]
mod sink;
#[path = "common/types.rs"]
mod types;


use core_audit::log::{append, genesis_log};
use core_config::reload::{current_config, reload, ReloadContext, ReloadEngine, ReloadOutcome};
use oncall::error::TransportError;
use oncall::limits::{MAX_SECRET_BYTES, MAX_SECRET_DIRS, MAX_TIMEOUT_MILLIS};
use oncall::model::{AlertNotice, Channel, ChannelKind, Message};
use oncall::notify::notify;
use oncall::secret::{read_secret, secret_text};
use oncall::settings::{open_settings_engine, parse_settings, settings_state, TransportSettings};
use oncall::transport::{build_agent, check_text, https_sender, https_url, payload, post, send_one};
use pki::{release_silent, spawn_silent, test_pki};
use sink::{spawn_sink, Seen};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::Path;
use std::sync::mpsc::channel as signal;
use std::sync::{Arc, Mutex};
use tempfile::{tempdir, TempDir};
use tracing::Dispatch;
use types::TestResult;


const INVALID_UTF8: &[u8] = &[u8::MAX, u8::MAX - 1];


const STATE_KEYS: usize = 4;


const TENANT: &str = "acme";


const SECRET: &str = "s3cr3t-tok3n-value";


const STATUS_OK: u16 = 200;


const STATUS_REDIRECT: u16 = 302;


const STATUS_ERROR: u16 = 500;


const TIMEOUT_MILLIS: u64 = 5000;


const SHORT_TIMEOUT_MILLIS: u64 = 150;


#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);


impl io::Write for Capture {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|error| io::Error::other(error.to_string())).map(|mut inner| {
            inner.extend_from_slice(buffer);
            buffer.len()
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


struct Fixture {
    directory: TempDir,
    settings: TransportSettings,
}


fn fixture(ca_pem: Option<&str>, timeout_millis: u64) -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let secrets = directory.path().join("secrets");
    fs::create_dir(&secrets)?;
    fs::write(secrets.join("token"), format!("{SECRET}\n"))?;
    let ca_file = match ca_pem {
        Some(pem) => {
            let path = directory.path().join("ca.pem");
            fs::write(&path, pem)?;
            Some(path.display().to_string())
        }
        None => None,
    };
    let settings = TransportSettings {
        timeout_millis,
        ca_file,
        secret_dirs: BTreeMap::from([(TENANT.to_string(), secrets.display().to_string())]),
        smtp: None,
    };
    Ok(Fixture { directory, settings })
}


fn channel_for(kind: ChannelKind, target: &str, secret_file: Option<&str>) -> Channel {
    Channel {
        name: "pager".to_string(),
        tenant: TENANT.to_string(),
        kind,
        target: target.to_string(),
        secret_file: secret_file.map(str::to_string),
    }
}


fn message() -> Message {
    Message {
        subject: "[acme] disk".to_string(),
        body: "label host: web-1".to_string(),
    }
}


fn url_of(port: u16) -> String {
    format!("https://localhost:{port}/hook")
}


fn send_to_one_sink(kind: ChannelKind, secret_file: Option<&str>) -> Result<Seen, Box<dyn std::error::Error>> {
    let pki = test_pki()?;
    let sink = spawn_sink(pki.server_config.clone(), vec![(STATUS_OK, String::new())])?;
    let fixture = fixture(Some(&pki.ca_pem), TIMEOUT_MILLIS)?;
    send_one(&fixture.settings, &channel_for(kind, &url_of(sink.port), secret_file), &message())?;
    let seen = sink.seen.join().map_err(|_panic| "sink panicked")??;
    seen.into_iter().next().ok_or_else(|| "nothing received".into())
}


#[test]
fn a_webhook_sends_its_json_body_with_the_bearer_token() -> TestResult {
    let seen = send_to_one_sink(ChannelKind::Webhook, Some("token"))?;
    assert_eq!(seen.authorization, format!("Bearer {SECRET}"));
    assert_eq!(seen.body, "label host: web-1");
    assert_eq!(seen.content_type, "application/json");
    Ok(())
}


#[test]
fn ntfy_sends_the_subject_as_title_and_no_header_without_a_secret() -> TestResult {
    let seen = send_to_one_sink(ChannelKind::Ntfy, None)?;
    assert_eq!(seen.title, "[acme] disk");
    assert_eq!(seen.authorization, "");
    assert_eq!(seen.body, "label host: web-1");
    assert!(seen.content_type.starts_with("text/plain"));
    Ok(())
}


#[test]
fn teams_slack_and_sms_send_a_json_text() -> TestResult {
    let expected = "[acme] disk\\nlabel host: web-1";
    assert_eq!(send_to_one_sink(ChannelKind::Teams, None)?.body, format!("{{\"text\":\"{expected}\"}}"));
    assert_eq!(send_to_one_sink(ChannelKind::Slack, None)?.body, format!("{{\"text\":\"{expected}\"}}"));
    assert_eq!(send_to_one_sink(ChannelKind::Sms, None)?.body, format!("{{\"message\":\"{expected}\"}}"));
    Ok(())
}


#[test]
fn smtp_is_not_an_https_kind() -> TestResult {
    assert!(matches!(payload(ChannelKind::Smtp, &message()), Err(TransportError::NotHttps)));
    Ok(())
}


#[test]
fn a_redirect_is_a_failure_and_the_second_listener_sees_nothing() -> TestResult {
    let pki = test_pki()?;
    let other = TcpListener::bind("127.0.0.1:0")?;
    other.set_nonblocking(true)?;
    let location = format!("https://localhost:{}/x", other.local_addr()?.port());
    let sink = spawn_sink(pki.server_config.clone(), vec![(STATUS_REDIRECT, location)])?;
    let fixture = fixture(Some(&pki.ca_pem), TIMEOUT_MILLIS)?;
    let outcome = send_one(
        &fixture.settings,
        &channel_for(ChannelKind::Webhook, &url_of(sink.port), Some("token")),
        &message(),
    );
    assert!(outcome.is_err());
    sink.seen.join().map_err(|_panic| "sink panicked")??;
    assert_eq!(other.accept().map(|_| ()).map_err(|error| error.kind()), Err(io::ErrorKind::WouldBlock));
    Ok(())
}


#[test]
fn an_error_status_is_a_failure() -> TestResult {
    let pki = test_pki()?;
    let sink = spawn_sink(pki.server_config.clone(), vec![(STATUS_ERROR, String::new())])?;
    let fixture = fixture(Some(&pki.ca_pem), TIMEOUT_MILLIS)?;
    let outcome = send_one(
        &fixture.settings,
        &channel_for(ChannelKind::Webhook, &url_of(sink.port), None),
        &message(),
    );
    assert!(matches!(outcome, Err(TransportError::Status)));
    sink.seen.join().map_err(|_panic| "sink panicked")??;
    Ok(())
}


#[test]
fn an_environment_proxy_is_ignored() -> TestResult {
    let pki = test_pki()?;
    let sink = spawn_sink(pki.server_config.clone(), vec![(STATUS_OK, String::new())])?;
    let fixture = fixture(Some(&pki.ca_pem), TIMEOUT_MILLIS)?;
    std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:1");
    std::env::set_var("ALL_PROXY", "http://127.0.0.1:1");
    send_one(
        &fixture.settings,
        &channel_for(ChannelKind::Webhook, &url_of(sink.port), None),
        &message(),
    )?;
    assert_eq!(sink.seen.join().map_err(|_panic| "sink panicked")??.len(), 1);
    Ok(())
}


#[test]
fn an_untrusted_certificate_and_a_cleartext_target_are_refused() -> TestResult {
    let pki = test_pki()?;
    let sink = spawn_sink(pki.server_config.clone(), vec![(STATUS_OK, String::new())])?;
    let other = test_pki()?;
    let fixture = fixture(Some(&other.ca_pem), TIMEOUT_MILLIS)?;
    let outcome = send_one(
        &fixture.settings,
        &channel_for(ChannelKind::Webhook, &url_of(sink.port), None),
        &message(),
    );
    assert!(matches!(outcome, Err(TransportError::Request(_))));
    assert!(sink.seen.join().map_err(|_panic| "sink panicked")?.is_err());
    let cleartext = channel_for(ChannelKind::Webhook, "http://localhost:1/x", None);
    assert!(matches!(send_one(&fixture.settings, &cleartext, &message()), Err(TransportError::Target)));
    Ok(())
}


#[test]
fn the_request_goes_to_the_parsed_url() -> TestResult {
    let channel = channel_for(ChannelKind::Webhook, "https://local\thost:1/a\nb", None);
    assert_eq!(https_url(&channel)?.as_str(), "https://localhost:1/ab");
    Ok(())
}


#[test]
fn a_server_that_never_answers_fails_on_the_injected_deadline() -> TestResult {
    let (release, wait) = signal();
    let silent = spawn_silent(wait)?;
    let port = silent.port;
    let fixture = fixture(None, SHORT_TIMEOUT_MILLIS)?;
    let outcome = send_one(&fixture.settings, &channel_for(ChannelKind::Webhook, &url_of(port), None), &message());
    assert!(matches!(outcome, Err(TransportError::Request(_))));
    release_silent(silent, &release)?;
    Ok(())
}


#[test]
fn forbidden_characters_are_refused_for_every_kind() -> TestResult {
    let fixture = fixture(None, TIMEOUT_MILLIS)?;
    ["\u{2028}", "\u{2029}", "\u{0085}", "\0"].iter().try_for_each(|forbidden| {
        let in_subject = Message {
            subject: format!("a{forbidden}b"),
            body: "ok".to_string(),
        };
        let in_body = Message {
            subject: "ok".to_string(),
            body: format!("a{forbidden}b"),
        };
        [in_subject, in_body].iter().try_for_each(|text| {
            assert!(matches!(check_text(text), Err(TransportError::ForbiddenChar)));
            let sent = send_one(&fixture.settings, &channel_for(ChannelKind::Slack, "https://localhost:1/x", None), text);
            assert!(matches!(sent, Err(TransportError::ForbiddenChar)));
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    })
}


#[test]
fn the_secret_file_stays_inside_the_tenant_directory() -> TestResult {
    let fixture = fixture(None, TIMEOUT_MILLIS)?;
    let outside = fixture.directory.path().join("outside");
    fs::write(&outside, SECRET)?;
    let absolute = outside.display().to_string();
    assert!(matches!(
        read_secret(&fixture.settings, TENANT, &absolute),
        Err(TransportError::SecretFile(_))
    ));
    assert!(matches!(
        read_secret(&fixture.settings, TENANT, "../outside"),
        Err(TransportError::SecretFile(_))
    ));
    assert!(matches!(
        read_secret(&fixture.settings, TENANT, "missing"),
        Err(TransportError::SecretFile(_))
    ));
    assert!(matches!(
        read_secret(&fixture.settings, "other", "token"),
        Err(TransportError::NoSecretsDir)
    ));
    assert_eq!(read_secret(&fixture.settings, TENANT, "token")?.as_str(), SECRET);
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_symlink_leaving_the_tenant_directory_is_refused() -> TestResult {
    let fixture = fixture(None, TIMEOUT_MILLIS)?;
    let outside = fixture.directory.path().join("outside");
    fs::write(&outside, SECRET)?;
    std::os::unix::fs::symlink(&outside, fixture.directory.path().join("secrets").join("link"))?;
    assert!(matches!(
        read_secret(&fixture.settings, TENANT, "link"),
        Err(TransportError::SecretFile(_))
    ));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_fifo_or_directory_as_secret_file_is_refused_without_blocking() -> TestResult {
    let fixture = fixture(None, TIMEOUT_MILLIS)?;
    let secrets = fixture.directory.path().join("secrets");
    assert!(std::process::Command::new("mkfifo").arg(secrets.join("pipe")).status()?.success());
    assert!(matches!(
        read_secret(&fixture.settings, TENANT, "pipe"),
        Err(TransportError::SecretFile(_))
    ));
    fs::create_dir(secrets.join("subdir"))?;
    assert!(matches!(
        read_secret(&fixture.settings, TENANT, "subdir"),
        Err(TransportError::SecretFile(_))
    ));
    Ok(())
}


#[test]
fn a_missing_secrets_directory_is_refused() -> TestResult {
    let mut fixture = fixture(None, TIMEOUT_MILLIS)?;
    fixture
        .settings
        .secret_dirs
        .insert(TENANT.to_string(), fixture.directory.path().join("absent").display().to_string());
    assert!(matches!(
        read_secret(&fixture.settings, TENANT, "token"),
        Err(TransportError::SecretFile(_))
    ));
    Ok(())
}


#[test]
fn an_oversized_or_malformed_secret_is_refused() -> TestResult {
    let fixture = fixture(None, TIMEOUT_MILLIS)?;
    let secrets = fixture.directory.path().join("secrets");
    fs::write(secrets.join("big"), vec![b'a'; MAX_SECRET_BYTES as usize + 1])?;
    assert!(matches!(
        read_secret(&fixture.settings, TENANT, "big"),
        Err(TransportError::SecretTooLarge { .. })
    ));
    fs::write(secrets.join("max"), vec![b'a'; MAX_SECRET_BYTES as usize])?;
    assert_eq!(read_secret(&fixture.settings, TENANT, "max")?.len() as u64, MAX_SECRET_BYTES);
    assert!(matches!(
        secret_text(&vec![b'a'; MAX_SECRET_BYTES as usize + 1]),
        Err(TransportError::SecretTooLarge { .. })
    ));
    assert!(matches!(secret_text(INVALID_UTF8), Err(TransportError::SecretFormat)));
    assert!(matches!(secret_text(b" \n"), Err(TransportError::SecretFormat)));
    assert!(matches!(secret_text(b"a\x01b"), Err(TransportError::SecretFormat)));
    assert!(matches!(secret_text(b"a\nb"), Err(TransportError::SecretFormat)));
    assert_eq!(secret_text(b"abc\r\n")?.as_str(), "abc");
    Ok(())
}


#[test]
fn the_ca_file_is_checked() -> TestResult {
    let mut fixture = fixture(None, TIMEOUT_MILLIS)?;
    fixture.settings.ca_file = Some(fixture.directory.path().join("absent.pem").display().to_string());
    assert!(matches!(build_agent(&fixture.settings), Err(TransportError::CaFile(_))));
    let junk = fixture.directory.path().join("junk.pem");
    fs::write(&junk, "not a certificate")?;
    fixture.settings.ca_file = Some(junk.display().to_string());
    assert!(matches!(build_agent(&fixture.settings), Err(TransportError::Certificate(_))));
    fixture.settings.ca_file = None;
    let agent = build_agent(&fixture.settings)?;
    let prepared = payload(ChannelKind::Webhook, &message())?;
    let url = https_url(&channel_for(ChannelKind::Webhook, "https://localhost:1/x", None))?;
    assert!(matches!(post(&agent, &url, &prepared), Err(TransportError::Request(_))));
    Ok(())
}


#[test]
fn the_secret_never_reaches_failures_debug_or_logs() -> TestResult {
    let pki = test_pki()?;
    let sink = spawn_sink(pki.server_config.clone(), vec![(STATUS_ERROR, String::new())])?;
    let fixture = fixture(Some(&pki.ca_pem), TIMEOUT_MILLIS)?;
    let settings_path = fixture.directory.path().join("transport.yaml");
    fs::write(&settings_path, settings_yaml(&fixture.settings))?;
    let engine = engine_for(&settings_path)?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer({
                let writer = Capture(captured.clone());
                move || writer.clone()
            })
            .finish(),
    );
    let alert = AlertNotice {
        tenant: TENANT.to_string(),
        name: "disk".to_string(),
        labels: BTreeMap::new(),
        annotations: BTreeMap::new(),
    };
    let channels = [channel_for(ChannelKind::Webhook, &url_of(sink.port), Some("token"))];
    let mut sender = https_sender(&engine);
    let failures = tracing::dispatcher::with_default(&dispatch, || notify(&alert, &channels, &mut sender))?;
    assert_eq!(failures.len(), 1);
    sink.seen.join().map_err(|_panic| "sink panicked")??;
    let logs = String::from_utf8(captured.lock().map_err(|error| error.to_string())?.clone())?;
    let debug = format!("{failures:?} {:?} {:?}", current_config(&engine), TransportError::Status);
    assert!(logs.contains("sender failed"));
    assert!(!logs.contains(SECRET) && !debug.contains(SECRET));
    assert!(!logs.contains("/hook") && !format!("{failures:?}").contains("/hook"));
    Ok(())
}


fn settings_yaml(settings: &TransportSettings) -> String {
    let ca = settings.ca_file.as_ref().map_or(String::new(), |path| format!("ca_file: {path}\n"));
    let dirs: String = settings.secret_dirs.iter().map(|(tenant, dir)| format!("  {tenant}: {dir}\n")).collect();
    format!("timeout_millis: {}\n{ca}secret_dirs:\n{dirs}", settings.timeout_millis)
}


fn engine_for(path: &Path) -> Result<ReloadEngine<TransportSettings>, Box<dyn std::error::Error>> {
    let log = genesis_log(io::sink());
    let context = ReloadContext {
        actor_id: "test".to_string(),
        tenant: TENANT.to_string(),
        module: "oncall".to_string(),
        target: path.display().to_string(),
        request_id: "r".to_string(),
    };
    Ok(open_settings_engine(path, Box::new(move |entry| append(&log, entry)), context)?)
}


#[test]
fn settings_are_reloaded_without_restart_and_an_invalid_file_keeps_the_old_ones() -> TestResult {
    let fixture = fixture(None, TIMEOUT_MILLIS)?;
    let path = fixture.directory.path().join("transport.yaml");
    fs::write(&path, settings_yaml(&fixture.settings))?;
    let engine = engine_for(&path)?;
    assert_eq!(current_config(&engine).timeout_millis, TIMEOUT_MILLIS);
    assert_eq!(settings_state(&current_config(&engine)).len(), STATE_KEYS);
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    fs::write(
        &path,
        settings_yaml(&TransportSettings {
            timeout_millis: SHORT_TIMEOUT_MILLIS,
            ..fixture.settings.clone()
        }),
    )?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).timeout_millis, SHORT_TIMEOUT_MILLIS);
    fs::write(&path, "timeout_millis: 0\nsecret_dirs: {}\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).timeout_millis, SHORT_TIMEOUT_MILLIS);
    Ok(())
}


#[test]
fn an_invalid_first_settings_file_is_refused() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("transport.yaml");
    fs::write(&path, "timeout_millis: 0\nsecret_dirs: {}\n")?;
    assert!(engine_for(&path).is_err());
    assert!(engine_for(&directory.path().join("absent.yaml")).is_err());
    Ok(())
}


#[test]
fn settings_bounds_are_enforced() -> TestResult {
    let refused = |text: &str| parse_settings(text, "s.yaml").is_err();
    assert!(parse_settings("timeout_millis: 1\nsecret_dirs: {}\n", "s.yaml").is_ok());
    assert!(refused("timeout_millis: 0\nsecret_dirs: {}\n"));
    assert!(refused(&format!("timeout_millis: {}\nsecret_dirs: {{}}\n", MAX_TIMEOUT_MILLIS + 1)));
    assert!(refused("timeout_millis: 1\nca_file: ''\nsecret_dirs: {}\n"));
    assert!(refused("timeout_millis: 1\nsecret_dirs:\n  '': /x\n"));
    assert!(refused("timeout_millis: 1\nsecret_dirs:\n  acme: ''\n"));
    assert!(refused("timeout_millis: 1\nsecret_dirs: {}\ntoken: abc\n"));
    let many: String = (0..=MAX_SECRET_DIRS).map(|index| format!("  t{index}: /x\n")).collect();
    assert!(refused(&format!("timeout_millis: 1\nsecret_dirs:\n{many}")));
    Ok(())
}


const TRACE_SECRET: &str = "BEARERTOKEN16BYT";


const HALF_LEN: usize = 8;


const TRACE_URL_PATH: &str = "/services/T000/B000/SLACKURLSECRET";


#[test]
fn the_log_bridge_at_trace_never_sees_the_bearer_token_or_the_url_path() -> TestResult {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(captured.clone());
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .try_init()
        .map_err(|error| error.to_string())?;
    let pki = test_pki()?;
    let sink = spawn_sink(pki.server_config.clone(), vec![(STATUS_OK, String::new())])?;
    let fixture = fixture(Some(&pki.ca_pem), TIMEOUT_MILLIS)?;
    let secrets = fixture.directory.path().join("secrets");
    fs::write(secrets.join("token"), TRACE_SECRET)?;
    let target = format!("https://localhost:{}{TRACE_URL_PATH}", sink.port);
    send_one(&fixture.settings, &channel_for(ChannelKind::Webhook, &target, Some("token")), &message())?;
    sink.seen.join().map_err(|_panic| "sink panicked")??;
    let logs = String::from_utf8(captured.lock().map_err(|error| error.to_string())?.clone())?;
    let (first_half, second_half) = TRACE_SECRET.split_at(HALF_LEN);
    let spaced_hex = |text: &str| text.bytes().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ");
    let lowered = logs.to_lowercase();
    assert!(!logs.contains(TRACE_SECRET));
    assert!(!logs.contains(first_half) && !logs.contains(second_half));
    assert!(!lowered.contains(&spaced_hex(first_half)) && !lowered.contains(&spaced_hex(second_half)));
    assert!(!logs.contains("SLACKURLSECRET"));
    assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    Ok(())
}
