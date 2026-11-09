#[path = "common/mailsink.rs"]
mod mailsink;
#[path = "common/pki.rs"]
mod pki;
#[path = "common/types.rs"]
mod types;


use mailsink::{spawn_drip, spawn_relay, Delivered, Mode};
use oncall::channel::validate_channel;
use oncall::error::TransportError;
use oncall::limits::{MAX_HOST_LEN, MAX_MAIL_BODY_BYTES, MAX_MAIL_SUBJECT_BYTES, MAX_USERNAME_LEN};
use oncall::model::{AlertNotice, Channel, ChannelKind, Message};
use oncall::notify::notify;
use oncall::settings::{parse_settings, validate_smtp, SmtpSettings, SmtpTls, TransportSettings};
use oncall::smtp::{hand_over, parse_address, send_mail};
use oncall::transport::{send_one, FORBIDDEN_CHARS};
use pki::{spawn_silent, test_pki};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io;
use std::sync::mpsc::channel as signal;
use std::sync::{Arc, Mutex};
use tempfile::{tempdir, TempDir};
use types::TestResult;


const TENANT: &str = "acme";


const PASSWORD: &str = "hunter2-pw";


const PLAIN_AUTH: &str = "AUTH PLAIN AG1haWxlcgBodW50ZXIyLXB3";


const SENDER: &str = "alerts@example.com";


const RECIPIENT: &str = "oncall@example.com";


const TIMEOUT_MILLIS: u64 = 5000;


const SHORT_TIMEOUT_MILLIS: u64 = 150;


const UNUSED_PORT: u16 = 1;


const SUBMISSION_PORT: u16 = 587;


const REPLY_TEXT: &str = "REPLYSECRETTEXT";


struct Fixture {
    directory: TempDir,
    settings: TransportSettings,
}


fn smtp_settings(port: u16, tls: SmtpTls, username: Option<&str>) -> SmtpSettings {
    SmtpSettings {
        host: "localhost".to_string(),
        port,
        tls,
        from: SENDER.to_string(),
        username: username.map(str::to_string),
    }
}


fn make_fixture(ca_pem: Option<&str>, smtp: Option<SmtpSettings>, timeout_millis: u64) -> Result<Fixture, Box<dyn Error>> {
    let directory = tempdir()?;
    let secrets = directory.path().join("secrets");
    fs::create_dir(&secrets)?;
    fs::write(secrets.join("smtp-pass"), format!("{PASSWORD}\n"))?;
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
        smtp,
    };
    Ok(Fixture { directory, settings })
}


fn mail_channel(target: &str, secret_file: Option<&str>) -> Channel {
    Channel {
        name: "mail".to_string(),
        tenant: TENANT.to_string(),
        kind: ChannelKind::Smtp,
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


fn alert() -> AlertNotice {
    AlertNotice {
        tenant: TENANT.to_string(),
        name: "disk".to_string(),
        labels: BTreeMap::new(),
        annotations: BTreeMap::new(),
    }
}


struct Attempt {
    outcome: Result<(), TransportError>,
    delivered: Delivered,
}


fn attempt(mode: Mode, tls: SmtpTls, secret: Option<&str>, username: Option<&str>) -> Result<Attempt, Box<dyn Error>> {
    let pki = test_pki()?;
    let relay = spawn_relay(pki.server_config.clone(), mode, None)?;
    let fixture = make_fixture(Some(&pki.ca_pem), Some(smtp_settings(relay.port, tls, username)), TIMEOUT_MILLIS)?;
    let outcome = send_one(&fixture.settings, &mail_channel(RECIPIENT, secret), &message());
    let delivered = relay.done.join().map_err(|_panic| "relay panicked")??;
    Ok(Attempt { outcome, delivered })
}


fn has_command(delivered: &Delivered, prefix: &str) -> bool {
    delivered.commands.iter().any(|command| command.starts_with(prefix))
}


#[test]
fn a_mail_is_delivered_over_starttls_with_the_expected_headers_and_credentials() -> TestResult {
    let Attempt { outcome, delivered } = attempt(Mode::Starttls, SmtpTls::Starttls, Some("smtp-pass"), Some("mailer"))?;
    outcome?;
    assert!(delivered.commands.contains(&PLAIN_AUTH.to_string()));
    assert!(has_command(&delivered, &format!("MAIL FROM:<{SENDER}>")));
    assert!(has_command(&delivered, &format!("RCPT TO:<{RECIPIENT}>")));
    assert!(delivered.data.contains(&format!("From: {SENDER}")));
    assert!(delivered.data.contains(&format!("To: {RECIPIENT}")));
    assert!(delivered.data.contains("Subject: [acme] disk"));
    assert!(delivered.data.contains("Content-Type: text/plain; charset=utf-8"));
    assert!(delivered.data.contains("label host: web-1"));
    Ok(())
}


#[test]
fn a_mail_is_delivered_over_implicit_tls_without_authentication() -> TestResult {
    let Attempt { outcome, delivered } = attempt(Mode::Implicit, SmtpTls::Implicit, None, Some("mailer"))?;
    outcome?;
    assert!(!has_command(&delivered, "AUTH"));
    assert!(delivered.data.contains("label host: web-1"));
    Ok(())
}


#[test]
fn a_server_without_starttls_is_refused_and_no_credential_is_sent() -> TestResult {
    let Attempt { outcome, delivered } = attempt(Mode::PlainOnly, SmtpTls::Starttls, Some("smtp-pass"), Some("mailer"))?;
    assert!(matches!(outcome, Err(TransportError::Smtp(_))));
    assert!(!has_command(&delivered, "AUTH"));
    assert!(!has_command(&delivered, "MAIL"));
    assert!(delivered.data.is_empty());
    Ok(())
}


#[test]
fn a_certificate_outside_the_configured_ca_or_the_system_roots_is_refused() -> TestResult {
    let server_pki = test_pki()?;
    let other_pki = test_pki()?;
    let relay = spawn_relay(server_pki.server_config.clone(), Mode::Implicit, None)?;
    let wrong_ca = make_fixture(
        Some(&other_pki.ca_pem),
        Some(smtp_settings(relay.port, SmtpTls::Implicit, None)),
        TIMEOUT_MILLIS,
    )?;
    assert!(matches!(
        send_one(&wrong_ca.settings, &mail_channel(RECIPIENT, None), &message()),
        Err(TransportError::Smtp(_))
    ));
    assert!(relay.done.join().is_ok());
    let system_roots = spawn_relay(server_pki.server_config.clone(), Mode::Implicit, None)?;
    let no_ca = make_fixture(None, Some(smtp_settings(system_roots.port, SmtpTls::Implicit, None)), TIMEOUT_MILLIS)?;
    assert!(matches!(
        send_one(&no_ca.settings, &mail_channel(RECIPIENT, None), &message()),
        Err(TransportError::Smtp(_))
    ));
    assert!(system_roots.done.join().is_ok());
    Ok(())
}


#[test]
fn hostile_addresses_are_refused_at_load_and_before_sending() -> TestResult {
    let hostile = [
        "x>,<y@evil",
        "mailto:a@example.com",
        "a@example.com\r\nBcc: x@example.com",
        "a@example.com\nBcc: x@example.com",
        "a\u{2028}b@example.com",
        "a\u{2029}b@example.com",
        "a\u{0085}b@example.com",
        "a\0b@example.com",
        "a b@example.com",
        "<a@example.com>",
        "a@example.com,b@example.com",
        "@example.com",
        "a@",
        "",
    ];
    let fixture = make_fixture(None, Some(smtp_settings(UNUSED_PORT, SmtpTls::Starttls, None)), TIMEOUT_MILLIS)?;
    hostile.iter().try_for_each(|target| {
        let channel = mail_channel(target, None);
        assert!(validate_channel(&channel).is_err(), "load accepted {target:?}");
        assert!(
            matches!(
                send_one(&fixture.settings, &channel, &message()),
                Err(TransportError::Address(_) | TransportError::ForbiddenChar)
            ),
            "send accepted {target:?}"
        );
        assert!(parse_address(target).is_err());
        Ok::<(), io::Error>(())
    })?;
    assert!(parse_address(RECIPIENT).is_ok());
    assert!(validate_channel(&mail_channel(RECIPIENT, None)).is_ok());
    Ok(())
}


#[test]
fn line_breaks_and_separators_in_the_subject_and_forbidden_characters_are_refused() -> TestResult {
    let fixture = make_fixture(None, Some(smtp_settings(UNUSED_PORT, SmtpTls::Starttls, None)), TIMEOUT_MILLIS)?;
    let channel = mail_channel(RECIPIENT, None);
    let refused = |subject: &str, body: &str| {
        send_mail(
            &fixture.settings,
            &channel,
            &Message {
                subject: subject.to_string(),
                body: body.to_string(),
            },
        )
    };
    assert!(matches!(refused("a\r\nBcc: evil@example.com", "b"), Err(TransportError::MailText)));
    assert!(matches!(refused("a\nb", "b"), Err(TransportError::MailText)));
    assert!(matches!(refused("a\rb", "b"), Err(TransportError::MailText)));
    assert!(matches!(
        refused("x".repeat(MAX_MAIL_SUBJECT_BYTES + 1).as_str(), "b"),
        Err(TransportError::MailText)
    ));
    assert!(matches!(
        refused("a", "x".repeat(MAX_MAIL_BODY_BYTES + 1).as_str()),
        Err(TransportError::MailText)
    ));
    FORBIDDEN_CHARS.iter().try_for_each(|forbidden| {
        assert!(matches!(refused(&format!("a{forbidden}b"), "b"), Err(TransportError::ForbiddenChar)));
        assert!(matches!(refused("a", &format!("a{forbidden}b")), Err(TransportError::ForbiddenChar)));
        Ok::<(), io::Error>(())
    })?;
    Ok(())
}


#[test]
fn a_body_that_looks_like_the_end_of_data_cannot_smuggle_a_command() -> TestResult {
    let pki = test_pki()?;
    let relay = spawn_relay(pki.server_config.clone(), Mode::Implicit, None)?;
    let fixture = make_fixture(
        Some(&pki.ca_pem),
        Some(smtp_settings(relay.port, SmtpTls::Implicit, None)),
        TIMEOUT_MILLIS,
    )?;
    let hostile = Message {
        subject: "s".to_string(),
        body: "a\r\n.\r\nRCPT TO:<evil@example.com>\r\n.\r\n".to_string(),
    };
    send_one(&fixture.settings, &mail_channel(RECIPIENT, None), &hostile)?;
    let delivered = relay.done.join().map_err(|_panic| "relay panicked")??;
    let recipients = delivered.commands.iter().filter(|command| command.starts_with("RCPT")).count();
    assert_eq!(recipients, 1);
    assert!(!delivered.commands.iter().any(|command| command.contains("evil")));
    Ok(())
}


#[test]
fn a_server_that_never_answers_fails_on_the_injected_timeout() -> TestResult {
    let (release, wait) = signal();
    let silent = spawn_silent(wait)?;
    let fixture = make_fixture(None, Some(smtp_settings(silent.port, SmtpTls::Starttls, None)), SHORT_TIMEOUT_MILLIS)?;
    let outcome = send_one(&fixture.settings, &mail_channel(RECIPIENT, None), &message());
    assert!(matches!(outcome, Err(TransportError::Smtp(_))));
    release.send(())?;
    silent.held.join().map_err(|_panic| "silent server panicked")??;
    Ok(())
}


#[test]
fn a_server_that_drips_a_reply_forever_fails_on_the_total_deadline() -> TestResult {
    let (release, wait) = signal();
    let drip = spawn_drip(wait)?;
    let fixture = make_fixture(None, Some(smtp_settings(drip.port, SmtpTls::Starttls, None)), SHORT_TIMEOUT_MILLIS)?;
    let outcome = send_one(&fixture.settings, &mail_channel(RECIPIENT, None), &message());
    assert!(matches!(outcome, Err(TransportError::Deadline(_))));
    release.send(())?;
    drip.held.join().map_err(|_panic| "drip server panicked")??;
    Ok(())
}


#[test]
fn a_late_outcome_with_no_receiver_is_dropped() -> TestResult {
    let (sender, receiver) = signal();
    hand_over(&sender, Ok(()));
    assert!(matches!(receiver.recv()?, Ok(())));
    drop(receiver);
    hand_over(&sender, Ok(()));
    Ok(())
}


#[test]
fn the_server_reply_text_never_reaches_an_error_or_a_failure_reason() -> TestResult {
    let pki = test_pki()?;
    let relay = spawn_relay(pki.server_config.clone(), Mode::Implicit, Some(REPLY_TEXT))?;
    let fixture = make_fixture(
        Some(&pki.ca_pem),
        Some(smtp_settings(relay.port, SmtpTls::Implicit, Some("mailer"))),
        TIMEOUT_MILLIS,
    )?;
    let outcome = send_one(&fixture.settings, &mail_channel(RECIPIENT, Some("smtp-pass")), &message());
    let error = outcome.err().ok_or("the send succeeded")?;
    assert!(matches!(error, TransportError::Smtp(_)));
    assert!(!error.to_string().contains(REPLY_TEXT));
    assert!(!format!("{error:?}").contains(PASSWORD));
    assert!(!error.to_string().contains(PASSWORD));
    relay.done.join().map_err(|_panic| "relay panicked")??;
    let again = spawn_relay(pki.server_config.clone(), Mode::Implicit, Some(REPLY_TEXT))?;
    let second = make_fixture(
        Some(&pki.ca_pem),
        Some(smtp_settings(again.port, SmtpTls::Implicit, Some("mailer"))),
        TIMEOUT_MILLIS,
    )?;
    let mut engine_free_sender = |channel: &Channel, text: &Message| send_one(&second.settings, channel, text).map_err(|failure| failure.to_string());
    let failures = notify(&alert(), &[mail_channel(RECIPIENT, Some("smtp-pass"))], &mut engine_free_sender)?;
    assert_eq!(failures.len(), 1);
    assert_eq!(
        failures.iter().map(|failure| failure.reason.as_str()).collect::<Vec<_>>(),
        vec!["sender failed"]
    );
    again.done.join().map_err(|_panic| "relay panicked")??;
    Ok(())
}


#[test]
fn configuration_mistakes_fail_with_fixed_errors() -> TestResult {
    let channel = mail_channel(RECIPIENT, None);
    let without = make_fixture(None, None, TIMEOUT_MILLIS)?;
    assert!(matches!(
        send_one(&without.settings, &channel, &message()),
        Err(TransportError::SmtpNotConfigured)
    ));
    let no_username = make_fixture(None, Some(smtp_settings(UNUSED_PORT, SmtpTls::Starttls, None)), TIMEOUT_MILLIS)?;
    assert!(matches!(
        send_one(&no_username.settings, &mail_channel(RECIPIENT, Some("smtp-pass")), &message()),
        Err(TransportError::NoUsername)
    ));
    let with_username = make_fixture(None, Some(smtp_settings(UNUSED_PORT, SmtpTls::Starttls, Some("mailer"))), TIMEOUT_MILLIS)?;
    let foreign = Channel {
        tenant: "other".to_string(),
        ..mail_channel(RECIPIENT, Some("smtp-pass"))
    };
    assert!(matches!(
        send_one(&with_username.settings, &foreign, &message()),
        Err(TransportError::NoSecretsDir)
    ));
    assert!(matches!(
        send_one(
            &with_username.settings,
            &mail_channel(RECIPIENT, Some("../secrets/smtp-pass")),
            &message()
        ),
        Err(TransportError::SecretFile(_))
    ));
    Ok(())
}


#[test]
fn a_missing_or_unusable_ca_file_is_refused() -> TestResult {
    let mut missing = make_fixture(None, Some(smtp_settings(UNUSED_PORT, SmtpTls::Starttls, None)), TIMEOUT_MILLIS)?;
    missing.settings.ca_file = Some(missing.directory.path().join("absent.pem").display().to_string());
    assert!(matches!(
        send_one(&missing.settings, &mail_channel(RECIPIENT, None), &message()),
        Err(TransportError::CaFile(_))
    ));
    let garbage = make_fixture(
        Some("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"),
        Some(smtp_settings(UNUSED_PORT, SmtpTls::Starttls, None)),
        TIMEOUT_MILLIS,
    )?;
    assert!(matches!(
        send_one(&garbage.settings, &mail_channel(RECIPIENT, None), &message()),
        Err(TransportError::SmtpCertificate(_))
    ));
    Ok(())
}


const GOOD_SETTINGS: &str =
    "timeout_millis: 1000\nsecret_dirs: {}\nsmtp:\n  host: mail.example.com\n  port: 587\n  tls: starttls\n  from: alerts@example.com\n";


#[test]
fn smtp_settings_are_parsed_and_bounded() -> TestResult {
    let with_user = |username: &str| SmtpSettings {
        username: Some(username.to_string()),
        ..smtp_settings_of("mail.example.com", SUBMISSION_PORT, SmtpTls::Starttls)
    };
    assert!(validate_smtp(&with_user("mailer")).is_ok());
    assert!(validate_smtp(&with_user("a\u{1}b")).is_err());
    assert!(validate_smtp(&SmtpSettings {
        host: "a\tb".to_string(),
        ..with_user("mailer")
    })
    .is_err());
    let parsed = parse_settings(GOOD_SETTINGS, "s.yaml")?;
    assert_eq!(
        parsed.smtp,
        Some(smtp_settings_of("mail.example.com", SUBMISSION_PORT, SmtpTls::Starttls))
    );
    assert!(parse_settings(&format!("{GOOD_SETTINGS}  username: mailer\n").replace("starttls", "implicit"), "s.yaml").is_ok());
    assert!(parse_settings("timeout_millis: 1000\nsecret_dirs: {}\n", "s.yaml")?.smtp.is_none());
    let refused = |text: String| parse_settings(&text, "s.yaml").is_err();
    assert!(refused(GOOD_SETTINGS.replace("mail.example.com", "")));
    assert!(refused(GOOD_SETTINGS.replace("mail.example.com", &"h".repeat(MAX_HOST_LEN as usize + 1))));
    assert!(refused(GOOD_SETTINGS.replace("mail.example.com", "mail example")));
    assert!(refused(GOOD_SETTINGS.replace("587", "0")));
    assert!(refused(GOOD_SETTINGS.replace("587", "70000")));
    assert!(refused(GOOD_SETTINGS.replace("starttls", "plain")));
    assert!(refused(GOOD_SETTINGS.replace("alerts@example.com", "mailto:a@example.com")));
    assert!(refused(GOOD_SETTINGS.replace("alerts@example.com", "x>,<y@evil")));
    assert!(refused(format!("{GOOD_SETTINGS}  username: ''\n")));
    assert!(refused(format!("{GOOD_SETTINGS}  username: \"a\\u0001b\"\n")));
    assert!(refused(format!(
        "{GOOD_SETTINGS}  username: {}\n",
        "u".repeat(MAX_USERNAME_LEN as usize + 1)
    )));
    assert!(refused(format!("{GOOD_SETTINGS}  password: abc\n")));
    Ok(())
}


fn smtp_settings_of(host: &str, port: u16, tls: SmtpTls) -> SmtpSettings {
    SmtpSettings {
        host: host.to_string(),
        port,
        tls,
        from: SENDER.to_string(),
        username: None,
    }
}


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


#[test]
fn the_log_bridge_at_trace_never_sees_the_smtp_password() -> TestResult {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(captured.clone());
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .try_init()
        .map_err(|error| error.to_string())?;
    let Attempt { outcome, delivered } = attempt(Mode::Starttls, SmtpTls::Starttls, Some("smtp-pass"), Some("mailer"))?;
    outcome?;
    assert!(delivered.commands.contains(&PLAIN_AUTH.to_string()));
    let logs = String::from_utf8(captured.lock().map_err(|error| error.to_string())?.clone())?;
    let encoded = PLAIN_AUTH.trim_start_matches("AUTH PLAIN ");
    let spaced_hex: String = PASSWORD.bytes().map(|byte| format!("{byte:02x} ")).collect();
    assert!(!logs.contains(PASSWORD));
    assert!(!logs.contains(encoded));
    assert!(!logs.to_lowercase().contains(spaced_hex.trim_end()));
    assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    Ok(())
}
