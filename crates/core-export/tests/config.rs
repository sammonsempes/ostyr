#[path = "common/types.rs"]
mod types;


use core_export::config::{load_export, parse_export, SyslogTransport, DEFAULT_APP_NAME, DEFAULT_BATCH_SIZE, DEFAULT_BUFFER_MAX_BYTES};
use core_export::error::ExportError;
use std::fs;
use tempfile::tempdir;
use types::TestResult;


const FULL: &str = "syslog:
  address: siem.example:6514
  transport: udp
  hostname: srv1
  app_name: edr
  ca_file: /etc/ostyr/ca.pem
webhook:
  url: https://siem.example/hook
  token: vault://kv/siem-token
  batch_size: 10
  buffer_dir: /var/lib/ostyr/export
  buffer_max_bytes: 4096
  ca_file: /etc/ostyr/ca.pem
";


const MINIMAL: &str = "syslog:
  address: siem.example:6514
  hostname: srv1
webhook:
  url: https://siem.example/hook
  buffer_dir: /var/lib/ostyr/export
";


const BATCH_SIZE: usize = 10;


const BUFFER_MAX: u64 = 4096;


#[test]
fn a_full_configuration_is_parsed() -> TestResult {
    let config = parse_export(FULL, "export.yaml")?;
    let syslog = config.syslog.ok_or("syslog expected")?;
    let webhook = config.webhook.ok_or("webhook expected")?;
    assert_eq!((syslog.transport, syslog.app_name.as_str()), (SyslogTransport::Udp, "edr"));
    assert_eq!(webhook.token.map(|token| token.0), Some("vault://kv/siem-token".to_string()));
    assert_eq!((webhook.batch_size, webhook.buffer_max_bytes), (BATCH_SIZE, BUFFER_MAX));
    Ok(())
}


#[test]
fn defaults_are_tls_and_the_constants() -> TestResult {
    let config = parse_export(MINIMAL, "export.yaml")?;
    let syslog = config.syslog.ok_or("syslog expected")?;
    let webhook = config.webhook.ok_or("webhook expected")?;
    assert_eq!((syslog.transport, syslog.app_name.as_str()), (SyslogTransport::Tls, DEFAULT_APP_NAME));
    assert_eq!(
        (webhook.batch_size, webhook.buffer_max_bytes),
        (DEFAULT_BATCH_SIZE, DEFAULT_BUFFER_MAX_BYTES)
    );
    assert!(webhook.token.is_none());
    Ok(())
}


#[test]
fn a_plaintext_credential_is_rejected_without_echoing_it() -> TestResult {
    let text = "webhook:\n  url: https://x\n  token: hunter2\n  buffer_dir: /b\n";
    let error = parse_export(text, "export.yaml").err().ok_or("must fail")?;
    assert!(matches!(error, ExportError::Config(_)));
    assert!(error.to_string().contains("export.yaml:"));
    assert!(!error.to_string().contains("hunter2"));
    Ok(())
}


#[test]
fn unknown_fields_are_rejected() -> TestResult {
    assert!(parse_export("webhook:\n  url: x\n  buffer_dir: b\n  extra: 1\n", "export.yaml").is_err());
    Ok(())
}


#[test]
fn a_configuration_loads_from_a_file() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("export.yaml");
    fs::write(&path, MINIMAL)?;
    assert!(load_export(&path)?.syslog.is_some());
    assert!(matches!(load_export(&dir.path().join("absent.yaml")), Err(ExportError::Config(_))));
    Ok(())
}
