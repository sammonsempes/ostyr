use crate::types::TestResult;
use core_audit::log::open_file_log;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_config::reload::{reload_entry, MAX_VALUE_CHARS};
use status_page::app::{file_audit, reload_context, run_app, sample_inputs, AppFile, AUDIT_DECLARED_KEYS};
use status_page::model::{ComponentConfig, ComponentState, PageConfig};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;


const PAGE: &str = "id: main
tenant: acme
title: Acme status
components:
  - name: Website
    service: svc-web
  - name: API
    service: svc-api
";


fn files(dir: &Path, page: &str, settings: &str) -> Result<AppFile, std::io::Error> {
    fs::write(dir.join("page.yaml"), page)?;
    fs::write(dir.join("settings.yaml"), settings)?;
    Ok(AppFile {
        page_file: dir.join("page.yaml"),
        settings_file: dir.join("settings.yaml"),
        audit_file: dir.join("audit.log"),
    })
}


#[tokio::test]
async fn the_example_serves_the_sample_page_until_shutdown() -> TestResult {
    let dir = tempdir()?;
    let file = files(dir.path(), PAGE, "burst: 30\n")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = oneshot::channel::<()>();
    let running = tokio::spawn(run_app(
        file,
        listener,
        Box::pin(async {
            stopped.await.unwrap_or_default();
        }),
    ));
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(b"GET /status.json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    let answer = String::from_utf8(bytes)?;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.contains("Acme status") && answer.contains("Sample incident"));
    stop.send(()).map_err(|()| "server gone")?;
    running.await??;
    Ok(())
}


#[tokio::test]
async fn the_example_refuses_bad_files() -> TestResult {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let bad_page = files(dir.path(), "id: x\n", "burst: 30\n")?;
    assert!(run_app(bad_page, listener, Box::pin(std::future::ready(()))).await.is_err());
    let other = TcpListener::bind("127.0.0.1:0").await?;
    let bad_settings = files(dir.path(), PAGE, "burst: 0\n")?;
    assert!(run_app(bad_settings, other, Box::pin(std::future::ready(()))).await.is_err());
    Ok(())
}


#[test]
fn sample_inputs_degrade_the_first_component_only() -> TestResult {
    let config = PageConfig {
        id: "main".to_owned(),
        tenant: "acme".to_owned(),
        title: "t".to_owned(),
        checks: Vec::new(),
        components: vec![
            ComponentConfig {
                name: "A".to_owned(),
                service: "a".to_owned(),
                objective_ppm: None,
                rule: None,
            },
            ComponentConfig {
                name: "B".to_owned(),
                service: "b".to_owned(),
                objective_ppm: None,
                rule: None,
            },
        ],
    };
    let (states, incidents) = sample_inputs(&config);
    assert_eq!(
        states.iter().map(|state| state.state).collect::<Vec<_>>(),
        [ComponentState::Degraded, ComponentState::Operational]
    );
    assert_eq!(incidents.len(), 1);
    let empty = PageConfig {
        components: Vec::new(),
        ..config
    };
    assert!(sample_inputs(&empty).1.is_empty());
    Ok(())
}


#[test]
fn the_audit_function_appends_to_the_log() -> TestResult {
    let dir = tempdir()?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let entry = NewEntry {
        timestamp: time::OffsetDateTime::UNIX_EPOCH,
        actor: Actor {
            kind: ActorKind::System,
            id: "test".to_owned(),
        },
        tenant: "acme".to_owned(),
        module: "status_page".to_owned(),
        action: "config.reload".to_owned(),
        target: "settings.yaml".to_owned(),
        outcome: Outcome::Success,
        request_id: "r".to_owned(),
        justification: None,
        parameters: Default::default(),
    };
    assert!(file_audit(&log)(entry).is_ok());
    Ok(())
}


const OMITTED_CHARS: usize = 10;


fn logged_text(first_value: &str, extra: Option<(&str, &str)>) -> Result<String, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    let log = Arc::new(open_file_log(&path)?);
    let file = AppFile {
        page_file: "page.yaml".into(),
        settings_file: "settings.yaml".into(),
        audit_file: path.clone(),
    };
    let [first, second, third, fourth, fifth] = AUDIT_DECLARED_KEYS;
    let parameters = [(first, first_value.to_owned()), (second, "d".to_owned())];
    let mut entry = reload_entry(&reload_context(&file, "acme"), Outcome::Success, parameters);
    [third, fourth, fifth].iter().for_each(|key| {
        entry.parameters.insert((*key).to_owned(), "other".to_owned());
    });
    if let Some((key, value)) = extra {
        entry.parameters.insert(key.to_owned(), value.to_owned());
    }
    file_audit(&log)(entry)?;
    Ok(fs::read_to_string(path)?)
}


#[test]
fn an_undeclared_parameter_is_redacted() -> TestResult {
    let text = logged_text("ok", Some(("password", "hunter2-secret")))?;
    assert!(text.contains("[REDACTED]"));
    assert!(!text.contains("hunter2-secret"));
    Ok(())
}


#[test]
fn each_declared_key_keeps_its_value() -> TestResult {
    let text = logged_text("kept-value", None)?;
    assert!(text.contains("kept-value"));
    assert!(!text.contains("[REDACTED]"));
    Ok(())
}


#[test]
fn an_over_long_value_carries_the_cut_marker() -> TestResult {
    let long = "x".repeat(MAX_VALUE_CHARS + OMITTED_CHARS);
    let text = logged_text(&long, None)?;
    assert!(text.contains(&format!("truncated, {OMITTED_CHARS} characters omitted")));
    Ok(())
}
