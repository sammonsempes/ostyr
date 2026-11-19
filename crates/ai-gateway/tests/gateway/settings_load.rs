use crate::common::{deps, scripted, settings, TIMEOUT};
use crate::numbers::STATE_FIELDS;
use crate::types::TestResult;
use ai_gateway::chat::chat;
use ai_gateway::error::AiError;
use ai_gateway::limits::{
    MAX_MODEL_CHARS, MAX_REQUEST_BYTES_CEILING, MAX_RESPONSE_BYTES_CEILING, MAX_TIMEOUT_SECONDS, MAX_TOKENS_CEILING, MIN_RESPONSE_BYTES,
};
use ai_gateway::settings::{ai_state, endpoint_url, open_ai, validate_ai, AiSettings, OpenError};
use core_audit::log::{append, genesis_log};
use core_config::reload::{current_config, reload, ReloadContext, ReloadEngine, ReloadOutcome};
use serde_json::json;
use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;


fn field(settings_used: &AiSettings) -> Option<&'static str> {
    match validate_ai(settings_used) {
        Err(AiError::Settings { field }) => Some(field),
        _ => None,
    }
}


fn with_url(url: &str) -> AiSettings {
    AiSettings {
        base_url: url.to_owned(),
        ..settings("ok")
    }
}


#[test]
fn only_https_or_a_literal_loopback_address_is_a_base_url() -> TestResult {
    [
        "https://model.example/api",
        "https://10.0.0.5",
        "http://127.0.0.1:8080",
        "http://127.9.9.9/v1",
        "http://[::1]:11434",
    ]
    .into_iter()
    .for_each(|url| assert_eq!(field(&with_url(url)), None, "{url}"));
    [
        "http://10.0.0.5",
        "http://localhost.evil.example",
        "http://localhost",
        "http://[::2]",
        "ftp://127.0.0.1",
        "https://user:pass@model.example",
        "https://user@model.example",
        "https://:secret@model.example",
        "https://model.example/?key=1",
        "https://model.example/#frag",
        "not a url",
        "file:///etc/passwd",
        "https://model.example\\v1",
        "https://model.example/\tv1",
        "https://model.example/v1\r\n",
        "https://model.example/a\nb",
        " https://model.example",
        "https://MODEL.example",
    ]
    .into_iter()
    .for_each(|url| assert_eq!(field(&with_url(url)), Some("base_url"), "{url}"));
    Ok(())
}


#[test]
fn the_model_is_an_ascii_allowlist() -> TestResult {
    let with_model = |model: &str| AiSettings {
        model: model.to_owned(),
        ..settings("ok")
    };
    ["gpt-4o", "llama3.1:8b", "org/model_v1.2", "a"]
        .into_iter()
        .for_each(|model| assert_eq!(field(&with_model(model)), None, "{model}"));
    let long = "a".repeat(MAX_MODEL_CHARS + 1);
    ["", "-x", "a b", "a\u{3164}b", "caf\u{e9}", "a;b", long.as_str()]
        .into_iter()
        .for_each(|model| assert_eq!(field(&with_model(model)), Some("model"), "{model:?}"));
    assert_eq!(field(&with_model(&"a".repeat(MAX_MODEL_CHARS))), None);
    Ok(())
}


#[test]
fn every_numeric_bound_names_its_field() -> TestResult {
    let base = settings("ok");
    let change = |edit: fn(&mut AiSettings)| {
        let mut copy = base.clone();
        edit(&mut copy);
        field(&copy)
    };
    assert_eq!(change(|used| used.timeout_seconds = 0), Some("timeout_seconds"));
    assert_eq!(change(|used| used.timeout_seconds = MAX_TIMEOUT_SECONDS + 1), Some("timeout_seconds"));
    assert_eq!(change(|used| used.timeout_seconds = MAX_TIMEOUT_SECONDS), None);
    assert_eq!(change(|used| used.max_tokens = 0), Some("max_tokens"));
    assert_eq!(change(|used| used.max_tokens = MAX_TOKENS_CEILING + 1), Some("max_tokens"));
    assert_eq!(change(|used| used.max_tokens = MAX_TOKENS_CEILING), None);
    assert_eq!(
        change(|used| used.max_response_bytes = MIN_RESPONSE_BYTES - 1),
        Some("max_response_bytes")
    );
    assert_eq!(
        change(|used| used.max_response_bytes = MAX_RESPONSE_BYTES_CEILING + 1),
        Some("max_response_bytes")
    );
    assert_eq!(change(|used| used.max_response_bytes = MAX_RESPONSE_BYTES_CEILING), None);
    assert_eq!(change(|used| used.max_request_bytes = 0), Some("max_request_bytes"));
    assert_eq!(
        change(|used| used.max_request_bytes = MAX_REQUEST_BYTES_CEILING + 1),
        Some("max_request_bytes")
    );
    assert_eq!(change(|used| used.max_request_bytes = MAX_REQUEST_BYTES_CEILING), None);
    Ok(())
}


#[test]
fn the_endpoint_and_the_state_follow_the_settings() -> TestResult {
    assert_eq!(
        endpoint_url(&with_url("https://model.example/api/")),
        "https://model.example/api/v1/chat/completions"
    );
    let state = ai_state(&settings("ok"));
    assert_eq!(state.get("model").map(String::as_str), Some("test-model:1"));
    assert_eq!(state.len(), STATE_FIELDS);
    Ok(())
}


const YAML: &str = "base_url: https://model.example/{script}\nmodel: {model}\ntimeout_seconds: {timeout}\nmax_tokens: 100\n";


fn yaml(script: &str, model: &str, timeout: u64) -> String {
    YAML.replace("{script}", script)
        .replace("{model}", model)
        .replace("{timeout}", &timeout.to_string())
}


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "ai".to_owned(),
        tenant: "example".to_owned(),
        module: "ai-gateway".to_owned(),
        target: "ai.yaml".to_owned(),
        request_id: "ai-reload".to_owned(),
    }
}


fn open_file(path: &Path) -> Result<ReloadEngine<AiSettings>, OpenError> {
    let log = genesis_log(io::sink());
    open_ai(path.to_owned(), Box::new(move |entry| append(&log, entry)), context())
}


fn open_text(directory: &Path, text: &str) -> Result<ReloadEngine<AiSettings>, Box<dyn Error>> {
    let path = directory.join("ai.yaml");
    fs::write(&path, text)?;
    Ok(open_file(&path)?)
}


#[test]
fn the_first_settings_must_parse_and_validate() -> TestResult {
    let directory = tempfile::tempdir()?;
    assert!(open_text(directory.path(), &yaml("ok", "m", TIMEOUT)).is_ok());
    let refused = open_text(directory.path(), &yaml("ok", "m", 0)).err().ok_or("accepted")?;
    assert!(matches!(
        refused.downcast_ref::<OpenError>(),
        Some(OpenError::Invalid(AiError::Settings { field: "timeout_seconds" }))
    ));
    let unknown = open_text(directory.path(), &format!("{}extra: 1\n", yaml("ok", "m", TIMEOUT)))
        .err()
        .ok_or("accepted")?;
    assert!(matches!(unknown.downcast_ref::<OpenError>(), Some(OpenError::Config(_))));
    assert!(matches!(open_file(&directory.path().join("absent.yaml")), Err(OpenError::Config(_))));
    Ok(())
}


#[test]
fn a_live_swap_between_two_calls_gives_each_call_one_snapshot() -> TestResult {
    let directory = tempfile::tempdir()?;
    let engine = open_text(directory.path(), &yaml("echo", "model-one", TIMEOUT))?;
    let before = current_config(&engine);
    let first = chat(&before, "i", &json!({"a": 1}), &deps(scripted))?;
    fs::write(directory.path().join("ai.yaml"), yaml("echo", "model-two", TIMEOUT))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    let after = current_config(&engine);
    let second = chat(&after, "i", &json!({"a": 1}), &deps(scripted))?;
    assert!(first.content.contains("\"model\":\"model-one\""));
    assert!(second.content.contains("\"model\":\"model-two\""));
    assert_eq!(before.model, "model-one");
    fs::write(directory.path().join("ai.yaml"), yaml("echo", "model-three", 0))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).model, "model-two");
    Ok(())
}
