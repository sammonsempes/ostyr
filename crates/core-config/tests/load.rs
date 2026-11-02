mod common;


use common::fixture;
use core_config::error::ConfigError;
use core_config::load::{load_module, load_platform};
use core_config::model::ModuleConfig;
use core_config::parse::{parse_document, position_of, read_text, ROOT_FIELD_PATH};
use core_config::secret::SecretRef;
use std::error::Error;
use std::io::{self, Read};


pub struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected failure"))
    }
}


type TestResult = Result<(), Box<dyn Error>>;


type Failure = (String, u64, u64, String, String);


fn parse_failure(name: &str) -> Result<Failure, Box<dyn Error>> {
    match load_module(&fixture(name)) {
        Err(ConfigError::Parse {
            file,
            line,
            column,
            field_path,
            message,
            ..
        }) => Ok((file, line, column, field_path, message)),
        other => Err(format!("expected a parse error, got {other:?}").into()),
    }
}


#[test]
fn valid_module_loads() -> TestResult {
    let module = load_module(&fixture("module_ok.yaml"))?;
    assert_eq!(module.name, "siem");
    assert_eq!(module.listen.as_deref(), Some("0.0.0.0:8080"));
    assert_eq!(module.secrets.get("db"), Some(&SecretRef("vault://kv/siem/db".to_string())));
    assert_eq!(module.settings.get("region").map(String::as_str), Some("eu"));
    Ok(())
}


#[test]
fn valid_platform_loads() -> TestResult {
    let platform = load_platform(&fixture("platform_ok.yaml"))?;
    assert_eq!(platform.modules.len(), 2);
    assert_eq!(platform.authentication.map(|auth| auth.provider), Some("oidc".to_string()));
    assert_eq!(platform.event_bus.map(|bus| bus.endpoint), Some("nats://bus.internal:4222".to_string()));
    assert!(platform.storage.is_some_and(|storage| storage.credentials.is_some()));
    Ok(())
}


#[test]
fn module_without_platform_file_needs_nothing_else() -> TestResult {
    let module: ModuleConfig = parse_document("name: alone\nversion: 1.0.0\n", "inline")?;
    assert!(module.tenant.is_none());
    assert!(module.secrets.is_empty());
    Ok(())
}


#[test]
fn unknown_field_is_located() -> TestResult {
    let (file, line, column, field_path, message) = parse_failure("module_unknown_field.yaml")?;
    assert!(file.ends_with("module_unknown_field.yaml"));
    assert_eq!((line, column), (3, 1));
    assert_eq!(field_path, "listn");
    assert!(message.contains("unknown field `listn`"), "{message}");
    Ok(())
}


#[test]
fn wrong_type_is_located() -> TestResult {
    let (_, line, column, field_path, _) = parse_failure("module_wrong_type.yaml")?;
    assert_eq!((line, column), (4, 14));
    assert_eq!(field_path, "settings.retention");
    Ok(())
}


#[test]
fn missing_field_is_located() -> TestResult {
    let (_, line, _, _, message) = parse_failure("module_missing_field.yaml")?;
    assert_eq!(line, 1);
    assert!(message.contains("missing field `version`"), "{message}");
    Ok(())
}


#[test]
fn plaintext_secret_is_rejected_without_echo() -> TestResult {
    let (_, line, column, field_path, message) = parse_failure("module_plaintext_secret.yaml")?;
    assert_eq!((line, column), (4, 7));
    assert_eq!(field_path, "secrets.db");
    assert!(message.contains("never a value"), "{message}");
    assert!(!message.contains("hunter2"), "{message}");
    Ok(())
}


#[test]
fn syntax_error_is_located() -> TestResult {
    let (_, line, _, _, _) = parse_failure("module_syntax.yaml")?;
    assert!(line >= 1);
    Ok(())
}


#[test]
fn error_outside_the_deserializer_uses_root_marker() -> TestResult {
    match parse_document::<ModuleConfig>("a: 1\n---\nb: 2\n", "inline") {
        Err(ConfigError::Parse { field_path, .. }) => {
            assert!(!field_path.is_empty() || field_path == ROOT_FIELD_PATH);
            Ok(())
        }
        other => Err(format!("expected a parse error, got {other:?}").into()),
    }
}


#[test]
fn parse_error_display_names_file_line_column_and_path() -> TestResult {
    let error = load_module(&fixture("module_unknown_field.yaml")).err().ok_or("no error")?;
    let text = error.to_string();
    assert!(text.contains("module_unknown_field.yaml:3:1: at `listn`"), "{text}");
    assert!(error.source().is_some());
    Ok(())
}


#[test]
fn missing_file_is_an_io_error() -> TestResult {
    let error = load_module(&fixture("absent.yaml")).err().ok_or("no error")?;
    assert!(matches!(error, ConfigError::Io { .. }));
    assert!(error.to_string().contains("absent.yaml"));
    assert!(error.source().is_some());
    Ok(())
}


#[test]
fn failing_reader_is_an_io_error() -> TestResult {
    let error = read_text(&mut FailingReader, "injected.yaml").err().ok_or("no error")?;
    assert!(matches!(error, ConfigError::Io { ref file, .. } if file == "injected.yaml"));
    Ok(())
}


#[test]
fn missing_position_is_zero() -> TestResult {
    assert_eq!(position_of(None), (0, 0));
    Ok(())
}


#[test]
fn reader_text_is_returned() -> TestResult {
    assert_eq!(read_text(&mut "a: 1".as_bytes(), "inline")?, "a: 1");
    Ok(())
}


#[test]
fn parse_error_without_position_displays() -> TestResult {
    let source = serde_saphyr::from_str::<ModuleConfig>("[").err().ok_or("no error")?;
    let error = ConfigError::Parse {
        file: "f.yaml".to_string(),
        line: 0,
        column: 0,
        field_path: ".".to_string(),
        message: "m".to_string(),
        source: Box::new(source),
    };
    assert_eq!(error.to_string(), "f.yaml:0:0: at `.`: m");
    Ok(())
}
