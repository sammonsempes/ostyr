use serde_json::Value;
use siem_ingest::clickhouse::{
    classify_reply, classify_transport, exception_code, failure_class, flatten_event, insert_query, join_key, read_secret, render_rows,
    EXCEPTION_CODE_HEADER, MAX_PASSWORD_BYTES,
};
use siem_ingest::error::{InsertClass, InsertError, SettingsError};
use siem_ingest::model::Document;
use siem_ingest::settings::{settings_state, validate_settings, IngestSettings};
use std::error::Error;
use std::io::{self, Read};
use std::path::PathBuf;
use time::OffsetDateTime;
use ureq::http::{HeaderMap, HeaderValue, StatusCode};


const NESTED: &str = r#"{"@timestamp":"2026-01-01T00:00:00Z","event":{"category":["process"],"kind":"event"},"tenant":"evil","tenant_tier":"gold"}"#;


const PARSE_CODE: u32 = 27;


const SIZES_CODE: u32 = 190;


const OTHER_CODE: u32 = 1;


const TWO_ROWS: usize = 2;


const BAD_BYTE: u8 = 0xff;


const BAD_HEADER_BYTE: u8 = 0xfa;


pub struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read failed"))
    }
}


fn document(text: &str) -> Document {
    Document {
        payload: text.as_bytes().to_vec(),
        timestamp: OffsetDateTime::UNIX_EPOCH,
    }
}


fn invalid_field(settings: &IngestSettings) -> Option<&'static str> {
    match validate_settings(settings) {
        Err(SettingsError::Invalid { field, .. }) | Err(SettingsError::OutOfRange { field, .. }) => Some(field),
        _ => None,
    }
}


#[test]
fn flatten_turns_nested_objects_into_dotted_keys() -> Result<(), Box<dyn Error>> {
    let flat = flatten_event(NESTED.as_bytes())?;
    assert_eq!(flat.get("event.kind"), Some(&Value::String("event".to_owned())));
    assert!(flat.get("event.category").is_some_and(Value::is_array));
    assert!(flat.contains_key("@timestamp"));
    assert_eq!(join_key("", "a"), "a");
    assert_eq!(join_key("a", "b"), "a.b");
    assert!(flatten_event(b"{").is_err());
    Ok(())
}


#[test]
fn tenant_column_comes_from_the_subject_and_tier_never_from_the_body() -> Result<(), Box<dyn Error>> {
    let body = render_rows("tenant-a", &[document(NESTED), document(NESTED)])?;
    let text = String::from_utf8(body)?;
    let rows: Vec<Value> = text.lines().map(serde_json::from_str).collect::<Result<_, _>>()?;
    assert_eq!(rows.len(), TWO_ROWS);
    assert!(rows.iter().all(|row| row.get("tenant") == Some(&Value::String("tenant-a".to_owned()))));
    assert!(rows.iter().all(|row| row.get("tenant_tier").is_none()));
    assert!(render_rows("tenant-a", &[document("{")]).is_err());
    Ok(())
}


#[test]
fn secret_file_is_bounded_and_trimmed() -> Result<(), Box<dyn Error>> {
    assert_eq!(read_secret(&b"s3cret\r\n"[..])?, "s3cret");
    let exact = vec![b'a'; usize::try_from(MAX_PASSWORD_BYTES)?];
    assert_eq!(read_secret(&exact[..])?.len(), exact.len());
    let over = vec![b'a'; usize::try_from(MAX_PASSWORD_BYTES)? + 1];
    assert!(matches!(read_secret(&over[..]), Err(InsertError::CredentialsTooLarge)));
    assert!(matches!(read_secret(FailingReader), Err(InsertError::Credentials(_))));
    assert!(matches!(read_secret(&[BAD_BYTE][..]), Err(InsertError::Credentials(_))));
    Ok(())
}


#[test]
fn replies_map_to_fixed_classes() -> Result<(), Box<dyn Error>> {
    assert_eq!(classify_reply(StatusCode::OK, None), None);
    assert_eq!(classify_reply(StatusCode::BAD_REQUEST, Some(PARSE_CODE)), Some(InsertClass::ParseError));
    assert_eq!(
        failure_class(StatusCode::INTERNAL_SERVER_ERROR, Some(PARSE_CODE)),
        InsertClass::ParseError
    );
    assert_eq!(
        failure_class(StatusCode::INTERNAL_SERVER_ERROR, Some(OTHER_CODE)),
        InsertClass::Unavailable
    );
    assert_eq!(
        failure_class(StatusCode::INTERNAL_SERVER_ERROR, Some(SIZES_CODE)),
        InsertClass::ParseError
    );
    assert_eq!(failure_class(StatusCode::UNAUTHORIZED, None), InsertClass::Unauthorized);
    assert_eq!(failure_class(StatusCode::FORBIDDEN, None), InsertClass::Unauthorized);
    assert_eq!(failure_class(StatusCode::REQUEST_TIMEOUT, None), InsertClass::Timeout);
    assert_eq!(failure_class(StatusCode::GATEWAY_TIMEOUT, None), InsertClass::Timeout);
    assert_eq!(failure_class(StatusCode::TOO_MANY_REQUESTS, None), InsertClass::Unavailable);
    assert_eq!(failure_class(StatusCode::NOT_FOUND, None), InsertClass::Rejected);
    Ok(())
}


#[test]
fn transport_errors_map_to_timeout_or_unavailable() -> Result<(), Box<dyn Error>> {
    assert_eq!(classify_transport(&ureq::Error::Timeout(ureq::Timeout::Global)), InsertClass::Timeout);
    assert_eq!(classify_transport(&ureq::Error::ConnectionFailed), InsertClass::Unavailable);
    Ok(())
}


#[test]
fn exception_code_is_read_from_the_header_only_when_numeric() -> Result<(), Box<dyn Error>> {
    let mut headers = HeaderMap::new();
    assert_eq!(exception_code(&headers), None);
    headers.insert(EXCEPTION_CODE_HEADER, HeaderValue::from_static("27"));
    assert_eq!(exception_code(&headers), Some(PARSE_CODE));
    headers.insert(EXCEPTION_CODE_HEADER, HeaderValue::from_static("soon"));
    assert_eq!(exception_code(&headers), None);
    headers.insert(EXCEPTION_CODE_HEADER, HeaderValue::from_bytes(&[BAD_HEADER_BYTE])?);
    assert_eq!(exception_code(&headers), None);
    Ok(())
}


#[test]
fn query_names_the_validated_table() -> Result<(), Box<dyn Error>> {
    assert_eq!(insert_query(&IngestSettings::default()), "INSERT INTO `events` FORMAT JSONEachRow");
    Ok(())
}


#[test]
fn connection_settings_are_validated() -> Result<(), Box<dyn Error>> {
    assert!(validate_settings(&IngestSettings::default()).is_ok());
    let loopback = IngestSettings {
        clickhouse_url: "http://127.0.0.1:8123".to_owned(),
        ..IngestSettings::default()
    };
    assert_eq!(invalid_field(&loopback), None);
    let localhost = IngestSettings {
        clickhouse_url: "http://localhost:8123".to_owned(),
        ..IngestSettings::default()
    };
    assert_eq!(invalid_field(&localhost), None);
    let plain = IngestSettings {
        clickhouse_url: "http://db.example:8123".to_owned(),
        ..IngestSettings::default()
    };
    assert_eq!(invalid_field(&plain), Some("clickhouse_url"));
    let table = IngestSettings {
        clickhouse_table: "events; DROP".to_owned(),
        ..IngestSettings::default()
    };
    assert_eq!(invalid_field(&table), Some("clickhouse_table"));
    let database = IngestSettings {
        clickhouse_database: String::new(),
        ..IngestSettings::default()
    };
    assert_eq!(invalid_field(&database), Some("clickhouse_database"));
    let user = IngestSettings {
        clickhouse_user: String::new(),
        ..IngestSettings::default()
    };
    assert_eq!(invalid_field(&user), Some("clickhouse_user"));
    let password = IngestSettings {
        clickhouse_password_file: PathBuf::new(),
        ..IngestSettings::default()
    };
    assert_eq!(invalid_field(&password), Some("clickhouse_password_file"));
    let timeout = IngestSettings {
        insert_timeout_ms: 0,
        ..IngestSettings::default()
    };
    assert_eq!(invalid_field(&timeout), Some("insert_timeout_ms"));
    let tenant = IngestSettings {
        max_tenant_bytes: 0,
        ..IngestSettings::default()
    };
    assert_eq!(invalid_field(&tenant), Some("max_tenant_bytes"));
    Ok(())
}


#[test]
fn credentials_are_a_path_in_the_state_never_inline() -> Result<(), Box<dyn Error>> {
    let state = settings_state(&IngestSettings::default());
    assert!(state.contains_key("clickhouse_password_file"));
    assert!(!state.contains_key("clickhouse_password"));
    Ok(())
}
