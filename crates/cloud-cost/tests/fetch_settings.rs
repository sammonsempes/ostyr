use cloud_cost::fetch_error::FetchError;
use cloud_cost::fetch_model::{FetchSettings, FetchSource, DEFAULT_FETCH_TIMEOUT_MS, DEFAULT_MAX_OBJECTS};
use cloud_cost::fetch_settings::{
    bucket_ok, ensure, load_fetch_settings, parse_fetch_settings, prefix_ok, reference_ok, region_ok, segment_ok, tenant_bound, validate_settings,
    validate_source, MAX_BUCKET_BYTES, MAX_FETCH_TIMEOUT_MS, MAX_ID_BYTES, MAX_OBJECTS_LIMIT, MAX_PREFIX_BYTES, MAX_REFERENCE_BYTES,
    MAX_REGION_BYTES, MAX_SOURCES,
};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;


const DOCUMENT: &str =
    "secrets_dir: /etc/ostyr/secrets\nsources:\n  - id: main\n    tenant: acme\n    endpoint: https://s3.example.test\n    region: garage\n    \
bucket: billing\n    prefix: exports/\n    credentials: acme/s3.key\n";


const OBJECTS_OVER: usize = 1001;


const TIMEOUT_OVER: u64 = 600_001;


const SHORT_BUCKET: &str = "ab";


fn source() -> FetchSource {
    FetchSource {
        id: "main".to_owned(),
        tenant: "acme".to_owned(),
        endpoint: "https://s3.example.test".to_owned(),
        region: "garage".to_owned(),
        bucket: "billing".to_owned(),
        prefix: "exports/".to_owned(),
        credentials: "acme/s3.key".to_owned(),
        ca_file: None,
        max_objects_per_run: DEFAULT_MAX_OBJECTS,
        timeout_ms: DEFAULT_FETCH_TIMEOUT_MS,
    }
}


fn settings(sources: Vec<FetchSource>) -> FetchSettings {
    FetchSettings {
        secrets_dir: PathBuf::from(if cfg!(windows) { "C:\\secrets" } else { "/etc/ostyr/secrets" }),
        sources,
    }
}


fn refused_field(error: Result<(), FetchError>) -> Option<&'static str> {
    match error {
        Err(FetchError::Settings(field)) => Some(field),
        _ => None,
    }
}


fn with(change: impl FnOnce(&mut FetchSource)) -> FetchSource {
    let mut changed = source();
    change(&mut changed);
    changed
}


#[test]
fn a_document_parses_with_defaults() -> Result<(), Box<dyn Error>> {
    let parsed = parse_fetch_settings(DOCUMENT, "sources.yaml")?;
    assert_eq!(parsed.sources.len(), 1);
    let first = parsed.sources.first().ok_or("no source")?;
    assert_eq!(first.max_objects_per_run, DEFAULT_MAX_OBJECTS);
    assert_eq!(first.timeout_ms, DEFAULT_FETCH_TIMEOUT_MS);
    assert!(first.ca_file.is_none());
    Ok(())
}


#[test]
fn an_unknown_field_is_refused() -> Result<(), Box<dyn Error>> {
    assert!(parse_fetch_settings(&format!("{DOCUMENT}    surprise: 1\n"), "sources.yaml").is_err());
    Ok(())
}


#[test]
fn a_settings_file_is_loaded_and_a_missing_one_is_refused() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("sources.yaml");
    fs::write(&path, DOCUMENT)?;
    assert_eq!(load_fetch_settings(&path)?.sources.len(), 1);
    assert!(load_fetch_settings(&dir.path().join("missing.yaml")).is_err());
    Ok(())
}


#[test]
fn a_valid_source_and_valid_settings_pass() -> Result<(), Box<dyn Error>> {
    assert!(validate_source(&source()).is_ok());
    assert!(validate_settings(&settings(vec![source(), with(|other| other.id = "second".to_owned())])).is_ok());
    assert!(validate_source(&with(|other| other.prefix = String::new())).is_ok());
    assert!(validate_source(&with(|other| other.endpoint = "http://127.0.0.1:9000".to_owned())).is_ok());
    assert!(validate_source(&with(|other| other.ca_file = Some(std::env::temp_dir().join("ca.pem")))).is_ok());
    Ok(())
}


#[test]
fn every_field_is_checked() -> Result<(), Box<dyn Error>> {
    let long_id = "a".repeat(MAX_ID_BYTES + 1);
    let long_prefix = "a".repeat(MAX_PREFIX_BYTES + 1);
    let long_reference = format!("acme/{}", "a".repeat(MAX_REFERENCE_BYTES));
    let cases: Vec<(FetchSource, &str)> = vec![
        (with(|other| other.id = long_id.clone()), "id"),
        (with(|other| other.id = ".hidden".to_owned()), "id"),
        (with(|other| other.tenant = "-x".to_owned()), "tenant"),
        (with(|other| other.endpoint = "http://s3.example.test".to_owned()), "endpoint"),
        (with(|other| other.endpoint = "https://user@s3.example.test".to_owned()), "endpoint"),
        (with(|other| other.region = String::new()), "region"),
        (with(|other| other.bucket = SHORT_BUCKET.to_owned()), "bucket"),
        (with(|other| other.prefix = "a/../b".to_owned()), "prefix"),
        (with(|other| other.prefix = long_prefix.clone()), "prefix"),
        (with(|other| other.credentials = "other/s3.key".to_owned()), "credentials"),
        (with(|other| other.credentials = "acme/../other/s3.key".to_owned()), "credentials"),
        (with(|other| other.credentials = "acme".to_owned()), "credentials"),
        (with(|other| other.credentials = long_reference.clone()), "credentials"),
        (with(|other| other.ca_file = Some(PathBuf::from("ca.pem"))), "ca_file"),
        (with(|other| other.max_objects_per_run = 0), "max_objects_per_run"),
        (with(|other| other.max_objects_per_run = OBJECTS_OVER), "max_objects_per_run"),
        (with(|other| other.timeout_ms = 0), "timeout_ms"),
        (with(|other| other.timeout_ms = TIMEOUT_OVER), "timeout_ms"),
    ];
    cases
        .iter()
        .for_each(|(bad, field)| assert_eq!(refused_field(validate_source(bad)), Some(*field), "{field}"));
    assert_eq!(MAX_OBJECTS_LIMIT, OBJECTS_OVER - 1);
    assert_eq!(MAX_FETCH_TIMEOUT_MS, TIMEOUT_OVER - 1);
    Ok(())
}


#[test]
fn the_settings_are_checked_as_a_whole() -> Result<(), Box<dyn Error>> {
    let relative = FetchSettings {
        secrets_dir: PathBuf::from("secrets"),
        sources: vec![source()],
    };
    assert_eq!(refused_field(validate_settings(&relative)), Some("secrets_dir"));
    let many: Vec<FetchSource> = (0..=MAX_SOURCES).map(|index| with(|other| other.id = format!("s{index}"))).collect();
    assert_eq!(refused_field(validate_settings(&settings(many))), Some("sources"));
    assert_eq!(refused_field(validate_settings(&settings(vec![source(), source()]))), Some("id"));
    assert_eq!(
        refused_field(validate_settings(&settings(vec![
            source(),
            with(|other| {
                other.id = "second".to_owned();
                other.max_objects_per_run = 0;
            })
        ]))),
        Some("max_objects_per_run")
    );
    Ok(())
}


#[test]
fn ensure_names_the_field() -> Result<(), Box<dyn Error>> {
    assert!(ensure(true, "x").is_ok());
    assert_eq!(refused_field(ensure(false, "x")), Some("x"));
    Ok(())
}


#[test]
fn name_grammars_are_ascii_allowlists() -> Result<(), Box<dyn Error>> {
    assert!(segment_ok("a.b_c-d"));
    assert!(!segment_ok(""));
    assert!(!segment_ok("-a"));
    assert!(!segment_ok(".a"));
    assert!(!segment_ok("a b"));
    assert!(!segment_ok("a\u{3164}"));
    assert!(reference_ok("acme/keys/s3.key"));
    assert!(!reference_ok("acme//s3.key"));
    assert!(!reference_ok("acme/../s3.key"));
    assert!(!reference_ok(&"a".repeat(MAX_REFERENCE_BYTES + 1)));
    assert!(tenant_bound("acme/s3.key", "acme"));
    assert!(!tenant_bound("acme-evil/s3.key", "acme"));
    assert!(!tenant_bound("acme", "acme"));
    assert!(!tenant_bound("other/s3.key", "acme"));
    assert!(prefix_ok("exports/2024-01/"));
    assert!(prefix_ok(""));
    assert!(!prefix_ok("/exports"));
    assert!(!prefix_ok("exports/../x"));
    assert!(!prefix_ok("exports/%2e"));
    assert!(!prefix_ok("exports/a b"));
    assert!(!prefix_ok(&"a".repeat(MAX_PREFIX_BYTES + 1)));
    assert!(bucket_ok("billing-1.exports"));
    assert!(!bucket_ok("ab"));
    assert!(!bucket_ok(&"a".repeat(MAX_BUCKET_BYTES + 1)));
    assert!(!bucket_ok("Billing"));
    assert!(!bucket_ok("bill_ing"));
    assert!(!bucket_ok("-billing"));
    assert!(!bucket_ok(".billing"));
    assert!(region_ok("eu-west-1"));
    assert!(!region_ok(""));
    assert!(!region_ok(&"a".repeat(MAX_REGION_BYTES + 1)));
    assert!(!region_ok("eu west"));
    Ok(())
}
