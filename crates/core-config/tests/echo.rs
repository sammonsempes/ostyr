#[path = "common/types.rs"]
mod types;


use core_config::error::ConfigError;
use core_config::model::ModuleConfig;
use core_config::parse::{describe_error, describe_path, parse_document};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::error::Error;
use types::TestResult;


const MARKER: &str = "/srv/canary-9";


const UNKNOWN_FIELD_LINE: u64 = 3;


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nested {
    pub inner: Inner,
    pub count: Option<u32>,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inner {
    pub flag: bool,
}


#[derive(Debug, Deserialize)]
pub enum Kind {
    Alpha,
}


#[derive(Debug, Deserialize)]
pub struct WithKind {
    pub kind: Kind,
}


#[derive(Debug, Deserialize)]
pub struct WithFloat {
    pub ratio: f64,
}


#[derive(Debug, Deserialize)]
pub struct WithItems {
    pub items: Vec<Inner>,
}


#[derive(Debug, Deserialize)]
pub struct WithMap {
    pub entries: BTreeMap<String, String>,
}


fn full_text(error: &ConfigError) -> String {
    let first: &dyn Error = error;
    std::iter::successors(Some(first), |current: &&dyn Error| (*current).source())
        .map(|current| format!("{current} {current:?}"))
        .collect::<Vec<_>>()
        .join(" ")
}


fn failure<Document: serde::de::DeserializeOwned>(text: &str) -> Result<ConfigError, Box<dyn Error>> {
    parse_document::<Document>(text, "f.yaml")
        .err()
        .ok_or_else(|| "expected a parse error".into())
}


#[test]
fn unknown_field_name_is_never_echoed() -> TestResult {
    let error = failure::<ModuleConfig>(&format!("name: a\nversion: 1.0.0\n{MARKER}: 1\n"))?;
    assert!(!full_text(&error).contains("canary"), "{error}");
    assert!(error.to_string().contains("unknown field, expected one of"), "{error}");
    assert!(matches!(error, ConfigError::Parse { ref field_path, line: UNKNOWN_FIELD_LINE, column: 1, .. } if field_path == "."));
    Ok(())
}


#[test]
fn nested_unknown_field_keeps_parent_path() -> TestResult {
    let error = failure::<Nested>(&format!("inner:\n  flag: true\n  {MARKER}: 1\n"))?;
    assert!(!full_text(&error).contains("canary"), "{error}");
    assert!(
        matches!(&error, ConfigError::Parse { field_path, .. } if field_path == "inner"),
        "{error}"
    );
    Ok(())
}


#[test]
fn type_mismatch_value_is_never_echoed() -> TestResult {
    let error = failure::<Nested>(&format!("inner:\n  flag: true\ncount: {MARKER}\n"))?;
    assert!(!full_text(&error).contains("canary"), "{error}");
    assert!(error.to_string().contains("invalid u32"), "{error}");
    assert!(
        matches!(&error, ConfigError::Parse { field_path, .. } if field_path == "count"),
        "{error}"
    );
    Ok(())
}


#[test]
fn unknown_variant_is_never_echoed() -> TestResult {
    let error = failure::<WithKind>(&format!("kind: {MARKER}\n"))?;
    assert!(!full_text(&error).contains("canary"), "{error}");
    assert!(error.to_string().contains("unknown variant, expected one of `Alpha`"), "{error}");
    Ok(())
}


#[test]
fn float_value_is_never_echoed() -> TestResult {
    let error = failure::<WithFloat>(&format!("ratio: {MARKER}\n"))?;
    assert!(!full_text(&error).contains("canary"), "{error}");
    Ok(())
}


#[test]
fn duplicate_key_is_never_echoed() -> TestResult {
    let error = failure::<WithMap>(&format!("entries:\n  {MARKER}: a\n  {MARKER}: b\n"))?;
    assert!(!full_text(&error).contains("canary"), "{error}");
    assert!(error.to_string().contains("duplicate mapping key"), "{error}");
    Ok(())
}


#[test]
fn bad_tag_is_never_echoed() -> TestResult {
    let on_enum = failure::<WithKind>("kind: !canary9 Alpha\n")?;
    assert!(!full_text(&on_enum).contains("canary"), "{on_enum}");
    Ok(())
}


#[test]
fn serde_invalid_type_is_never_echoed() -> TestResult {
    let error = failure::<Nested>(&format!("inner: {MARKER}\n"))?;
    assert!(!full_text(&error).contains("canary"), "{error}");
    let sequence = failure::<Nested>(&format!("inner:\n  flag: [{MARKER}]\n"))?;
    assert!(!full_text(&sequence).contains("canary"), "{sequence}");
    assert!(sequence.to_string().contains("expected"), "{sequence}");
    Ok(())
}


#[test]
fn describe_error_drops_document_text_from_every_variant() -> TestResult {
    let location = serde_saphyr::Location::UNKNOWN;
    let leaking = [
        serde_saphyr::Error::SerdeInvalidType {
            unexpected: MARKER.to_string(),
            expected: "a number".to_string(),
            location,
        },
        serde_saphyr::Error::SerdeInvalidValue {
            unexpected: MARKER.to_string(),
            expected: "a number".to_string(),
            location,
        },
        serde_saphyr::Error::DuplicateMappingKey {
            key: Some(MARKER.to_string()),
            location,
        },
        serde_saphyr::Error::TaggedEnumMismatch {
            tagged: MARKER.to_string(),
            target: "Kind",
            location,
        },
        serde_saphyr::Error::SerdeVariantId {
            msg: MARKER.to_string(),
            location,
        },
        serde_saphyr::Error::NonFiniteFloat {
            value: MARKER.to_string(),
            location,
        },
        serde_saphyr::Error::QuotingRequired {
            value: MARKER.to_string(),
            location,
        },
    ];
    let texts = leaking.iter().map(describe_error).collect::<Vec<_>>();
    assert!(texts.iter().all(|text| !text.contains("canary") && !text.is_empty()), "{texts:?}");
    assert_eq!(texts.len(), leaking.len());
    Ok(())
}


#[test]
fn describe_error_keeps_other_variants() -> TestResult {
    let syntax = serde_saphyr::from_str::<Nested>("[").err().ok_or("no error")?;
    assert_eq!(describe_error(&syntax), syntax.to_string());
    Ok(())
}


#[test]
fn describe_path_handles_root_and_sequences() -> TestResult {
    let nested = serde_path_to_error::deserialize::<_, WithItems>(serde_json::json!({ "items": [{ "flag": 1 }] }))
        .err()
        .ok_or("no error")?;
    assert_eq!(describe_path(nested.path(), false), "items[0].flag");
    assert_eq!(describe_path(nested.path(), true), "items[0]");
    let root = serde_path_to_error::deserialize::<_, Nested>(serde_json::json!(1))
        .err()
        .ok_or("no error")?;
    assert_eq!(describe_path(root.path(), true), ".");
    Ok(())
}
