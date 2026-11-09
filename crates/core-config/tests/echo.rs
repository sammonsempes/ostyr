#[path = "common/types.rs"]
mod types;


use core_config::error::ConfigError;
use core_config::model::ModuleConfig;
use core_config::parse::{
    bounded_message, describe_error, describe_path, parse_document, shown_key, strip_serde_names, MAX_KEY_BYTES, MAX_MESSAGE_CHARS,
};
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
    Beta(u32),
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


#[derive(Debug, Deserialize)]
pub struct AliasHolder {
    pub base: serde_json::Value,
    pub r#use: Nested,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flattened {
    pub outer: u32,
    #[serde(flatten)]
    pub rest: Rest,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rest {
    pub extra: Option<u32>,
}


#[derive(Debug, Deserialize)]
#[serde(try_from = "String")]
pub struct Checked {
    pub text: String,
}


impl TryFrom<String> for Checked {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Err(format!("invalid checked field, length {}", text.len()))
    }
}


#[derive(Debug, Deserialize)]
pub struct WithChecked {
    pub checked: Checked,
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
fn describe_error_keeps_only_proven_safe_variants() -> TestResult {
    let location = serde_saphyr::Location::UNKNOWN;
    let syntax = serde_saphyr::from_str::<Nested>("[").err().ok_or("no error")?;
    assert!(!describe_error(&syntax).is_empty());
    let eof = serde_saphyr::Error::Eof { location };
    assert_eq!(describe_error(&eof), eof.to_string());
    let classes = [
        (
            serde_saphyr::Error::Message {
                msg: MARKER.to_string(),
                location,
            },
            MARKER,
        ),
        (
            serde_saphyr::Error::InvalidOptions {
                msg: MARKER.to_string(),
                location,
            },
            "invalid document",
        ),
        (
            serde_saphyr::Error::HookError {
                msg: MARKER.to_string(),
                location,
            },
            "validation hook error",
        ),
        (
            serde_saphyr::Error::CyclicInclude {
                id: MARKER.to_string(),
                stack: vec![MARKER.to_string()],
                location,
            },
            "include error",
        ),
        (
            serde_saphyr::Error::UnresolvedProperty {
                name: MARKER.to_string(),
                location,
            },
            "property error",
        ),
        (
            serde_saphyr::Error::UnsupportedTag {
                tag: MARKER.to_string(),
                location,
            },
            "unsupported tag",
        ),
    ];
    classes.iter().for_each(|(error, class)| assert_eq!(describe_error(error), *class));
    Ok(())
}


#[test]
fn alias_and_snippet_wrappers_are_unwrapped() -> TestResult {
    let location = serde_saphyr::Location::UNKNOWN;
    let inner = serde_saphyr::Error::SerdeUnknownField {
        field: MARKER.to_string(),
        expected: vec!["flag"],
        location,
    };
    let wrapped = serde_saphyr::Error::WithSnippet {
        regions: Vec::new(),
        crop_radius: 0,
        error: Box::new(inner),
    };
    assert_eq!(describe_error(&wrapped), "unknown field, expected one of `flag`");
    Ok(())
}


#[test]
fn alias_replayed_unknown_key_is_never_echoed() -> TestResult {
    let text = format!("base: &anchor\n  flag: true\n  {MARKER}: 1\nuse:\n  inner: *anchor\n");
    let error = failure::<AliasHolder>(&text)?;
    assert!(!full_text(&error).contains("canary"), "{error}");
    assert!(error.to_string().contains("unknown field"), "{error}");
    Ok(())
}


#[test]
fn map_keys_never_reach_the_field_path() -> TestResult {
    let secrets = failure::<ModuleConfig>(&format!("name: a\nversion: 1.0.0\nsecrets:\n  {MARKER}: plain\n"))?;
    assert!(!full_text(&secrets).contains("canary"), "{secrets}");
    assert!(
        matches!(&secrets, ConfigError::Parse { field_path, .. } if field_path == "secrets.<key>"),
        "{secrets}"
    );
    let settings = failure::<ModuleConfig>(&format!("name: a\nversion: 1.0.0\nsettings:\n  {MARKER}: [\n"))?;
    assert!(!full_text(&settings).contains("canary"), "{settings}");
    let typed = failure::<WithMap>(&format!("entries:\n  {MARKER}: [1]\n"))?;
    assert!(!full_text(&typed).contains("canary"), "{typed}");
    assert!(
        matches!(&typed, ConfigError::Parse { field_path, .. } if field_path == "entries.<key>"),
        "{typed}"
    );
    Ok(())
}


#[test]
fn flatten_with_deny_unknown_fields_is_never_echoed() -> TestResult {
    let error = failure::<Flattened>(&format!("outer: 1\n{MARKER}: 1\n"))?;
    assert!(!full_text(&error).contains("canary"), "{error}");
    Ok(())
}


#[test]
fn try_from_error_is_never_echoed() -> TestResult {
    let error = failure::<Checked>(&format!("{MARKER}\n"))?;
    assert!(!full_text(&error).contains("canary"), "{error}");
    assert!(error.to_string().contains("invalid checked field"), "{error}");
    let custom = failure::<WithChecked>(&format!("checked: {MARKER}\n"))?;
    assert!(!full_text(&custom).contains("canary"), "{custom}");
    assert!(
        matches!(&custom, ConfigError::Parse { field_path, .. } if field_path == "checked"),
        "{custom}"
    );
    Ok(())
}


#[test]
fn shown_key_keeps_identifiers_only() -> TestResult {
    assert_eq!(shown_key("db_2"), "db_2");
    assert_eq!(shown_key(MARKER), "<key>");
    assert_eq!(shown_key(""), "<key>");
    assert_eq!(shown_key("Db"), "<key>");
    assert_eq!(shown_key(&"a".repeat(MAX_KEY_BYTES)), "a".repeat(MAX_KEY_BYTES));
    assert_eq!(shown_key(&"a".repeat(MAX_KEY_BYTES + 1)), "<key>");
    Ok(())
}


#[test]
fn strip_serde_names_cuts_the_document_name() -> TestResult {
    assert_eq!(strip_serde_names(&format!("unknown field `{MARKER}`, expected `a`")), "unknown field");
    assert_eq!(strip_serde_names("duplicate field `x`"), "duplicate field");
    assert_eq!(strip_serde_names("count must be positive"), "count must be positive");
    Ok(())
}


#[test]
fn non_string_key_is_shown_as_key() -> TestResult {
    let error = serde_path_to_error::deserialize::<_, BTreeMap<u32, Vec<u32>>>(serde_json::json!({ "1": "x" }))
        .err()
        .ok_or("no error")?;
    assert_eq!(describe_path(error.path(), false), "<key>");
    Ok(())
}


#[test]
fn bounded_message_truncates_and_escapes() -> TestResult {
    assert_eq!(bounded_message("a\nb\u{1b}"), "a\\nb\\u{1b}");
    assert_eq!(bounded_message(&"x".repeat(MAX_MESSAGE_CHARS + 1)).len(), MAX_MESSAGE_CHARS);
    Ok(())
}


#[test]
fn enum_segment_is_shown_when_identifier_shaped() -> TestResult {
    let error = serde_path_to_error::deserialize::<_, Vec<Kind>>(serde_json::json!([{ "Beta": "x" }]))
        .err()
        .ok_or("no error")?;
    assert_eq!(describe_path(error.path(), false), "[0].<key>");
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
