use crate::common::{fixed_random, settings, Failing, FIXED_NONCE};
use crate::types::TestResult;
use ai_gateway::error::{AiError, SecretClass};
use ai_gateway::limits::{MAX_DATA_DEPTH, MAX_DATA_NODES, MAX_KEY_BYTES};
use ai_gateway::request::{build_request, check_data_shape, closing_tag, key_text, new_nonce, opening_tag, read_authorization, read_key};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::symlink;


#[test]
fn the_shape_check_counts_nodes_and_depth_without_recursion() -> TestResult {
    assert!(check_data_shape(&json!({"a": [true, false, {"b": null}], "c": "text"})).is_ok());
    assert!(check_data_shape(&json!(null)).is_ok());
    let deep = (0..=MAX_DATA_DEPTH).fold(json!(1), |inner, _index| json!([inner]));
    assert!(matches!(check_data_shape(&deep), Err(AiError::DataTooComplex)));
    let wide = Value::Array(vec![json!({"k": 1}); MAX_DATA_NODES]);
    assert!(matches!(check_data_shape(&wide), Err(AiError::DataTooComplex)));
    Ok(())
}


#[test]
fn the_nonce_is_32_hex_characters_and_the_tags_use_it() -> TestResult {
    let nonce = new_nonce(fixed_random)?;
    assert_eq!(nonce, FIXED_NONCE);
    assert_eq!(opening_tag(&nonce), format!("<data-{FIXED_NONCE}>"));
    assert_eq!(closing_tag(&nonce), format!("</data-{FIXED_NONCE}>"));
    Ok(())
}


#[test]
fn the_body_is_built_from_one_settings_snapshot() -> TestResult {
    let body = build_request(&settings("x"), "instructions", &json!({"a": 1}), FIXED_NONCE)?;
    let parsed: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        parsed.pointer("/messages/1/content"),
        Some(&json!(format!("<data-{FIXED_NONCE}>{{\"a\":1}}</data-{FIXED_NONCE}>")))
    );
    Ok(())
}


#[test]
fn key_text_accepts_only_a_printable_ascii_token() -> TestResult {
    assert_eq!(key_text(b"  abc.DEF-1_2  \n")?.as_str(), "Bearer abc.DEF-1_2");
    assert!(matches!(key_text(b""), Err(AiError::Secret { class: SecretClass::Format })));
    assert!(matches!(key_text(b"a b"), Err(AiError::Secret { class: SecretClass::Format })));
    assert!(matches!(key_text(b"a\x07b"), Err(AiError::Secret { class: SecretClass::Format })));
    assert!(matches!(
        key_text("k\u{3164}".as_bytes()),
        Err(AiError::Secret { class: SecretClass::Format })
    ));
    assert!(matches!(
        key_text(&[b'a'; MAX_KEY_BYTES + 1]),
        Err(AiError::Secret {
            class: SecretClass::TooLarge
        })
    ));
    Ok(())
}


#[test]
fn a_failing_key_reader_is_a_fixed_class() -> TestResult {
    let error = read_key(&mut Failing).err().ok_or("accepted")?;
    assert!(matches!(
        error,
        AiError::Secret {
            class: SecretClass::Unreadable
        }
    ));
    assert!(!format!("{error} {error:?}").contains(crate::common::MARKER));
    Ok(())
}


#[test]
fn a_symlinked_key_file_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    let target = directory.path().join("target");
    fs::write(&target, b"sk-1")?;
    let link = directory.path().join("link");
    symlink(&target, &link)?;
    assert!(matches!(read_authorization(&link), Err(AiError::Secret { class: SecretClass::Refused })));
    Ok(())
}
