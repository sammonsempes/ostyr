use crate::common::{params_of, path_kind, refusal, single, text, text_kind};
use crate::types::TestResult;
use script_library::error::ScriptError;
use script_library::model::{ParamKind, ParamValue};
use script_library::params::validate_params;


pub const MIN_LENGTH: usize = 2;


pub const MAX_LENGTH: usize = 4;


pub const WIDE_LENGTH: usize = 64;


pub const LOW: i64 = -5;


pub const HIGH: i64 = 10;


#[test]
fn string_length_bounds() -> TestResult {
    let manifest = single("label", text_kind(MIN_LENGTH, MAX_LENGTH, None));
    validate_params(&manifest, &params_of(vec![("label", text("ab"))]))?;
    validate_params(&manifest, &params_of(vec![("label", text("abcd"))]))?;
    let short = refusal(validate_params(&manifest, &params_of(vec![("label", text("a"))])))?;
    assert!(matches!(short, ScriptError::TooShort(name) if name == "label"));
    let long = refusal(validate_params(&manifest, &params_of(vec![("label", text("abcde"))])))?;
    assert!(matches!(long, ScriptError::TooLong(name) if name == "label"));
    Ok(())
}


#[test]
fn string_nul_is_refused_without_echo() -> TestResult {
    let manifest = single("label", text_kind(0, MAX_LENGTH, None));
    let error = refusal(validate_params(&manifest, &params_of(vec![("label", text("a\0b"))])))?;
    assert!(matches!(error, ScriptError::NulByte(_)));
    Ok(())
}


#[test]
fn string_pattern_matches_whole_value() -> TestResult {
    let manifest = single("host", text_kind(0, WIDE_LENGTH, Some("[a-z]+|[0-9]+")));
    validate_params(&manifest, &params_of(vec![("host", text("abc"))]))?;
    validate_params(&manifest, &params_of(vec![("host", text("123"))]))?;
    let alternation = refusal(validate_params(&manifest, &params_of(vec![("host", text("a|b"))])))?;
    assert!(matches!(alternation, ScriptError::PatternMismatch(_)));
    let partial = refusal(validate_params(&manifest, &params_of(vec![("host", text("abc1"))])))?;
    assert!(matches!(partial, ScriptError::PatternMismatch(_)));
    let injected = refusal(validate_params(&manifest, &params_of(vec![("host", text("abc; rm -rf /"))])))?;
    assert!(matches!(injected, ScriptError::PatternMismatch(_)));
    let newline = refusal(validate_params(&manifest, &params_of(vec![("host", text("abc\n"))])))?;
    assert!(matches!(newline, ScriptError::PatternMismatch(_)));
    Ok(())
}


#[test]
fn unvalidated_manifest_with_bad_pattern_is_refused() -> TestResult {
    let manifest = single("host", text_kind(0, WIDE_LENGTH, Some("(")));
    let error = refusal(validate_params(&manifest, &params_of(vec![("host", text("x"))])))?;
    assert!(matches!(error, ScriptError::Pattern(_)));
    Ok(())
}


#[test]
fn integer_bounds() -> TestResult {
    let manifest = single("days", ParamKind::Integer { min: LOW, max: HIGH });
    validate_params(&manifest, &params_of(vec![("days", ParamValue::Integer(LOW))]))?;
    validate_params(&manifest, &params_of(vec![("days", ParamValue::Integer(HIGH))]))?;
    let below = refusal(validate_params(&manifest, &params_of(vec![("days", ParamValue::Integer(LOW - 1))])))?;
    assert!(matches!(below, ScriptError::OutOfRange(name) if name == "days"));
    let above = refusal(validate_params(&manifest, &params_of(vec![("days", ParamValue::Integer(HIGH + 1))])))?;
    assert!(matches!(above, ScriptError::OutOfRange(_)));
    Ok(())
}


#[test]
fn enumeration_membership() -> TestResult {
    let manifest = single(
        "level",
        ParamKind::Enumeration {
            values: vec!["low".to_string(), "high".to_string()],
        },
    );
    validate_params(&manifest, &params_of(vec![("level", text("high"))]))?;
    let error = refusal(validate_params(&manifest, &params_of(vec![("level", text("High"))])))?;
    assert!(matches!(error, ScriptError::NotAllowed(name) if name == "level"));
    Ok(())
}


#[test]
fn path_rules() -> TestResult {
    let manifest = single("target", path_kind(&["/var/log", "C:\\Data"]));
    validate_params(&manifest, &params_of(vec![("target", text("/var/log/app.log"))]))?;
    validate_params(&manifest, &params_of(vec![("target", text("C:\\Data\\x"))]))?;
    [
        "relative.log",
        "/var/log/../shadow",
        "/var/log/a\0b",
        "\\var\\log",
        "/var/log/..\\..\\etc",
    ]
    .iter()
    .try_for_each(|path| -> TestResult {
        let error = refusal(validate_params(&manifest, &params_of(vec![("target", text(path))])))?;
        assert!(matches!(error, ScriptError::MalformedPath(_)), "{path:?}");
        Ok(())
    })?;
    let outside = refusal(validate_params(&manifest, &params_of(vec![("target", text("/etc/shadow"))])))?;
    assert!(matches!(outside, ScriptError::PathOutsidePrefixes(_)));
    let sibling = refusal(validate_params(&manifest, &params_of(vec![("target", text("/var/logs/x"))])))?;
    assert!(matches!(sibling, ScriptError::PathOutsidePrefixes(_)));
    Ok(())
}


#[test]
fn missing_unknown_and_mistyped() -> TestResult {
    let manifest = single("days", ParamKind::Integer { min: 0, max: HIGH });
    let missing = refusal(validate_params(&manifest, &params_of(vec![])))?;
    assert!(matches!(missing, ScriptError::MissingParameter(name) if name == "days"));
    let unknown = refusal(validate_params(
        &manifest,
        &params_of(vec![("days", ParamValue::Integer(1)), ("extra", text("x"))]),
    ))?;
    assert!(matches!(unknown, ScriptError::UnknownParameter));
    let wrong = refusal(validate_params(&manifest, &params_of(vec![("days", text("1"))])))?;
    assert!(matches!(wrong, ScriptError::WrongType(name) if name == "days"));
    let wrong_text = refusal(validate_params(
        &single("label", text_kind(0, MAX_LENGTH, None)),
        &params_of(vec![("label", ParamValue::Integer(1))]),
    ))?;
    assert!(matches!(wrong_text, ScriptError::WrongType(_)));
    Ok(())
}


#[test]
fn no_parameters_accepts_empty_set() -> TestResult {
    let manifest = crate::common::manifest_with(script_library::model::Interpreter::Bash, vec![]);
    validate_params(&manifest, &params_of(vec![]))?;
    Ok(())
}
