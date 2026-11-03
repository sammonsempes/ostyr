#[path = "support/types.rs"]
mod types;


use core_redact::key::{is_sensitive_key, split_segments};
use core_redact::types::ParameterMap;
use core_redact::value::{apply_rule, redact_text, REDACTED};
use core_redact::{redact_parameters, redact_value};
use proptest::prelude::*;
use regex::Regex;
use types::TestResult;


const JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln-_x";


#[test]
fn sensitive_keys_are_matched_by_segment() {
    [
        "password",
        "PASSWORD",
        "passwd",
        "pwd",
        "secret",
        "token",
        "key",
        "auth",
        "authorization",
        "Authorization",
        "cookie",
        "credential",
        "session",
        "api_key",
        "apiKey",
        "APIKey",
        "x-auth-token",
        "db.password",
        "SSH_KEY",
        "key2",
        "pwd1",
        "tokens",
        "passwords",
        "passphrase",
        "apikey",
        "Set-Cookie",
    ]
    .iter()
    .for_each(|key| assert!(is_sensitive_key(key), "{key}"));
}


#[test]
fn near_miss_keys_are_not_sensitive() {
    [
        "author",
        "monkey",
        "keyboard",
        "name",
        "",
        "___",
        "sessionless",
        "s",
        "status",
        "tokenizer",
    ]
    .iter()
    .for_each(|key| assert!(!is_sensitive_key(key), "{key}"));
}


#[test]
fn keys_are_split_on_separators_and_camel_case() {
    assert_eq!(split_segments("apiKey"), ["api", "Key"]);
    assert_eq!(split_segments("APIKey"), ["API", "Key"]);
    assert_eq!(split_segments("x-auth_token.v2"), ["x", "auth", "token", "v", "2"]);
    assert_eq!(split_segments("a__b"), ["a", "", "b"]);
}


#[test]
fn sensitive_keys_redact_the_whole_value() {
    assert_eq!(redact_value("api_key", "anything at all"), REDACTED);
    assert_eq!(redact_value("name", "visible"), "visible");
}


#[test]
fn every_reviewed_probe_is_redacted() {
    let cases = [
        (
            "note",
            "a https://u:one@h1 and https://v:two@h2",
            "a https://u:[REDACTED]@h1 and https://v:[REDACTED]@h2",
        ),
        ("note", "postgres://app:p/ss@db/x", "postgres://app:[REDACTED]@db/x"),
        ("note", "redis://:p#ss@cache", "redis://:[REDACTED]@cache"),
        ("note", "Bearer\tabc", "Bearer\t[REDACTED]"),
        ("header", "Authorization: Bearer abc", "Authorization: Bearer [REDACTED]"),
        ("note", "token=eyJhbGciOi.eyJzdWIi.c2ln", "token=[REDACTED]"),
        ("note", "x eyJhbGciOi.eyJlbmMi.a-b.c_d.e-f y", "x [REDACTED] y"),
        ("note", "eyJhbGciOi.eyJlbmMi.c2ln= tail", "[REDACTED] tail"),
        ("note", "t=eyJhbGciOi==.eyJzdWIi=.c2ln==", "t=[REDACTED]"),
        ("note", "eyJhbGciOiJkaXIi..iv.ct.tag", "[REDACTED]"),
        ("note", "bearer abc", "bearer [REDACTED]"),
        ("note", "BASIC dXNlcg==", "BASIC [REDACTED]"),
        ("note", "Bearer Bearer abc", "Bearer [REDACTED]"),
        (
            "note",
            "x\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\ny",
            "x\n[REDACTED]\ny",
        ),
        ("note", "-----begin private key-----\nabc", REDACTED),
        (
            "note",
            "postgres://admin:s3cret@db.local:5432/app?x=1",
            "postgres://admin:[REDACTED]@db.local:5432/app?x=1",
        ),
    ];
    cases
        .iter()
        .for_each(|(key, value, expected)| assert_eq!(redact_value(key, value), *expected, "{value}"));
}


#[test]
fn near_misses_stay_unchanged() {
    [
        "author",
        "https://host",
        "https://example.org/path@x:y",
        "ssh://git@host/repo",
        "eyJ",
        "eyJabc.def",
        "eyJabc..ghi",
        "eyJa.b!.c",
        "no url",
        "https://host:8080/path",
        "bearer",
        "plain text",
    ]
    .iter()
    .for_each(|value| assert_eq!(redact_value("note", value), *value));
}


#[test]
fn parameters_are_redacted_by_key_and_value() {
    let parameters: ParameterMap = [
        ("password".to_owned(), "hunter2".to_owned()),
        ("note".to_owned(), "Bearer topsecret".to_owned()),
        ("name".to_owned(), "visible".to_owned()),
    ]
    .into();
    let redacted = redact_parameters(&parameters);
    assert_eq!(redacted.get("password").map(String::as_str), Some(REDACTED));
    assert_eq!(redacted.get("note").map(String::as_str), Some("Bearer [REDACTED]"));
    assert_eq!(redacted.get("name").map(String::as_str), Some("visible"));
}


#[test]
fn a_pattern_that_did_not_compile_redacts_everything() {
    let broken = Regex::new(&String::from("("));
    assert_eq!(apply_rule(&broken, "visible", REDACTED), REDACTED);
    assert_eq!(apply_rule(&Regex::new("a"), "banana", "o"), "bonono");
}


#[test]
fn redaction_is_idempotent() {
    let once = redact_text("Bearer abc https://u:p@h and -----BEGIN X-----y-----END X-----");
    assert_eq!(redact_text(&once), once);
}


#[test]
fn jwt_alone_is_redacted() -> TestResult {
    assert_eq!(redact_text(JWT), REDACTED);
    Ok(())
}


fn credential() -> impl Strategy<Value = String> {
    "[A-Za-z0-9]{16,32}"
}


fn segment() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-]{4,16}"
}


proptest! {
    #[test]
    fn bearer_and_basic_credentials_never_survive(secret in credential(), word in "(?i)(bearer|basic)", gap in "[ \t\r\n]{1,3}") {
        let output = redact_text(&format!("Authorization: {word}{gap}{secret} tail"));
        prop_assert!(!output.contains(&secret));
        prop_assert!(output.ends_with(" tail"));
    }

    #[test]
    fn url_passwords_never_survive(secret in "[A-Za-z0-9/?#:%!$&*+=-]{16,32}", user in "[a-z]{0,8}", text in "[a-z ]{0,8}") {
        let output = redact_text(&format!("{text} postgres://{user}:{secret}@db.local/app?x=1"));
        prop_assert!(!output.contains(&secret));
        prop_assert!(output.ends_with("@db.local/app?x=1"));
    }

    #[test]
    fn jwt_and_jwe_never_survive(first in segment(), middle in segment(), last in segment(), pad in "={0,2}", five in any::<bool>()) {
        let token = if five {
            format!("eyJ{first}{pad}.{middle}{pad}.{middle}.{middle}.{last}{pad}")
        } else {
            format!("eyJ{first}{pad}.{middle}{pad}.{last}{pad}")
        };
        let output = redact_text(&format!("token={token} end"));
        prop_assert_eq!(output, format!("token={REDACTED} end"));
    }

    #[test]
    fn pem_blocks_never_survive(body in credential(), label in "[A-Z ]{3,12}") {
        let output = redact_text(&format!("a -----BEGIN {label}-----\n{body}\n-----END {label}----- b"));
        prop_assert_eq!(output, format!("a {REDACTED} b"));
    }

    #[test]
    fn sensitive_key_spellings_always_redact(secret in credential(), prefix in "[a-z]{1,6}", name in prop::sample::select(vec!["key", "token", "auth", "secret"])) {
        let upper = name.to_uppercase();
        let spellings = [format!("{prefix}_{name}"), format!("{prefix}-{name}"), format!("{prefix}.{name}"), format!("{prefix}{upper}")];
        spellings.iter().for_each(|key| assert_eq!(redact_value(key, &secret), REDACTED, "{key}"));
    }
}
