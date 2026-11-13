mod common;


use common::types::TestResult;
use remote_shell::grammar::{valid_reference, valid_subject, MAX_REFERENCE_BYTES, MAX_SUBJECT_BYTES};


#[test]
fn subjects_with_plain_characters_are_valid() -> TestResult {
    assert!(valid_subject("alice"));
    assert!(valid_subject("alice.b@example.org"));
    assert!(valid_subject("auth0:x"));
    assert!(valid_subject("auth0|123"));
    assert!(valid_subject("a||"));
    assert!(valid_subject("|x"));
    assert!(valid_subject(&"a".repeat(MAX_SUBJECT_BYTES)));
    Ok(())
}


#[test]
fn empty_and_oversized_subjects_are_refused() -> TestResult {
    assert!(!valid_subject(""));
    assert!(!valid_subject(&"a".repeat(MAX_SUBJECT_BYTES + 1)));
    Ok(())
}


#[test]
fn whitespace_and_hidden_characters_are_refused() -> TestResult {
    assert!(!valid_subject("alice "));
    assert!(!valid_subject(" alice"));
    assert!(!valid_subject("ali\tce"));
    assert!(!valid_subject("ali\u{200b}ce"));
    assert!(!valid_subject("ali\u{ad}ce"));
    assert!(!valid_subject("ali\u{202e}ce"));
    assert!(!valid_subject("ali\u{feff}ce"));
    assert!(!valid_subject("ali\nce"));
    [
        "alice\u{3164}",
        "alice\u{115f}",
        "alice\u{1160}",
        "alice\u{ffa0}",
        "\u{3164}",
        "alice\u{0345}",
        "al\u{0456}ce",
    ]
    .iter()
    .for_each(|subject| assert!(!valid_subject(subject)));
    Ok(())
}


#[test]
fn references_follow_the_grammar() -> TestResult {
    assert!(valid_reference("INC-4521"));
    assert!(valid_reference("a"));
    assert!(valid_reference("T1.a:b/c_d-e"));
    assert!(valid_reference(&"a".repeat(MAX_REFERENCE_BYTES)));
    Ok(())
}


#[test]
fn bad_references_are_refused() -> TestResult {
    assert!(!valid_reference(""));
    assert!(!valid_reference("-INC"));
    assert!(!valid_reference("_INC"));
    assert!(!valid_reference("INC 1"));
    assert!(!valid_reference("\u{e9}"));
    assert!(!valid_reference("a/\u{e9}"));
    assert!(!valid_reference("INC\n1"));
    assert!(!valid_reference(&"a".repeat(MAX_REFERENCE_BYTES + 1)));
    Ok(())
}
