#[path = "common/types.rs"]
mod types;


use cloud_posture::text::{
    escaped, escaped_whole, finding_uid, shown, valid_provider, valid_reference, valid_spaced_reference, MAX_FINDING_UID_BYTES,
};
use types::TestResult;


const CAP: usize = 16;


const ESCAPED_LEN: usize = 8;


const HANGUL_BYTES: usize = 3;


#[test]
fn references_follow_the_ascii_allowlist() -> TestResult {
    let accepted = [
        "arn:aws:s3:::my-bucket",
        "/subscriptions/0a1b/resourceGroups/rg(1)/providers/Microsoft.Storage/x",
        "a",
        "9",
        "k8s_uid.1+2=3,4@5*",
        "arn:aws:lambda:eu-west-1:1:function:f:$LATEST",
        "arn:aws:logs:eu-west-1:1:log-group:/aws/x#y",
    ];
    accepted.iter().for_each(|text| assert!(valid_reference(text, CAP * CAP), "{text}"));
    let refused = [
        "",
        "-a",
        "a b",
        "a\u{3164}",
        "é",
        "a\n",
        "a\u{0}",
        "a\"",
        "a;b",
        "a|b",
        "a%b",
        "a\\b",
        "a?b",
        "a<b>",
    ];
    refused.iter().for_each(|text| assert!(!valid_reference(text, CAP * CAP), "{text:?}"));
    assert!(valid_reference(&"a".repeat(CAP), CAP));
    assert!(!valid_reference(&"a".repeat(CAP + 1), CAP));
    Ok(())
}


#[test]
fn providers_are_lowercase_ascii_names() -> TestResult {
    ["aws", "azure", "gcp", "kubernetes", "m365", "google_workspace"]
        .iter()
        .for_each(|text| assert!(valid_provider(text), "{text}"));
    ["", "AWS", "a-b", "a b", "a\u{3164}", &"a".repeat(CAP * CAP)]
        .iter()
        .for_each(|text| assert!(!valid_provider(text), "{text:?}"));
    Ok(())
}


#[test]
fn escaping_keeps_ascii_graphic_and_escapes_everything_else() -> TestResult {
    assert_eq!(escaped('a'), "a");
    assert_eq!(escaped(' '), " ");
    assert_eq!(escaped('\u{1b}'), "\\u{1b}");
    assert_eq!(escaped('\u{3164}'), "\\u{3164}");
    assert_eq!(escaped('е'), "\\u{435}");
    assert_eq!(escaped('\u{7f}'), "\\u{7f}");
    assert_eq!(escaped('\\'), "\\u{5c}");
    Ok(())
}


#[test]
fn shown_cuts_on_the_escaped_length_and_counts_the_source_bytes_left_out() -> TestResult {
    assert_eq!(shown("", CAP), "");
    assert_eq!(shown(&"a".repeat(CAP), CAP), "a".repeat(CAP));
    assert_eq!(shown(&"a".repeat(CAP + 1), CAP), format!("{}...[1 bytes cut]", "a".repeat(CAP)));
    let hangul = shown(&"\u{3164}".repeat(CAP), CAP);
    assert_eq!(
        hangul,
        format!(
            "{}...[{} bytes cut]",
            "\\u{3164}".repeat(CAP / ESCAPED_LEN),
            (CAP - CAP / ESCAPED_LEN) * HANGUL_BYTES
        )
    );
    let escaped_text = shown(&format!("ab{}", "\u{1b}".repeat(CAP)), CAP);
    assert!(escaped_text.starts_with("ab\\u{1b}"), "{escaped_text}");
    assert!(escaped_text.contains("bytes cut]"), "{escaped_text}");
    Ok(())
}


#[test]
fn a_finding_uid_is_kept_raw_and_escaped_on_demand() -> TestResult {
    assert_eq!(finding_uid("a b"), Some("a b".to_owned()));
    assert_eq!(finding_uid("a\u{3164}"), Some("a\u{3164}".to_owned()));
    assert_eq!(escaped_whole("\\u{1b}"), "\\u{5c}u{1b}");
    assert_ne!(escaped_whole("\\u{1b}"), escaped_whole("\u{1b}"));
    assert_eq!(finding_uid(""), None);
    assert!(finding_uid(&"a".repeat(MAX_FINDING_UID_BYTES)).is_some());
    assert_eq!(finding_uid(&"a".repeat(MAX_FINDING_UID_BYTES + 1)), None);
    Ok(())
}


#[test]
fn spaced_references_allow_single_inner_spaces_only() -> TestResult {
    ["a", "Conditional Access Policy", "Group/Domain Admins"]
        .iter()
        .for_each(|text| assert!(valid_spaced_reference(text, CAP * CAP), "{text}"));
    ["", " ", " a", "a ", "a  b", "a -b", "-a", "a\tb", "a\u{3164}b", "a<b"]
        .iter()
        .for_each(|text| assert!(!valid_spaced_reference(text, CAP * CAP), "{text:?}"));
    assert!(valid_spaced_reference("aaaa bbbb", CAP));
    assert!(!valid_spaced_reference("aaaaaaaaa bbbbbbbbb", CAP));
    Ok(())
}
