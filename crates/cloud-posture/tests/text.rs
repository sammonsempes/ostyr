#[path = "common/types.rs"]
mod types;


use cloud_posture::text::{
    cut_text, escaped, escaped_whole, finding_uid, shown, valid_provider, valid_reference, valid_spaced_reference, MAX_FINDING_UID_BYTES,
};
use types::TestResult;


const CAP: usize = 16;


const CUT: usize = 9;


const EMOJI_BYTES: usize = 4;


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
fn cut_text_keeps_a_raw_prefix_on_a_character_boundary_and_counts_the_rest() -> TestResult {
    assert_eq!(cut_text("", CAP), (String::new(), 0));
    assert_eq!(cut_text(&"a".repeat(CAP), CAP), ("a".repeat(CAP), 0));
    assert_eq!(cut_text(&"a".repeat(CAP + 1), CAP), ("a".repeat(CAP), 1));
    let emoji = "\u{1f600}".repeat(CAP);
    let (kept, cut) = cut_text(&emoji, CAP);
    assert_eq!((kept.len(), cut), (CAP, CAP * EMOJI_BYTES - CAP));
    assert!(kept.chars().all(|next| next == '\u{1f600}'));
    assert_eq!(cut_text("\u{3164}", 1), (String::new(), HANGUL_BYTES));
    assert_eq!(cut_text("ab", 0), (String::new(), "ab".len()));
    Ok(())
}


#[test]
fn shown_escapes_at_display_time_and_marks_a_real_cut_with_a_backslash() -> TestResult {
    assert_eq!(shown("", 0), "");
    assert_eq!(shown("a\u{3164}", 0), "a\\u{3164}");
    assert_eq!(shown("ab", CUT), format!("ab\\[{CUT} bytes cut]"));
    let forged = shown("x...[9 bytes cut]", 0);
    assert_eq!(forged, "x...[9 bytes cut]");
    assert_ne!(forged, shown("x", CUT));
    assert!(!shown("\\[9 bytes cut]", 0).contains("\\["));
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
