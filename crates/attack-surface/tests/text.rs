#[path = "support/types.rs"]
mod types;


use attack_surface::text::{is_hidden, shown, valid_hostname, valid_text, MAX_NAME_BYTES, SHOWN_BYTES};
use types::TestResult;


const TEXT_LIMIT: usize = 8;


const TWO_BYTE_CHARACTERS: usize = 33;


#[test]
fn shown_keeps_sixty_four_bytes_and_marks_the_cut() -> TestResult {
    let exact = "a".repeat(SHOWN_BYTES);
    assert_eq!(shown(&exact), exact);
    assert_eq!(shown(&format!("{exact}b")), format!("{exact}..."));
    let multibyte = "\u{e9}".repeat(TWO_BYTE_CHARACTERS);
    assert_eq!(shown(&multibyte), format!("{}...", "\u{e9}".repeat(TWO_BYTE_CHARACTERS - 1)));
    assert_eq!(shown(""), "");
    Ok(())
}


#[test]
fn shown_escapes_hidden_characters() -> TestResult {
    assert_eq!(shown("a\u{202e}b\nc"), "a\\u{202e}b\\u{a}c");
    Ok(())
}


#[test]
fn valid_text_refuses_empty_long_dashed_hidden_and_spaced_text() -> TestResult {
    assert!(valid_text("TICKET-1", TEXT_LIMIT));
    assert!(!valid_text("", TEXT_LIMIT));
    assert!(!valid_text("123456789", TEXT_LIMIT));
    assert!(!valid_text("-x", TEXT_LIMIT));
    assert!(!valid_text("a\u{200b}b", TEXT_LIMIT));
    assert!(!valid_text("a b", TEXT_LIMIT));
    Ok(())
}


#[test]
fn is_hidden_covers_control_format_and_separators() -> TestResult {
    ['\u{0}', '\u{202e}', '\u{200b}', '\u{2028}', '\u{2029}']
        .iter()
        .for_each(|next| assert!(is_hidden(*next)));
    assert!(!is_hidden('a') && !is_hidden(' '));
    Ok(())
}


#[test]
fn valid_hostname_follows_the_grammar() -> TestResult {
    assert!(valid_hostname("app.example.org"));
    assert!(valid_hostname("a-1.b2.io"));
    assert!(!valid_hostname("localhost"));
    assert!(!valid_hostname("1.2.3"));
    assert!(!valid_hostname("a..b"));
    assert!(!valid_hostname(&format!("{}.org", "a".repeat(MAX_NAME_BYTES))));
    Ok(())
}
