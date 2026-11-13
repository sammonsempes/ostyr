#[path = "support/types.rs"]
mod types;


use attack_surface::text::{is_hidden, shown, valid_argument, valid_reference, SHOWN_BYTES};
use types::TestResult;


const TEXT_LIMIT: usize = 8;


const TWO_BYTE_CHARACTERS: usize = 33;


#[test]
fn shown_keeps_sixty_four_bytes_and_marks_the_cut() -> TestResult {
    let exact = "a".repeat(SHOWN_BYTES);
    assert_eq!(shown(&exact), exact);
    assert_eq!(shown(&format!("{exact}b")), format!("{exact}..."));
    let multibyte = "\u{e9}".repeat(TWO_BYTE_CHARACTERS);
    assert_eq!(shown(&multibyte), format!("{}...", "\\u{e9}".repeat(TWO_BYTE_CHARACTERS - 1)));
    assert_eq!(shown(""), "");
    Ok(())
}


#[test]
fn shown_escapes_hidden_characters() -> TestResult {
    assert_eq!(shown("a\u{202e}b\nc"), "a\\u{202e}b\\u{a}c");
    Ok(())
}


#[test]
fn shown_escapes_look_alikes_and_keeps_ascii_graphic_and_space() -> TestResult {
    assert_eq!(shown("TICKET-\u{421}1"), "TICKET-\\u{421}1");
    assert_eq!(shown("a\u{2800}b"), "a\\u{2800}b");
    assert_eq!(shown("a b~!"), "a b~!");
    Ok(())
}


#[test]
fn valid_argument_is_ascii_graphic_without_leading_dash() -> TestResult {
    assert!(valid_argument("22,80-90", TEXT_LIMIT));
    assert!(valid_argument("a-b", TEXT_LIMIT));
    [
        "",
        "123456789",
        "-x",
        "a\u{200b}b",
        "a b",
        "a\u{3164}b",
        "a\u{2800}b",
        "\u{421}1",
        "a\tb",
        "a\u{7f}",
    ]
    .iter()
    .for_each(|text| assert!(!valid_argument(text, TEXT_LIMIT), "{text:?}"));
    Ok(())
}


#[test]
fn valid_reference_is_an_ascii_allowlist() -> TestResult {
    ["TICKET-1", "CHG-1234", "dns:_ostyr.example.com", "a/b_c.d", "9"]
        .iter()
        .for_each(|text| assert!(valid_reference(text, TEXT_LIMIT * TEXT_LIMIT), "{text}"));
    [
        "",
        "-T1",
        "_x",
        "T 1",
        "a;b",
        "alice\u{3164}approved",
        "a\u{2800}b",
        "TICKET-\u{421}1",
        "a\u{200b}b",
        "\u{e9}",
    ]
    .iter()
    .for_each(|text| assert!(!valid_reference(text, TEXT_LIMIT * TEXT_LIMIT), "{text:?}"));
    assert!(valid_reference("12345678", TEXT_LIMIT));
    assert!(!valid_reference("123456789", TEXT_LIMIT));
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
