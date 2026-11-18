mod common;


use cases::grammar::{
    is_bidi_control, is_domain, is_email, is_hash, is_label, is_plain_text, is_printable_ascii, is_url, is_valid_value, HASH_LENGTHS,
    MAX_DOMAIN_CHARS, MAX_LABEL_CHARS, MAX_LOCAL_CHARS,
};
use cases::model::ObservableKind;
use common::types::TestResult;


const FIVE_LABELS: usize = 5;


const FOUR_LABELS: usize = 4;


const UNDER_LABEL: usize = 62;


const LONG_LABEL: usize = 60;


#[test]
fn ip_addresses_are_parsed_and_a_zone_id_is_refused() -> TestResult {
    assert!(is_valid_value(ObservableKind::Ip, "10.0.0.1"));
    assert!(is_valid_value(ObservableKind::Ip, "2001:db8::1"));
    assert!(!is_valid_value(ObservableKind::Ip, "fe80::1%eth0"));
    assert!(!is_valid_value(ObservableKind::Ip, "10.0.0.256"));
    assert!(!is_valid_value(ObservableKind::Ip, ""));
    Ok(())
}


#[test]
fn domains_are_ldh_labels_of_one_to_sixty_three_and_at_most_253() -> TestResult {
    assert!(is_domain("example.com"));
    assert!(is_domain("a-b.c1"));
    assert!(is_label(&"a".repeat(MAX_LABEL_CHARS)));
    assert!(!is_label(&"a".repeat(MAX_LABEL_CHARS + 1)));
    assert!(!is_domain(&format!("{}.com", "a".repeat(MAX_LABEL_CHARS + 1))));
    assert!(!is_domain("-a.com") && !is_domain("a-.com"));
    assert!(!is_domain("a..com") && !is_domain("") && !is_domain("exa_mple.com"));
    assert!(!is_domain("exämple.com") && !is_domain("Example.com"));
    let long = vec!["a".repeat(LONG_LABEL); FIVE_LABELS].join(".");
    assert!(long.len() > MAX_DOMAIN_CHARS && !is_domain(&long));
    let widest = vec!["a".repeat(UNDER_LABEL); FOUR_LABELS].join(".");
    assert!(widest.len() <= MAX_DOMAIN_CHARS && is_domain(&widest));
    Ok(())
}


#[test]
fn hashes_have_a_known_length_and_hexadecimal_digits() -> TestResult {
    for length in HASH_LENGTHS {
        assert!(is_hash(&"a".repeat(length)), "{length}");
        assert!(!is_hash(&"a".repeat(length - 1)), "{length}");
        assert!(!is_hash(&"a".repeat(length + 1)), "{length}");
        assert!(!is_hash(&format!("{}g", "a".repeat(length - 1))), "{length}");
        assert!(!is_hash(&"A".repeat(length)), "{length}");
    }
    assert!(!is_hash(""));
    Ok(())
}


#[test]
fn emails_need_a_printable_local_part_and_a_domain() -> TestResult {
    assert!(is_email("alice+tag@example.com"));
    assert!(!is_email("alice smith@example.com"));
    assert!(!is_email("@example.com"));
    assert!(!is_email("alice@"));
    assert!(!is_email("alice"));
    assert!(!is_email("alice@exa mple.com"));
    assert!(!is_email(&format!("{}@example.com", "a".repeat(MAX_LOCAL_CHARS + 1))));
    assert!(is_email(&format!("{}@example.com", "a".repeat(MAX_LOCAL_CHARS))));
    assert!(!is_email("al\u{e9}@example.com"));
    Ok(())
}


#[test]
fn urls_are_absolute_printable_ascii_with_an_allowed_scheme() -> TestResult {
    assert!(is_url("http://example.com/a?b=c"));
    assert!(is_url("HTTPS://example.com"));
    assert!(is_url("ftp://example.com/file"));
    assert!(!is_url("javascript:alert(1)"));
    assert!(!is_url("file:///etc/passwd"));
    assert!(!is_url("http://"));
    assert!(!is_url("http:///path"));
    assert!(!is_url("http://example.com/a b"));
    assert!(!is_url("http://example.com/\u{1b}"));
    assert!(!is_url("http://exämple.com"));
    assert!(!is_url("htt"));
    assert!(!is_url("é"));
    Ok(())
}


#[test]
fn plain_text_refuses_controls_and_bidirectional_controls() -> TestResult {
    assert!(is_plain_text("report <1>.pdf \u{2028}"));
    for refused in [
        "a\u{1b}b",
        "a\nb",
        "a\u{7f}",
        "a\u{85}",
        "a\u{202e}b",
        "a\u{2066}",
        "a\u{2069}",
        "a\u{202a}",
    ] {
        assert!(!is_plain_text(refused), "{refused:?}");
    }
    assert!(!is_valid_value(ObservableKind::Filename, "evil\u{202e}gpj.exe"));
    assert!(is_valid_value(ObservableKind::Other, "<script>"));
    assert!(is_bidi_control('\u{202b}') && !is_bidi_control('a') && !is_bidi_control('\u{2065}') && !is_bidi_control('\u{202f}'));
    assert!(is_printable_ascii("a~!") && !is_printable_ascii("a b") && !is_printable_ascii("\u{7f}"));
    Ok(())
}


#[test]
fn every_kind_is_dispatched_to_its_grammar() -> TestResult {
    assert!(is_valid_value(ObservableKind::Domain, "example.com"));
    let shortest = HASH_LENGTHS.iter().min().copied().unwrap_or(0);
    assert!(is_valid_value(ObservableKind::Hash, &"0".repeat(shortest)));
    assert!(!is_valid_value(ObservableKind::Hash, &"0".repeat(shortest - 1)));
    assert!(is_valid_value(ObservableKind::Email, "a@b.co"));
    assert!(is_valid_value(ObservableKind::Url, "http://a.b"));
    assert!(is_valid_value(ObservableKind::Filename, "x.exe"));
    Ok(())
}
