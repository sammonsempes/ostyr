use phishing_report::error::TriageError;
use phishing_report::limits::Limits;
use phishing_report::model::{Counts, UrlHit};
use phishing_report::scan::scan;
use phishing_report::text::{clean, clean_address, has_hostile, is_hostile, is_zero_width, REPLACEMENT};
use phishing_report::urls::{collect, html_text, URL_RULE};
use regex::Regex;


const LONG_TEXT: usize = 500;


const SMALL_CAP: usize = 5;


const TWO: usize = 2;


const THREE: usize = 3;


const URL_CAP: usize = 2;


const TINY_URL_BYTES: usize = 30;


const MANY_LINES: usize = 20;


fn links(found: &[UrlHit]) -> Vec<&str> {
    found.iter().map(|hit| hit.url.as_str()).collect()
}


#[test]
fn hostile_characters_are_recognised() -> Result<(), Box<dyn std::error::Error>> {
    let hostile = [
        '\u{0}', '\u{1b}', '\r', '\n', '\u{202E}', '\u{2066}', '\u{200B}', '\u{2028}', '\u{FEFF}', '\u{3164}',
    ];
    assert!(hostile.iter().all(|candidate| is_hostile(*candidate)));
    assert!(!is_hostile('a'));
    assert!(!is_hostile('\u{e9}'));
    assert!(has_hostile("invoice\u{202E}fdp.exe"));
    assert!(!has_hostile("invoice.pdf"));
    Ok(())
}


#[test]
fn clean_replaces_and_counts_hostile_characters() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let cleaned = clean("a\u{1b}[31mb\u{202E}c", LONG_TEXT, &mut counts);
    assert_eq!(cleaned, format!("a{REPLACEMENT}[31mb{REPLACEMENT}c"));
    assert_eq!(counts.replaced_chars, TWO);
    assert_eq!(counts.text_cut, 0);
    Ok(())
}


#[test]
fn clean_cuts_with_a_marker_and_counts() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let cleaned = clean(&"x".repeat(LONG_TEXT), SMALL_CAP, &mut counts);
    assert_eq!(cleaned, format!("xxxxx[cut {} chars]", LONG_TEXT - SMALL_CAP));
    assert_eq!(counts.text_cut, 1);
    let mut exact = Counts::default();
    assert_eq!(clean("xxxxx", SMALL_CAP, &mut exact), "xxxxx");
    assert_eq!(exact.text_cut, 0);
    Ok(())
}


#[test]
fn clean_address_strips_brackets_and_refuses_bad_ones() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    assert_eq!(clean_address(" <a@b.example> ", LONG_TEXT, &mut counts).as_deref(), Some("a@b.example"));
    assert_eq!(clean_address("a@b.example\r\nBcc: x@y.example", LONG_TEXT, &mut counts), None);
    assert_eq!(clean_address("a\u{1b}@b.example", LONG_TEXT, &mut counts), None);
    assert_eq!(clean_address("no-at-sign", LONG_TEXT, &mut counts), None);
    assert_eq!(clean_address("a@b.example", SMALL_CAP, &mut counts), None);
    assert_eq!(counts.addresses_refused, SMALL_CAP - 1);
    assert_eq!(clean_address("<>", LONG_TEXT, &mut counts), None);
    assert_eq!(counts.addresses_refused, SMALL_CAP - 1);
    Ok(())
}


#[test]
fn scan_keeps_a_small_message_whole() -> Result<(), Box<dyn std::error::Error>> {
    let raw = b"From: a@b.example\r\nSubject: hi\r\n\r\nbody: not a header here\r\n";
    let scanned = scan(raw, &Limits::default());
    assert!(!scanned.cut);
    assert_eq!(scanned.usable, raw.as_slice());
    Ok(())
}


#[test]
fn scan_cuts_before_the_header_line_over_budget() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        headers: TWO,
        parts: TWO,
        ..Limits::default()
    };
    let raw = "H1: a\r\nH2: b\r\nH3: c\r\nH4: d\r\nH5: e\r\n\r\nbody\r\n".as_bytes();
    let scanned = scan(raw, &limits);
    assert!(scanned.cut);
    assert_eq!(scanned.usable, "H1: a\r\nH2: b\r\nH3: c\r\nH4: d\r\n".as_bytes());
    Ok(())
}


#[test]
fn scan_ignores_lines_that_are_not_header_shaped() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        headers: 1,
        parts: 1,
        ..Limits::default()
    };
    let raw = " folded: continuation\r\n:empty name\r\nnot a header: x\r\nno colon at all\r\nOne: 1\r\n";
    let scanned = scan(raw.as_bytes(), &limits);
    assert!(!scanned.cut);
    Ok(())
}


#[test]
fn scan_cuts_on_part_delimiters_and_message_type_lines() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        parts: 1,
        ..Limits::default()
    };
    let delimiters = "--a\r\nx\r\n--a\r\nx\r\n--a\r\nx\r\n";
    let cut_delimiters = scan(delimiters.as_bytes(), &limits);
    assert!(cut_delimiters.cut);
    assert_eq!(cut_delimiters.usable, "--a\r\nx\r\n--a\r\nx\r\n".as_bytes());
    let nested = "Content-Type: Message/RFC822\r\n\r\ncontent-type: message/rfc822\r\n\r\nContent-Type: message/rfc822\r\n";
    assert!(scan(nested.as_bytes(), &limits).cut);
    let plain = "Content-Type: text/plain\r\nContent-Type: message/\r\nContent\r\n";
    assert!(!scan(plain.as_bytes(), &limits).cut);
    Ok(())
}


#[test]
fn urls_are_deduplicated_trimmed_and_normalised() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let text = "see HTTP://Example.org/a?x=1. and http://example.org/a?x=1, then ftp://files.example/x) also http://\u{e9}xample.org/";
    let found = collect(&URL_RULE, text, 0, &Limits::default(), Vec::new(), &mut counts);
    assert_eq!(
        links(&found),
        ["http://example.org/a?x=1", "ftp://files.example/x", "http://xn--xample-9ua.org/"]
    );
    assert_eq!(counts, Counts::default());
    Ok(())
}


#[test]
fn urls_refuse_hostile_long_and_unparsable_ones() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        url_bytes: TINY_URL_BYTES,
        ..Limits::default()
    };
    let mut counts = Counts::default();
    let text =
        "http://a.example/\u{1b}[31m http://a.example/\u{202E}x http://long.example/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa http://[bad http://ok.example/";
    let found = collect(&URL_RULE, text, 0, &limits, Vec::new(), &mut counts);
    assert_eq!(links(&found), ["http://ok.example/"]);
    assert_eq!(counts.urls_refused, THREE + 1);
    Ok(())
}


#[test]
fn urls_are_capped_and_the_overflow_counted() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        urls: URL_CAP,
        ..Limits::default()
    };
    let mut counts = Counts::default();
    let text = "http://a.example/ http://b.example/ http://a.example/ http://c.example/ http://d.example/";
    let found = collect(&URL_RULE, text, 0, &limits, Vec::new(), &mut counts);
    assert_eq!(links(&found), ["http://a.example/", "http://b.example/"]);
    assert_eq!(counts.urls_dropped, TWO);
    Ok(())
}


#[test]
fn urls_in_html_attributes_and_data_urls_are_listed() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let html = html_text(
        "<a href=\"http://a.example/?x=1&amp;y=2\">t</a><img src='data:image/png;base64,AAAA'><p>metadata:no</p>",
        &mut counts,
    );
    let found = collect(&URL_RULE, &html, 0, &Limits::default(), Vec::new(), &mut counts);
    assert_eq!(links(&found), ["http://a.example/?x=1&y=2", "data:image/png;base64,AAAA"]);
    Ok(())
}


#[test]
fn a_pattern_that_did_not_compile_lists_nothing_and_is_counted() -> Result<(), Box<dyn std::error::Error>> {
    let broken = Regex::new(&String::from("("));
    let mut counts = Counts::default();
    let kept = vec![UrlHit {
        level: 0,
        url: "http://kept.example/".to_owned(),
    }];
    let found = collect(&broken, "http://a.example/", 0, &Limits::default(), kept.clone(), &mut counts);
    assert_eq!(found, kept);
    assert_eq!(counts.pattern_failed, 1);
    Ok(())
}


#[test]
fn many_header_like_lines_are_cut_without_a_refusal() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        headers: 1,
        parts: 1,
        ..Limits::default()
    };
    let raw = "A: 1\r\n".repeat(MANY_LINES);
    let scanned = scan(raw.as_bytes(), &limits);
    assert!(scanned.cut);
    assert_eq!(scanned.usable, "A: 1\r\n".as_bytes());
    Ok(())
}


#[test]
fn errors_name_no_message_text() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(TriageError::TooLarge.to_string(), "the message is larger than the size limit");
    assert_eq!(TriageError::Unparsable.to_string(), "the bytes are not a message");
    Ok(())
}


#[test]
fn html_character_references_are_decoded_and_undecodable_ones_counted() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let html = "<a href=\"https&#58;//a.evil.test/x\"> <a href=\"&#104;ttps://b.evil.test/y\"> <a href=\"https&colon;//c.evil.test/z\"> \
        <a href=\"&#x68;ttps://d.evil.test/w\"> https://e.evil.test/?a=1&b=2 &bogusentity; &;x &#; & done";
    let decoded = html_text(html, &mut counts);
    let found = collect(&URL_RULE, &decoded, 1, &Limits::default(), Vec::new(), &mut counts);
    assert_eq!(
        links(&found),
        [
            "https://a.evil.test/x",
            "https://b.evil.test/y",
            "https://c.evil.test/z",
            "https://d.evil.test/w",
            "https://e.evil.test/?a=1&b=2"
        ]
    );
    assert!(found.iter().all(|hit| hit.level == 1));
    assert_eq!(counts.html_refs_undecoded, TWO);
    let mut long = Counts::default();
    let name = "a".repeat(LONG_TEXT);
    html_text(&format!("&{name};"), &mut long);
    assert_eq!(long.html_refs_undecoded, 0);
    Ok(())
}


#[test]
fn a_url_with_a_zero_width_character_is_listed_cleaned_and_counted() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let text = "http://ev\u{200B}il.example/p\u{2060}ath http://plain.example/ http://e.example/\u{202E}x";
    let found = collect(&URL_RULE, text, 0, &Limits::default(), Vec::new(), &mut counts);
    assert_eq!(links(&found), ["http://evil.example/path", "http://plain.example/"]);
    assert_eq!(counts.urls_cleaned, 1);
    assert_eq!(counts.urls_refused, 1);
    assert!(is_zero_width('\u{FEFF}') && is_zero_width('\u{AD}') && !is_zero_width('a') && !is_zero_width('\u{202E}'));
    let tiny = Limits {
        url_bytes: TINY_URL_BYTES,
        ..Limits::default()
    };
    let big = format!("http://a.example/{}", "\u{200B}".repeat(LONG_TEXT));
    let mut limited = Counts::default();
    let kept = collect(&URL_RULE, &big, 0, &tiny, Vec::new(), &mut limited);
    assert_eq!(links(&kept), ["http://a.example/"]);
    Ok(())
}


#[test]
fn nested_message_lines_are_cut_over_the_budget() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        nested_messages: TWO,
        ..Limits::default()
    };
    let raw = "Content-Type:\r\n  MESSAGE/rfc822\r\nx\r\nmessage/rfc822\r\nx\r\nmessage/rfc822\r\nx\r\n";
    let scanned = scan(raw.as_bytes(), &limits);
    assert!(scanned.cut);
    assert_eq!(
        scanned.usable,
        "Content-Type:\r\n  MESSAGE/rfc822\r\nx\r\nmessage/rfc822\r\nx\r\n".as_bytes()
    );
    Ok(())
}
