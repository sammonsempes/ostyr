#[path = "common/logging.rs"]
mod logging;
#[path = "common/sample.rs"]
mod sample;
#[path = "common/types.rs"]
mod types;


use dns_rpz::error::PolicyError;
use dns_rpz::limits::{MAX_HOST_HEADER_BYTES, MAX_NAME_BYTES, MAX_PAGE_BYTES, MAX_PAGE_TEXT_CHARS, PAGE_FIXED_BYTES};
use dns_rpz::policy::{validate_policy, SinkholePage};
use dns_rpz::sinkhole::render_page;
use logging::init_logging;
use sample::sample_policy;
use types::TestResult;


const UNKNOWN: &str = "unknown domain";


const HUGE_HEADER_BYTES: usize = 1_000_000;


const MAX_PORT: &str = "65535";


const STATUS_OK: u16 = 200;


const LABEL_BYTES: usize = 63;


const FULL_LABELS: usize = 3;


const SHOWN_TWICE: usize = 2;


const MARKER: &str = "zzmarker";


fn page(contact: &str, organisation: &str) -> SinkholePage {
    SinkholePage {
        contact: contact.to_owned(),
        organisation: organisation.to_owned(),
    }
}


fn html_of(host: &[u8]) -> String {
    init_logging();
    let rendered = render_page(None, Some(host));
    assert_eq!(rendered.status, STATUS_OK);
    rendered.html
}


fn long_name(length: usize) -> String {
    let labels = [
        "a".repeat(LABEL_BYTES),
        "b".repeat(LABEL_BYTES),
        "c".repeat(LABEL_BYTES),
        "d".repeat(length - LABEL_BYTES * FULL_LABELS - FULL_LABELS),
    ];
    labels.join(".")
}


#[test]
fn a_valid_name_is_shown_in_both_languages_with_status_200() -> TestResult {
    let html = html_of(b"Blocked.Example.com:8080");
    assert_eq!(html.matches("<strong>blocked.example.com</strong>").count(), SHOWN_TWICE);
    assert!(html.contains("Access blocked") && html.contains("Acc&egrave;s bloqu&eacute;"));
    assert!(!html.contains(UNKNOWN) && !html.contains("Contact"));
    assert!(html_of(b"localhost").contains("<strong>localhost</strong>"));
    assert!(html_of(b"a.example:1").contains("a.example"));
    Ok(())
}


#[test]
fn every_refusal_class_shows_unknown_domain_and_never_the_input() -> TestResult {
    let refused: Vec<Vec<u8>> = vec![
        format!("{MARKER}.example.com.").into_bytes(),
        format!("{MARKER}_x.example.com").into_bytes(),
        format!("{MARKER}.example.com:80:80").into_bytes(),
        format!("{MARKER}.example.com:").into_bytes(),
        format!("{MARKER}.example.com:12a").into_bytes(),
        format!("[::1{MARKER}]:80").into_bytes(),
        b"[2001:db8::1]".to_vec(),
        b"192.0.2.1".to_vec(),
        b"192.0.2.1:80".to_vec(),
        b"0x7f.1".to_vec(),
        b"1.2.3.4.5".to_vec(),
        b"".to_vec(),
        b":80".to_vec(),
        b"..".to_vec(),
        b"a..b".to_vec(),
        format!("a b{MARKER}.example").into_bytes(),
        b"<script>alert(1)</script>".to_vec(),
        b"a\"b'c&d.example".to_vec(),
        b"a\0b.example".to_vec(),
        b"a\r\nb.example".to_vec(),
        b"\xff\xfe.example".to_vec(),
        "\u{202e}evil.example".as_bytes().to_vec(),
        "ex\u{3002}".as_bytes().to_vec(),
        "xn--zz.example".as_bytes().to_vec(),
        "a".repeat(HUGE_HEADER_BYTES).into_bytes(),
    ];
    refused.iter().for_each(|host| {
        let html = html_of(host);
        assert!(html.contains(UNKNOWN));
        assert!(!html.contains(MARKER) && !html.contains("script") && !html.contains("evil") && !html.contains('\0'));
        assert!(html.contains("domaine inconnu"));
    });
    init_logging();
    let missing = render_page(None, None);
    assert_eq!((missing.status, missing.html.contains(UNKNOWN)), (STATUS_OK, true));
    Ok(())
}


#[test]
fn an_idn_host_shows_the_a_label_only() -> TestResult {
    let ascii = html_of(b"xn--bcher-kva.example");
    let raw = html_of("b\u{fc}cher.example".as_bytes());
    assert_eq!(ascii, raw);
    assert!(raw.contains("<strong>xn--bcher-kva.example</strong>"));
    assert!(!raw.contains('\u{fc}'));
    Ok(())
}


#[test]
fn the_header_cap_and_the_port_length_are_exact() -> TestResult {
    let name = long_name(MAX_NAME_BYTES);
    let exact = format!("{name}:{MAX_PORT}");
    assert_eq!(exact.len(), MAX_HOST_HEADER_BYTES);
    assert!(html_of(exact.as_bytes()).contains(&name));
    assert!(html_of(format!("{exact}0").as_bytes()).contains(UNKNOWN));
    assert!(html_of(format!("{name}0:80").as_bytes()).contains(UNKNOWN));
    assert!(html_of(format!("{name}:{MAX_PORT}0").as_bytes()).contains(UNKNOWN));
    assert!(html_of(b"a.example:00000").contains("a.example"));
    assert!(html_of(b"a.example:000000").contains(UNKNOWN));
    Ok(())
}


#[test]
fn contact_texts_are_escaped_and_shown() -> TestResult {
    init_logging();
    let texts = page("<script>\"x\"'y'&", "Org & Co");
    let html = render_page(Some(&texts), Some(b"a.example")).html;
    assert!(html.contains("&lt;script&gt;&quot;x&quot;&#x27;y&#x27;&amp;"));
    assert!(html.contains("Org &amp; Co"));
    assert!(!html.contains("<script>") && !html.contains("<a ") && !html.contains("<form") && !html.contains("http"));
    let accents = page("s\u{e9}curit\u{e9}@example.org", "\u{c9}quipe");
    assert!(render_page(Some(&accents), None).html.contains("\u{e9}"));
    Ok(())
}


#[test]
fn invisible_and_control_characters_in_the_texts_are_refused_by_field_name() -> TestResult {
    let refused = [
        "x\u{3164}y",
        "x\u{200b}y",
        "x\u{202e}y",
        "x\u{7}y",
        "x\u{a0}y",
        "x\u{ad}y",
        "\u{d7}",
        "\u{f7}",
        "a\nb",
        "   ",
        "",
        "\u{4e2d}",
    ];
    refused.iter().for_each(|bad| {
        let mut policy = sample_policy();
        policy.sinkhole_page = Some(page(bad, "Org"));
        assert!(
            matches!(validate_policy(&policy), Err(PolicyError::Setting(field)) if field == "sinkhole_page.contact"),
            "{bad:?}"
        );
        policy.sinkhole_page = Some(page("ok", bad));
        assert!(
            matches!(validate_policy(&policy), Err(PolicyError::Setting(field)) if field == "sinkhole_page.organisation"),
            "{bad:?}"
        );
    });
    let mut long = sample_policy();
    long.sinkhole_page = Some(page(&"a".repeat(MAX_PAGE_TEXT_CHARS + 1), "Org"));
    assert!(validate_policy(&long).is_err());
    long.sinkhole_page = Some(page(&"a".repeat(MAX_PAGE_TEXT_CHARS), &"\u{e9}".repeat(MAX_PAGE_TEXT_CHARS)));
    assert!(validate_policy(&long).is_ok());
    long.sinkhole_page = None;
    assert!(validate_policy(&long).is_ok());
    Ok(())
}


#[test]
fn the_page_is_deterministic_and_bounded() -> TestResult {
    init_logging();
    let worst = page(&"\"".repeat(MAX_PAGE_TEXT_CHARS), &"'".repeat(MAX_PAGE_TEXT_CHARS));
    let host = long_name(MAX_NAME_BYTES);
    let first = render_page(Some(&worst), Some(host.as_bytes()));
    assert_eq!(first, render_page(Some(&worst), Some(host.as_bytes())));
    assert!(first.html.len() <= MAX_PAGE_BYTES);
    let fixed = render_page(None, Some("a".repeat(HUGE_HEADER_BYTES).as_bytes())).html;
    assert!(fixed.len() <= PAGE_FIXED_BYTES);
    assert!(render_page(Some(&worst), Some("<".repeat(HUGE_HEADER_BYTES).as_bytes())).html.len() <= MAX_PAGE_BYTES);
    Ok(())
}


#[test]
fn a_hex_ipv4_literal_is_an_address_and_shows_unknown_domain() -> TestResult {
    for host in ["0x7f.0x1", "0x7f000001", "0X7F.0X1", "a.0x", "example.0xff"] {
        let html = html_of(host.as_bytes());
        assert!(html.contains(UNKNOWN), "{host}");
        assert!(!html.contains(host));
    }
    assert!(html_of(b"a.0xg").contains("<strong>a.0xg</strong>"));
    assert!(html_of(b"x0x1.example").contains("x0x1.example"));
    Ok(())
}


#[test]
fn uts46_mapping_shows_the_name_a_browser_resolves() -> TestResult {
    assert!(html_of("a\u{200b}b.example".as_bytes()).contains("<strong>ab.example</strong>"));
    assert!(html_of("a\u{ad}b.example".as_bytes()).contains("<strong>ab.example</strong>"));
    assert!(html_of("a\u{3002}example".as_bytes()).contains("<strong>a.example</strong>"));
    assert!(html_of("a\u{3164}b.example".as_bytes()).contains("<strong>ab.example</strong>"));
    Ok(())
}
