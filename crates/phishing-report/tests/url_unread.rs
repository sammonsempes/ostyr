use phishing_report::limits::Limits;
use phishing_report::model::{Counts, ReporterPolicy, Triage};
use phishing_report::triage::triage;
use phishing_report::urls::{collect_indexed, index_from, URL_RULE};


const PAD: usize = 2100;


const MARGIN: usize = 100;


const HALF_MARGIN: usize = 50;


const UNREAD: &str = "url_host_unread";


const FLAGGED_FORMS: usize = 4;


fn run_text(text: &str) -> (Vec<String>, Counts) {
    let mut counts = Counts::default();
    let mut index = index_from(&[], Vec::new());
    collect_indexed(&URL_RULE, text, 0, &Limits::default(), Vec::new(), &mut index, &mut counts);
    (index.hosts, counts)
}


fn port_padding() -> String {
    format!("https://p.evil.test:{}443/x", "0".repeat(PAD))
}


fn typed_slash_beyond_the_cut() -> String {
    format!("https://{}@c.evil.test/xyz", "a".repeat(PAD - HALF_MARGIN))
}


fn userinfo_padding() -> String {
    format!("https://{}@u.evil.test/x", "a".repeat(PAD))
}


fn slash_padding() -> String {
    format!("https:{}s.evil.test/x", "/".repeat(PAD))
}


fn control_url() -> String {
    format!("https://long.evil.test/{}", "b".repeat(PAD))
}


#[test]
fn every_padded_form_is_flagged_unread_and_lists_no_host() -> Result<(), Box<dyn std::error::Error>> {
    [port_padding(), userinfo_padding(), slash_padding(), typed_slash_beyond_the_cut()]
        .iter()
        .enumerate()
        .try_for_each(|(form, url)| {
            let (hosts, counts) = run_text(url);
            assert!(hosts.is_empty(), "form {form}");
            assert_eq!(counts.url_host_unread, 1, "form {form}");
            assert_eq!(counts.urls_refused, 1, "form {form}");
            Ok(())
        })
}


#[test]
fn a_typed_slash_inside_the_cut_lists_the_host_and_is_not_flagged() -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("https://{}@c.evil.test/{}", "a".repeat(PAD - MARGIN), "x".repeat(MARGIN));
    let (hosts, counts) = run_text(&url);
    assert_eq!(hosts, ["c.evil.test"]);
    assert_eq!(counts.url_host_unread, 0);
    Ok(())
}


#[test]
fn the_control_url_lists_its_host_and_is_not_flagged() -> Result<(), Box<dyn std::error::Error>> {
    let (hosts, counts) = run_text(&control_url());
    assert_eq!(hosts, ["long.evil.test"]);
    assert_eq!(counts.url_host_unread, 0);
    Ok(())
}


#[test]
fn a_long_data_url_is_not_flagged() -> Result<(), Box<dyn std::error::Error>> {
    let (hosts, counts) = run_text(&format!("data:image/png;base64,{}", "A".repeat(PAD)));
    assert!(hosts.is_empty());
    assert_eq!(counts.url_host_unread, 0);
    assert_eq!(counts.urls_refused, 1);
    Ok(())
}


#[test]
fn a_hostile_refusal_or_an_unparsable_short_url_is_not_flagged() -> Result<(), Box<dyn std::error::Error>> {
    let (hosts, counts) = run_text("https://[bad https://x\u{1b}y.test/a");
    assert!(hosts.is_empty());
    assert_eq!(counts.url_host_unread, 0);
    Ok(())
}


fn message(body: &str) -> Result<Triage, Box<dyn std::error::Error>> {
    let raw = format!("From: p@evil.test\r\nContent-Type: text/plain\r\n\r\n{body}\r\n");
    Ok(triage(raw.as_bytes(), &["mx.example.org".to_owned()], &ReporterPolicy::default())?)
}


#[test]
fn a_flagged_url_makes_the_verdict_uncertain_once_with_the_reason() -> Result<(), Box<dyn std::error::Error>> {
    let body = [
        control_url(),
        port_padding(),
        userinfo_padding(),
        slash_padding(),
        typed_slash_beyond_the_cut(),
    ]
    .join("\r\n");
    let record = message(&body)?;
    assert_eq!(record.counts.url_host_unread, FLAGGED_FORMS);
    assert!(record.original_uncertain);
    assert_eq!(record.uncertain_reasons, [UNREAD]);
    assert_eq!(record.refused_hosts, ["long.evil.test"]);
    Ok(())
}


const TWO_LEVELS: usize = 2;


#[test]
fn a_flagged_url_at_two_levels_names_the_reason_once() -> Result<(), Box<dyn std::error::Error>> {
    let flagged = port_padding();
    let inner = format!("From: q@evil.test\r\nContent-Type: text/plain\r\n\r\n{flagged}\r\n");
    let outer = format!(
        "From: p@evil.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n\
         --BND\r\nContent-Type: text/plain\r\n\r\n{flagged}\r\n\
         --BND\r\nContent-Type: message/rfc822\r\n\r\n{inner}\r\n--BND--\r\n"
    );
    let record = triage(outer.as_bytes(), &["mx.example.org".to_owned()], &ReporterPolicy::default())?;
    assert_eq!(record.counts.url_host_unread, TWO_LEVELS);
    assert_eq!(record.uncertain_reasons.iter().filter(|reason| reason.as_str() == UNREAD).count(), 1);
    Ok(())
}


#[test]
fn a_message_with_only_readable_urls_is_not_flagged() -> Result<(), Box<dyn std::error::Error>> {
    let clean = message("http://ok.test/")?;
    assert_eq!(clean.counts.url_host_unread, 0);
    assert!(!clean.uncertain_reasons.iter().any(|reason| reason == UNREAD));
    Ok(())
}
