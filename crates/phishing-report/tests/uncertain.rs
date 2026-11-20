use phishing_report::auth::parse_header;
use phishing_report::error::TriageError;
use phishing_report::limits::{Limits, MAX_FROM_ADDRESSES};
use phishing_report::model::{Counts, ReporterPolicy, Triage};
use phishing_report::triage::{triage, triage_with};


const PASS_CORP: &str = "Authentication-Results: mx.corp.test; dmarc=pass header.from=corp.test";


const FORWARD_HEADERS: [&str; 2] = [PASS_CORP, "From: employee@corp.test"];


const MANY_ADDRESSES: usize = 40;


const LONG_LOCAL: usize = 400;


const SMALL_HEADER_BYTES: usize = 200;


fn policy() -> ReporterPolicy {
    ReporterPolicy {
        internal_domains: vec!["corp.test".to_owned()],
    }
}


fn ids() -> Vec<String> {
    vec!["mx.corp.test".to_owned()]
}


fn run(text: &str) -> Result<Triage, TriageError> {
    triage(text.as_bytes(), &ids(), &policy())
}


fn mail(headers: &[&str], body: &str) -> String {
    format!("{}\r\n\r\n{body}", headers.join("\r\n"))
}


fn forward(headers: &[&str], body: &str, parts: &[String]) -> String {
    let mut all = headers.to_vec();
    all.push("MIME-Version: 1.0");
    all.push("Content-Type: multipart/mixed; boundary=\"OUT\"");
    let mut text = format!("--OUT\r\nContent-Type: text/plain\r\n\r\n{body}\r\n");
    parts.iter().for_each(|part| text.push_str(&format!("--OUT\r\n{part}\r\n")));
    text.push_str("--OUT--\r\n");
    mail(&all, &text)
}


fn attached(message: &str) -> String {
    format!("Content-Type: message/rfc822\r\n\r\n{message}")
}


fn outside(from: &str) -> String {
    mail(&[from, "Subject: Your account"], "no link")
}


fn with_original(from: &str) -> Result<Triage, TriageError> {
    run(&forward(&FORWARD_HEADERS, "fyi", &[attached(&outside(from))]))
}


#[test]
fn a_forward_with_its_own_url_next_to_the_attachment_is_uncertain() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&forward(
        &FORWARD_HEADERS,
        "see https://evil.test/steal",
        &[attached(&outside("From: noreply@microsoft.com"))],
    ))?;
    assert_eq!(record.original_level, Some(1));
    assert_eq!(record.sender.as_deref(), Some("noreply@microsoft.com"));
    assert!(record.original_uncertain);
    assert_eq!(record.uncertain_reasons, ["forward_has_own_content"]);
    assert_eq!(record.original_source.as_deref(), Some("attached"));
    assert_eq!(record.counts.original_uncertain, 1);
    assert!(!record.original_internal);
    Ok(())
}


#[test]
fn a_forward_with_its_own_attachment_or_a_second_message_is_uncertain() -> Result<(), Box<dyn std::error::Error>> {
    let first = attached(&outside("From: noreply@microsoft.com"));
    let pdf = "Content-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\n\r\nJVBER".to_owned();
    let with_pdf = run(&forward(&FORWARD_HEADERS, "fyi", &[first.clone(), pdf]))?;
    assert_eq!(with_pdf.uncertain_reasons, ["forward_has_own_content"]);
    let with_second = run(&forward(&FORWARD_HEADERS, "fyi", &[first.clone(), first]))?;
    assert_eq!(with_second.uncertain_reasons, ["forward_has_own_content"]);
    assert_eq!(with_second.counts.messages_unopened, 1);
    Ok(())
}


#[test]
fn a_clean_forward_as_attachment_is_not_uncertain() -> Result<(), Box<dyn std::error::Error>> {
    let record = with_original("From: security@bank.test")?;
    assert_eq!(record.original_level, Some(1));
    assert!(!record.original_uncertain);
    assert!(record.uncertain_reasons.is_empty());
    assert_eq!(record.counts.original_uncertain, 0);
    assert_eq!(record.original_source.as_deref(), Some("attached"));
    Ok(())
}


#[test]
fn the_reported_level_zero_and_an_inline_forward_have_their_own_source() -> Result<(), Box<dyn std::error::Error>> {
    let reported = run(&outside("From: security@bank.test"))?;
    assert_eq!(reported.original_source.as_deref(), Some("reported"));
    assert!(!reported.original_uncertain);
    let inline = run(&forward(&FORWARD_HEADERS, "fyi", &[]))?;
    assert_eq!(inline.original_source, None);
    assert!(!inline.original_uncertain);
    Ok(())
}


#[test]
fn a_quoted_header_from_holding_a_space_is_a_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let quoted = "Authentication-Results: mx.corp.test; dmarc=pass header.from=\"corp.test evil.test\"";
    let record = run(&forward(
        &[quoted, "From: employee@corp.test"],
        "fyi",
        &[attached(&outside("From: a@bank.test"))],
    ))?;
    assert_eq!(record.reporter, "dmarc_domain_mismatch");
    assert_eq!(record.original_level, Some(0));
    let mut counts = Counts::default();
    let parsed = parse_header("mx.corp.test; dmarc=pass header.from=\"a b\" header.d=x", &mut counts);
    assert_eq!(parsed.map(|header| header.pass_from), Some(vec![vec!["a b".to_owned()]]));
    Ok(())
}


#[test]
fn a_trailing_dot_decoy_or_an_address_beyond_the_cap_is_internal() -> Result<(), Box<dyn std::error::Error>> {
    let dotted = with_original("From: ceo@corp.test.")?;
    assert!(dotted.original_internal);
    assert_eq!(dotted.counts.original_internal, 1);
    let mut list: Vec<String> = (0..MANY_ADDRESSES).map(|i| format!("u{i}@evil.test")).collect();
    list.push("ceo@corp.test".to_owned());
    let crowd = with_original(&format!("From: {}", list.join(", ")))?;
    assert_eq!(crowd.senders.len(), MAX_FROM_ADDRESSES);
    assert!(!crowd.senders.iter().any(|address| address == "ceo@corp.test"));
    assert!(crowd.original_internal);
    let subdomain = with_original("From: ceo@mail.corp.test")?;
    assert!(!subdomain.original_internal);
    Ok(())
}


#[test]
fn a_from_that_cannot_be_judged_makes_the_original_uncertain() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        "From: CEO ceo@corp.test x",
        "From: ceo@corp.test>",
        "From: ceo corp.test",
        "From: <@evil.test:ceo@corp.test x>",
        "From: =?utf-8?q?ceo=40corp=2Etest?=",
    ];
    let reasons: Vec<Vec<String>> = cases
        .iter()
        .map(|from| with_original(from).map(|record| record.uncertain_reasons))
        .collect::<Result<_, _>>()?;
    assert!(reasons.iter().all(|found| found.iter().any(|reason| reason == "from_unparsed")));
    let fine = with_original("From: Ceo <ceo@corp.test>")?;
    assert!(fine.uncertain_reasons.is_empty());
    let level_zero = run(&mail(&["From: =?utf-8?q?ceo=40corp=2Etest?="], "x"))?;
    assert_eq!(level_zero.reporter, "from_ambiguous");
    assert_eq!(level_zero.uncertain_reasons, ["from_unparsed"]);
    let long = mail(&[&format!("From: {}@evil.test", "a".repeat(LONG_LOCAL))], "x");
    let small = Limits {
        header_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    let skipped = triage_with(long.as_bytes(), &ids(), &policy(), &small)?;
    assert_eq!(skipped.uncertain_reasons, ["from_unparsed"]);
    assert_eq!(skipped.counts.headers_skipped, 1);
    Ok(())
}


const SMALL_URL_BYTES: usize = 40;


const SMALL_PART_BYTES: usize = 300;


const BIG_TEXT: usize = 500;


fn run_limited(text: &str, limits: &Limits) -> Result<Triage, TriageError> {
    triage_with(text.as_bytes(), &ids(), &policy(), limits)
}


#[test]
fn a_refused_level_zero_url_makes_the_forward_uncertain() -> Result<(), Box<dyn std::error::Error>> {
    let decoy = attached(&outside("From: noreply@microsoft.com"));
    let small = Limits {
        url_bytes: SMALL_URL_BYTES,
        ..Limits::default()
    };
    let long = format!("see https://evil.test/{}", "a".repeat(SMALL_URL_BYTES));
    let too_long = run_limited(&forward(&FORWARD_HEADERS, &long, std::slice::from_ref(&decoy)), &small)?;
    assert!(too_long.urls.is_empty());
    assert_eq!(too_long.counts.urls_refused, 1);
    assert_eq!(too_long.uncertain_reasons, ["forward_has_own_content"]);
    let bidi = run(&forward(
        &FORWARD_HEADERS,
        "see https://evil.test/\u{202e}x",
        std::slice::from_ref(&decoy),
    ))?;
    assert_eq!(bidi.uncertain_reasons, ["forward_has_own_content"]);
    let bad_port = run(&forward(&FORWARD_HEADERS, "see https://evil.test:99999/x", std::slice::from_ref(&decoy)))?;
    assert_eq!(bad_port.uncertain_reasons, ["forward_has_own_content"]);
    let clean = run(&forward(&FORWARD_HEADERS, "fyi", &[decoy]))?;
    assert!(clean.uncertain_reasons.is_empty());
    Ok(())
}


#[test]
fn an_unread_level_zero_part_makes_the_forward_uncertain() -> Result<(), Box<dyn std::error::Error>> {
    let decoy = attached(&outside("From: noreply@microsoft.com"));
    let small = Limits {
        part_bytes: SMALL_PART_BYTES,
        ..Limits::default()
    };
    let record = run_limited(&forward(&FORWARD_HEADERS, &"x".repeat(BIG_TEXT), std::slice::from_ref(&decoy)), &small)?;
    assert_eq!(record.original_level, Some(1));
    assert!(record.counts.parts_skipped > 0);
    assert_eq!(record.uncertain_reasons, ["forward_content_unread"]);
    let fine = run_limited(&forward(&FORWARD_HEADERS, "fyi", &[decoy]), &small)?;
    assert!(fine.uncertain_reasons.is_empty());
    Ok(())
}


#[test]
fn an_oversized_second_from_of_the_original_is_unparsed() -> Result<(), Box<dyn std::error::Error>> {
    let big = format!("From: {}@corp.test", "a".repeat(LONG_LOCAL));
    let original = mail(&["From: noreply@microsoft.com", &big, "Subject: x"], "no link");
    let small = Limits {
        header_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    let record = run_limited(&forward(&FORWARD_HEADERS, "fyi", &[attached(&original)]), &small)?;
    assert_eq!(record.original_level, Some(1));
    assert_eq!(record.uncertain_reasons, ["from_unparsed"]);
    Ok(())
}


#[test]
fn only_one_pair_of_quotes_is_stripped_from_header_from() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let parsed = parse_header("mx.corp.test; dmarc=pass header.from=\"\"corp.test\"\"", &mut counts);
    assert_eq!(parsed.map(|header| header.pass_from), Some(vec![vec!["\"corp.test\"".to_owned()]]));
    let plain = parse_header("mx.corp.test; dmarc=pass header.from=\"corp.test\"", &mut counts);
    assert_eq!(plain.map(|header| header.pass_from), Some(vec![vec!["corp.test".to_owned()]]));
    Ok(())
}
