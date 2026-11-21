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
fn an_attached_original_is_always_an_attached_claim() -> Result<(), Box<dyn std::error::Error>> {
    let decoy = attached(&outside("From: noreply@microsoft.com"));
    let with_url = run(&forward(&FORWARD_HEADERS, "see https://evil.test/steal", std::slice::from_ref(&decoy)))?;
    let with_pdf = run(&forward(
        &FORWARD_HEADERS,
        "fyi",
        &[
            decoy.clone(),
            "Content-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\n\r\nJVBER".to_owned(),
        ],
    ))?;
    let two = run(&forward(&FORWARD_HEADERS, "fyi", &[decoy.clone(), decoy.clone()]))?;
    let empty = run(&forward(&FORWARD_HEADERS, "", std::slice::from_ref(&decoy)))?;
    let clean = with_original("From: security@bank.test")?;
    let big = Limits {
        part_bytes: SMALL_PART_BYTES,
        ..Limits::default()
    };
    let unread = triage_with(
        forward(&FORWARD_HEADERS, &"x".repeat(BIG_TEXT), &[decoy]).as_bytes(),
        &ids(),
        &policy(),
        &big,
    )?;
    [with_url, with_pdf, two, empty, clean, unread].iter().for_each(|record| {
        assert_eq!(record.original_level, Some(1));
        assert!(record.original_uncertain);
        assert_eq!(record.uncertain_reasons, ["attached_claim"]);
        assert_eq!(record.counts.original_uncertain, 1);
        assert_eq!(record.original_source.as_deref(), Some("attached"));
    });
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
    assert!(dotted.internal_claimed);
    assert_eq!(dotted.counts.internal_claimed, 1);
    let mut list: Vec<String> = (0..MANY_ADDRESSES).map(|i| format!("u{i}@evil.test")).collect();
    list.push("ceo@corp.test".to_owned());
    let crowd = with_original(&format!("From: {}", list.join(", ")))?;
    assert_eq!(crowd.senders.len(), MAX_FROM_ADDRESSES);
    assert!(!crowd.senders.iter().any(|address| address == "ceo@corp.test"));
    assert!(crowd.internal_claimed);
    let subdomain = with_original("From: ceo@mail.corp.test")?;
    assert!(!subdomain.internal_claimed);
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
    assert_eq!(fine.uncertain_reasons, ["attached_claim"]);
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
    let outsider = run(&outside("From: security@bank.test"))?;
    assert!(!outsider.original_uncertain);
    Ok(())
}


const SMALL_PART_BYTES: usize = 300;


const BIG_TEXT: usize = 500;


fn run_limited(text: &str, limits: &Limits) -> Result<Triage, TriageError> {
    triage_with(text.as_bytes(), &ids(), &policy(), limits)
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
    assert_eq!(record.uncertain_reasons, ["attached_claim", "from_unparsed"]);
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


#[test]
fn an_attached_message_without_a_from_is_still_an_attached_claim() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&forward(&FORWARD_HEADERS, "fyi", &[attached(&mail(&["Subject: only a subject"], "x"))]))?;
    assert_eq!(record.original_level, Some(1));
    assert_eq!(record.sender, None);
    assert_eq!(record.uncertain_reasons, ["attached_claim"]);
    assert_eq!(record.counts.original_uncertain, 1);
    Ok(())
}


#[test]
fn an_address_with_two_at_signs_is_unparsed_and_a_domain_mismatch_is_not_internal() -> Result<(), Box<dyn std::error::Error>> {
    let evil_pass = "Authentication-Results: mx.corp.test; dmarc=pass header.from=evil.test";
    let record = run(&mail(&[evil_pass, "From: <phisher@evil.test> ceo@corp.test"], "x"))?;
    assert_eq!(record.reporter, "dmarc_domain_mismatch");
    assert_eq!(record.original_level, Some(0));
    assert!(record.original_uncertain);
    assert_eq!(
        record.uncertain_reasons,
        ["dmarc_domain_mismatch", "internal_unauthenticated", "from_unparsed"]
    );
    assert!(record.internal_claimed);
    assert_eq!(record.counts.internal_claimed, 1);
    assert_eq!(record.counts.original_uncertain, 1);
    let two = with_original("From: a@b@evil.test")?;
    assert!(two.uncertain_reasons.iter().any(|reason| reason == "from_unparsed"));
    let empty_local = with_original("From: <@evil.test>")?;
    assert!(empty_local.uncertain_reasons.iter().any(|reason| reason == "from_unparsed"));
    Ok(())
}


#[test]
fn a_display_name_holding_an_address_is_judged_on_the_real_address() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&outside("From: \"ceo@corp.test\" <phisher@evil.test>"))?;
    assert_eq!(record.reporter, "external");
    assert!(!record.original_uncertain);
    assert!(!record.internal_claimed);
    assert_eq!(record.sender.as_deref(), Some("phisher@evil.test"));
    Ok(())
}
