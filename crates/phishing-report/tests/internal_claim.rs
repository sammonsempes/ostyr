use cases::model::ObservableKind;
use phishing_report::error::TriageError;
use phishing_report::limits::{Limits, MAX_FROM_ADDRESSES};
use phishing_report::model::{ReporterPolicy, Triage};
use phishing_report::observables::observables;
use phishing_report::policy::{check_policy, is_strict_domain};
use phishing_report::triage::{triage, triage_with};


const PASS_CORP: &str = "Authentication-Results: mx.corp.test; dmarc=pass header.from=corp.test";


const FORWARD_HEADERS: [&str; 2] = [PASS_CORP, "From: employee@corp.test"];


const MANY_ADDRESSES: usize = 40;


const SMALL_HEADER_COUNT: usize = 3;


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


fn forward(headers: &[&str], attachment: Option<&str>) -> String {
    let mut all = headers.to_vec();
    all.push("MIME-Version: 1.0");
    all.push("Content-Type: multipart/mixed; boundary=\"OUT\"");
    let mut text = "--OUT\r\nContent-Type: text/plain\r\n\r\nfyi\r\n".to_owned();
    attachment
        .iter()
        .for_each(|message| text.push_str(&format!("--OUT\r\nContent-Type: message/rfc822\r\n\r\n{message}\r\n")));
    text.push_str("--OUT--\r\n");
    mail(&all, &text)
}


fn spoofed(auth: &str, from: &str) -> Result<Triage, TriageError> {
    run(&mail(&[auth, from, "Subject: Reset"], "x"))
}


fn assert_claimed_unauthenticated(record: &Triage) {
    assert_eq!(record.original_level, Some(0));
    assert!(record.internal_claimed);
    assert!(record.original_uncertain);
    assert!(record.uncertain_reasons.iter().any(|reason| reason == "internal_unauthenticated"));
}


#[test]
fn a_spoofed_employee_at_level_zero_is_a_claim_never_an_identity() -> Result<(), Box<dyn std::error::Error>> {
    let failing = "Authentication-Results: mx.corp.test; dmarc=fail header.from=corp.test";
    let employee = spoofed(failing, "From: emp@corp.test")?;
    assert_claimed_unauthenticated(&employee);
    assert_eq!(employee.reporter, "dmarc_fail");
    assert_eq!(employee.counts.internal_claimed, 1);
    let none = run(&mail(&["From: emp@corp.test"], "x"))?;
    assert_claimed_unauthenticated(&none);
    let upper = run(&mail(&["From: ceo@CORP.TEST"], "x"))?;
    assert_claimed_unauthenticated(&upper);
    Ok(())
}


#[test]
fn a_group_or_a_list_naming_an_internal_domain_is_a_claim() -> Result<(), Box<dyn std::error::Error>> {
    let pass_evil = "Authentication-Results: mx.corp.test; dmarc=pass header.from=evil.test";
    let group = spoofed(pass_evil, "From: Team: phisher@evil.test; Other: ceo@corp.test;")?;
    assert_eq!(group.reporter, "from_ambiguous");
    assert_claimed_unauthenticated(&group);
    let list = run(&mail(&["From: phisher@evil.test, ceo@corp.test"], "x"))?;
    assert_claimed_unauthenticated(&list);
    let glued = run(&mail(&["From: <phisher@evil.test> ceo@corp.test"], "x"))?;
    assert_claimed_unauthenticated(&glued);
    assert!(glued.uncertain_reasons.iter().any(|reason| reason == "from_unparsed"));
    Ok(())
}


#[test]
fn the_claim_reads_every_raw_address_past_the_cap() -> Result<(), Box<dyn std::error::Error>> {
    let mut list: Vec<String> = (0..MANY_ADDRESSES).map(|i| format!("u{i}@evil.test")).collect();
    list.push("ceo@corp.test".to_owned());
    let crowd = run(&mail(&[&format!("From: {}", list.join(", "))], "x"))?;
    assert_eq!(crowd.senders.len(), MAX_FROM_ADDRESSES);
    assert!(!crowd.senders.iter().any(|address| address == "ceo@corp.test"));
    assert_claimed_unauthenticated(&crowd);
    Ok(())
}


#[test]
fn a_trailing_dot_still_claims_but_is_never_plain() -> Result<(), Box<dyn std::error::Error>> {
    let dotted = run(&mail(&["From: ceo@corp.test."], "x"))?;
    assert_claimed_unauthenticated(&dotted);
    assert!(dotted.uncertain_reasons.iter().any(|reason| reason == "from_unparsed"));
    let single = run(&mail(&["From: ceo@corp"], "x"))?;
    assert_eq!(single.reporter, "from_ambiguous");
    assert!(single.uncertain_reasons.iter().any(|reason| reason == "from_unparsed"));
    assert!(!single.internal_claimed);
    let other = run(&mail(&["From: ceo@evil.test."], "x"))?;
    assert_eq!(other.reporter, "from_ambiguous");
    assert!(other.uncertain_reasons.iter().any(|reason| reason == "from_unparsed"));
    assert!(!other.internal_claimed);
    assert!(is_strict_domain("corp.test"));
    assert!(!is_strict_domain("corp.test."));
    assert!(!is_strict_domain("corp"));
    Ok(())
}


#[test]
fn a_single_label_internal_domain_is_a_refused_policy() -> Result<(), Box<dyn std::error::Error>> {
    let single = ReporterPolicy {
        internal_domains: vec!["corp".to_owned()],
    };
    assert_eq!(check_policy(&single), Err(TriageError::PolicyRefused));
    assert_eq!(triage(b"From: a@b.test\r\n\r\nx", &[], &single), Err(TriageError::PolicyRefused));
    Ok(())
}


#[test]
fn a_real_internal_sender_is_the_forward_and_an_attached_internal_from_is_a_claim() -> Result<(), Box<dyn std::error::Error>> {
    let inline = run(&forward(&FORWARD_HEADERS, None))?;
    assert_eq!(inline.reporter, "forward");
    assert_eq!(inline.auth.reason.as_deref(), Some("inline_forward"));
    assert!(!inline.internal_claimed);
    let attached = run(&forward(&FORWARD_HEADERS, Some(&mail(&["From: ceo@corp.test", "Subject: x"], "y"))))?;
    assert_eq!(attached.reporter, "forward");
    assert_eq!(attached.original_level, Some(1));
    assert!(attached.internal_claimed);
    assert_eq!(attached.uncertain_reasons, ["attached_claim"]);
    Ok(())
}


#[test]
fn a_header_level_cut_by_the_limit_is_unparsed() -> Result<(), Box<dyn std::error::Error>> {
    let text = mail(&["From: ok@evil.test", "Subject: x", "X-A: 1", "From: ceo@corp.test"], "y");
    let small = Limits {
        headers: SMALL_HEADER_COUNT,
        ..Limits::default()
    };
    let cut = triage_with(text.as_bytes(), &ids(), &policy(), &small)?;
    assert_eq!(cut.reporter, "external");
    assert_eq!(cut.uncertain_reasons, ["from_unparsed"]);
    assert!(!cut.internal_claimed);
    let whole = triage_with(text.as_bytes(), &ids(), &policy(), &Limits::default())?;
    assert_claimed_unauthenticated(&whole);
    Ok(())
}


#[test]
fn an_unparsed_address_is_an_email_observable_only() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&mail(&["From: <phisher@evil.test> ceo@corp.test"], "x"))?;
    let found = observables(&record, &policy());
    assert!(found.iter().any(|(kind, _)| *kind == ObservableKind::Email));
    assert!(!found.iter().any(|(kind, _)| *kind == ObservableKind::Domain));
    let plain = observables(&run(&mail(&["From: a@evil.test"], "x"))?, &policy());
    assert!(plain.contains(&(ObservableKind::Domain, "evil.test".to_owned())));
    Ok(())
}
