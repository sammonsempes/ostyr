use cases::model::ObservableKind;
use phishing_report::auth::{parse_header, verdicts_with_from};
use phishing_report::error::TriageError;
use phishing_report::limits::{Limits, MAX_FROM_ADDRESSES};
use phishing_report::model::{Counts, ReporterPolicy, Triage};
use phishing_report::observables::observables;
use phishing_report::policy::{check_policy, is_internal, is_ldh_domain, reporter_policy, MAX_INTERNAL_DOMAINS};
use phishing_report::triage::{triage, triage_with};


const PASS_CORP: &str = "Authentication-Results: mx.corp.test; dmarc=pass header.from=corp.test";


const THREE: usize = 3;


const LONG_LABEL: usize = 64;


const LONG_NAME: usize = 130;


const OVERSIZE_HEADER: usize = 400;


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


fn forward(headers: &[&str], attached: &[&str]) -> String {
    let mut all = headers.to_vec();
    all.push("MIME-Version: 1.0");
    all.push("Content-Type: multipart/mixed; boundary=\"OUT\"");
    let mut body = "--OUT\r\nContent-Type: text/html\r\n\r\n<a href=\"https://evil.test/steal\">x</a>\r\n".to_owned();
    attached.iter().for_each(|message| {
        body.push_str(&format!("--OUT\r\nContent-Type: message/rfc822\r\n\r\n{message}\r\n"));
    });
    body.push_str("--OUT--\r\n");
    mail(&all, &body)
}


fn decoy() -> String {
    mail(
        &[
            "Authentication-Results: mx.corp.test; dmarc=pass header.from=corp.test",
            "From: ceo@corp.test",
            "Subject: Q3 plan",
        ],
        "see http://decoy.test/",
    )
}


fn phish() -> String {
    mail(&["From: security@bank.test", "Return-Path: <p@evil.test>", "Subject: Your account"], "x")
}


fn urls(record: &Triage) -> Vec<(usize, &str)> {
    record.urls.iter().map(|hit| (hit.level, hit.url.as_str())).collect()
}


#[test]
fn a_real_forward_from_an_internal_reporter_has_level_one_as_original() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&forward(&[PASS_CORP, "From: employee@corp.test"], &[&phish()]))?;
    assert_eq!(record.reporter, "forward");
    assert_eq!(record.original_level, Some(1));
    assert_eq!(record.sender.as_deref(), Some("security@bank.test"));
    assert_eq!(record.auth.reason.as_deref(), Some("attached_original"));
    assert_eq!(record.reporter_auth.as_ref().map(|auth| auth.dmarc.as_str()), Some("pass"));
    assert!(!record.internal_claimed);
    assert_eq!(record.counts.reporter_unverified, 0);
    assert_eq!(urls(&record), [(0, "https://evil.test/steal")]);
    Ok(())
}


#[test]
fn a_phish_with_its_own_decoy_is_the_original_with_reporter_external() -> Result<(), Box<dyn std::error::Error>> {
    let text = forward(
        &[
            "Authentication-Results: mx.corp.test; dmarc=fail header.from=bank.test",
            "From: security@bank.test",
            "Subject: Your account",
        ],
        &[&decoy()],
    );
    let record = run(&text)?;
    assert_eq!(record.reporter, "external");
    assert_eq!(record.original_level, Some(0));
    assert_eq!(record.sender.as_deref(), Some("security@bank.test"));
    assert_eq!(record.auth.dmarc, "fail");
    assert_eq!(record.reporter_auth, None);
    assert!(!record.internal_claimed);
    assert_eq!(record.counts.auth_nested_ignored, 1);
    assert_eq!(urls(&record), [(0, "https://evil.test/steal"), (1, "http://decoy.test/")]);
    Ok(())
}


#[test]
fn an_inline_forward_with_a_decoy_makes_the_internal_original_loud() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&forward(&[PASS_CORP, "From: employee@corp.test"], &[&decoy()]))?;
    assert_eq!(record.original_level, Some(1));
    assert_eq!(record.sender.as_deref(), Some("ceo@corp.test"));
    assert!(record.internal_claimed);
    assert_eq!(record.counts.internal_claimed, 1);
    assert_eq!(record.auth.dmarc, "unknown");
    assert!(urls(&record).contains(&(0, "https://evil.test/steal")));
    Ok(())
}


#[test]
fn an_inline_forward_with_nothing_attached_has_no_original_headers() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&forward(
        &[PASS_CORP, "From: employee@corp.test", "Subject: FW: x", "Return-Path: <e@corp.test>"],
        &[],
    ))?;
    assert_eq!(record.reporter, "forward");
    assert_eq!(record.original_level, None);
    assert_eq!(record.sender, None);
    assert_eq!(record.return_path, None);
    assert_eq!(record.subject, None);
    assert_eq!(record.auth.reason.as_deref(), Some("inline_forward"));
    assert!(record.reporter_auth.is_some());
    assert!(!record.internal_claimed);
    assert_eq!(urls(&record), [(0, "https://evil.test/steal")]);
    Ok(())
}


#[test]
fn several_from_addresses_are_ambiguous_and_all_listed() -> Result<(), Box<dyn std::error::Error>> {
    let multi = forward(
        &[
            "Authentication-Results: mx.corp.test; dmarc=pass header.from=evil.test",
            "From: x@evil.test, ceo@corp.test",
        ],
        &[],
    );
    let record = run(&multi)?;
    assert_eq!(record.reporter, "from_ambiguous");
    assert_eq!(record.original_level, Some(0));
    assert_eq!(record.senders, ["x@evil.test", "ceo@corp.test"]);
    assert!(record.internal_claimed);
    let twice = run(&forward(&[PASS_CORP, "From: a@corp.test", "From: b@evil.test"], &[]))?;
    assert_eq!(twice.reporter, "from_ambiguous");
    assert_eq!(twice.senders, ["a@corp.test", "b@evil.test"]);
    let group = run(&forward(&[PASS_CORP, "From: team: a@corp.test;"], &[]))?;
    assert_eq!(group.reporter, "from_ambiguous");
    assert_eq!(group.senders, ["a@corp.test"]);
    let none = run(&forward(&[PASS_CORP], &[]))?;
    assert_eq!(none.reporter, "from_ambiguous");
    assert!(none.senders.is_empty());
    let empty = run(&forward(&[PASS_CORP, "From:"], &[]))?;
    assert_eq!(empty.reporter, "from_ambiguous");
    assert!(empty.senders.is_empty());
    Ok(())
}


#[test]
fn a_pass_for_another_domain_is_a_mismatch_and_counted() -> Result<(), Box<dyn std::error::Error>> {
    let wrong = "Authentication-Results: mx.corp.test; dmarc=pass header.from=evil.test";
    let record = run(&forward(&[wrong, "From: employee@corp.test"], &[&phish()]))?;
    assert_eq!(record.reporter, "dmarc_domain_mismatch");
    assert_eq!(record.original_level, Some(0));
    assert_eq!(record.counts.reporter_unverified, 1);
    let second = "Authentication-Results: mx.corp.test; dmarc=pass header.from=evil.test";
    let mixed = run(&forward(&[PASS_CORP, second, "From: employee@corp.test"], &[]))?;
    assert_eq!(mixed.reporter, "dmarc_domain_mismatch");
    let missing = "Authentication-Results: mx.corp.test; dmarc=pass";
    let absent = run(&forward(&[missing, "From: employee@corp.test"], &[]))?;
    assert_eq!(absent.reporter, "dmarc_domain_mismatch");
    let quoted = "Authentication-Results: mx.corp.test; dmarc=pass header.from=\"CORP.test\"";
    let fine = run(&forward(&[quoted, "From: Employee@Corp.Test"], &[]))?;
    assert_eq!(fine.reporter, "forward");
    Ok(())
}


#[test]
fn an_internal_sender_without_a_pass_is_unverified() -> Result<(), Box<dyn std::error::Error>> {
    let none = "Authentication-Results: mx.corp.test; dmarc=none";
    let record = run(&forward(&[none, "From: employee@corp.test"], &[&phish()]))?;
    assert_eq!(record.reporter, "dmarc_none");
    assert_eq!(record.original_level, Some(0));
    assert_eq!(record.counts.reporter_unverified, 1);
    let bare = run(&forward(&["From: employee@corp.test"], &[]))?;
    assert_eq!(bare.reporter, "dmarc_unknown");
    Ok(())
}


#[test]
fn a_subdomain_of_a_listed_domain_is_external() -> Result<(), Box<dyn std::error::Error>> {
    let sub = "Authentication-Results: mx.corp.test; dmarc=pass header.from=sub.corp.test";
    let record = run(&forward(&[sub, "From: employee@sub.corp.test"], &[&phish()]))?;
    assert_eq!(record.reporter, "external");
    assert_eq!(record.counts.reporter_unverified, 0);
    Ok(())
}


#[test]
fn a_forged_pass_inside_an_attached_message_is_never_trusted() -> Result<(), Box<dyn std::error::Error>> {
    let nested = forward(&["From: a@bank.test"], &[&decoy()]);
    let record = run(&forward(&[PASS_CORP, "From: employee@corp.test"], &[&nested]))?;
    assert_eq!(record.original_level, Some(1));
    assert_eq!(record.counts.auth_nested_ignored, 1);
    assert_eq!(record.levels.len(), THREE);
    assert!(record
        .levels
        .iter()
        .skip(1)
        .all(|level| level.auth.reason.as_deref() == Some("attached_original")));
    Ok(())
}


#[test]
fn every_from_address_is_listed_up_to_a_cap_and_the_rest_counted() -> Result<(), Box<dyn std::error::Error>> {
    let many: Vec<String> = (0..MAX_FROM_ADDRESSES + THREE).map(|i| format!("u{i}@evil.test")).collect();
    let header = format!("From: {}", many.join(", "));
    let record = run(&mail(&[&header], "x"))?;
    assert_eq!(record.senders.len(), MAX_FROM_ADDRESSES);
    assert_eq!(record.counts.addresses_refused, THREE);
    let long = format!("From: {}@evil.test", "a".repeat(OVERSIZE_HEADER));
    let limits = Limits {
        header_bytes: OVERSIZE_HEADER,
        ..Limits::default()
    };
    let big = triage_with(mail(&[&long], "x").as_bytes(), &ids(), &policy(), &limits)?;
    assert!(big.senders.is_empty());
    assert_eq!(big.counts.headers_skipped, 1);
    Ok(())
}


#[test]
fn the_senders_reach_the_observables() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&mail(&["From: a@evil.test, b@other.test"], "x"))?;
    let found = observables(&record, &policy());
    assert!(found.contains(&(ObservableKind::Email, "b@other.test".to_owned())));
    assert!(found.contains(&(ObservableKind::Domain, "other.test".to_owned())));
    Ok(())
}


#[test]
fn the_policy_is_checked_lowered_and_matched_exactly() -> Result<(), Box<dyn std::error::Error>> {
    let built = reporter_policy(&["Corp.Test".to_owned(), "xn--bcher-kva.example".to_owned()])?;
    assert_eq!(built.internal_domains, ["corp.test", "xn--bcher-kva.example"]);
    assert!(is_internal(&built, "CORP.test"));
    assert!(!is_internal(&built, "mail.corp.test"));
    let bad = [
        "",
        "corp.test.",
        "-x.test",
        "x-.test",
        "a..test",
        "caf\u{e9}.test",
        "a b.test",
        &"a".repeat(LONG_LABEL),
        &format!("{}.test", "a.".repeat(LONG_NAME)),
    ];
    bad.iter().for_each(|entry| {
        assert!(!is_ldh_domain(entry), "{entry}");
        assert_eq!(reporter_policy(&[(*entry).to_owned()]), Err(TriageError::PolicyRefused));
    });
    let crowd = vec!["a.test".to_owned(); MAX_INTERNAL_DOMAINS + 1];
    assert_eq!(reporter_policy(&crowd), Err(TriageError::PolicyRefused));
    assert_eq!(check_policy(&ReporterPolicy { internal_domains: crowd }), Err(TriageError::PolicyRefused));
    let refused = ReporterPolicy {
        internal_domains: vec!["-x".to_owned()],
    };
    assert_eq!(triage(b"From: a@b.test\r\n\r\nx", &[], &refused), Err(TriageError::PolicyRefused));
    Ok(())
}


#[test]
fn header_from_values_come_from_trusted_pass_results_only() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let texts = [
        Some("mx.corp.test; dmarc=pass header.from=a.test header.from=\"B.test\"; dmarc=pass; spf=pass header.from=c.test"),
        Some("other.test; dmarc=pass header.from=d.test"),
    ];
    let (verdict, from) = verdicts_with_from(&texts, &ids(), false, &mut counts);
    assert_eq!(verdict.dmarc, "pass");
    assert_eq!(from, [vec!["a.test".to_owned(), "b.test".to_owned()], Vec::<String>::new()]);
    let (oversized, none) = verdicts_with_from(&texts, &ids(), true, &mut counts);
    assert_eq!(oversized.reason.as_deref(), Some("oversized_header"));
    assert!(none.is_empty());
    let parsed = parse_header("mx.corp.test; dmarc=pass header.from=a.test; header.fro", &mut counts).ok_or("refused")?;
    assert_eq!(parsed.pass_from, [vec!["a.test".to_owned()]]);
    Ok(())
}
