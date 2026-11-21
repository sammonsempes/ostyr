use cases::model::ObservableKind;
use phishing_report::error::TriageError;
use phishing_report::limits::Limits;
use phishing_report::model::{ReporterPolicy, Triage};
use phishing_report::observables::observables;
use phishing_report::triage::{triage, triage_with};


const FAIL_CORP: &str = "Authentication-Results: mx.corp.test; dmarc=fail header.from=evil.test";


const PASS_CORP: &str = "Authentication-Results: mx.corp.test; dmarc=pass header.from=corp.test";


const SMALL_HEADER_BYTES: usize = 64;


fn policy() -> ReporterPolicy {
    ReporterPolicy {
        internal_domains: vec!["corp.test".to_owned()],
    }
}


fn ids() -> Vec<String> {
    vec!["mx.corp.test".to_owned()]
}


fn mail(headers: &[&str], body: &str) -> String {
    format!("{}\r\n\r\n{body}", headers.join("\r\n"))
}


fn with_return_path(value: &str) -> Result<Triage, TriageError> {
    let path = format!("Return-Path: {value}");
    let text = mail(&[FAIL_CORP, "From: phisher@evil.test", &path, "Subject: s"], "x");
    triage(text.as_bytes(), &ids(), &policy())
}


fn has_reason(record: &Triage, reason: &str) -> bool {
    record.uncertain_reasons.iter().any(|found| found == reason)
}


#[test]
fn an_internal_return_path_is_a_claim_and_never_a_domain_observable() -> Result<(), Box<dyn std::error::Error>> {
    let record = with_return_path("<ceo@corp.test>")?;
    assert!(record.internal_claimed);
    assert_eq!(record.counts.internal_claimed, 1);
    assert!(has_reason(&record, "internal_unauthenticated"));
    assert_eq!(record.reporter, "external");
    let found = observables(&record, &policy());
    assert!(found.contains(&(ObservableKind::Email, "ceo@corp.test".to_owned())));
    assert!(found.contains(&(ObservableKind::Domain, "evil.test".to_owned())));
    assert!(!found.contains(&(ObservableKind::Domain, "corp.test".to_owned())));
    Ok(())
}


#[test]
fn every_odd_form_of_an_internal_return_path_claims() -> Result<(), Box<dyn std::error::Error>> {
    [
        "<a@evil.test> <ceo@corp.test>",
        "ceo@corp.test (x)",
        "< ceo @ corp.test >",
        "<ceo@corp.test.>",
    ]
    .iter()
    .try_for_each(|value| -> Result<(), TriageError> {
        assert!(with_return_path(value)?.internal_claimed, "{value}");
        Ok(())
    })?;
    Ok(())
}


#[test]
fn an_external_empty_or_null_return_path_claims_nothing() -> Result<(), Box<dyn std::error::Error>> {
    ["<a@evil.test>", "<>", ""].iter().try_for_each(|value| -> Result<(), TriageError> {
        let record = with_return_path(value)?;
        assert!(!record.internal_claimed, "{value}");
        assert!(!has_reason(&record, "internal_unauthenticated"));
        Ok(())
    })?;
    Ok(())
}


#[test]
fn an_oversized_first_return_path_does_not_hide_an_internal_second_one() -> Result<(), Box<dyn std::error::Error>> {
    let big = format!("Return-Path: <{}@evil.test>", "a".repeat(SMALL_HEADER_BYTES));
    let text = mail(&[FAIL_CORP, "From: phisher@evil.test", &big, "Return-Path: <ceo@corp.test>"], "x");
    let limits = Limits {
        header_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    let record = triage_with(text.as_bytes(), &ids(), &policy(), &limits)?;
    assert!(record.internal_claimed);
    let oversized_alone = mail(&[FAIL_CORP, "From: phisher@evil.test", &big], "x");
    assert!(!triage_with(oversized_alone.as_bytes(), &ids(), &policy(), &limits)?.internal_claimed);
    Ok(())
}


#[test]
fn an_attached_original_with_an_internal_return_path_is_claimed() -> Result<(), Box<dyn std::error::Error>> {
    let inner = mail(&["From: phisher@evil.test", "Return-Path: <ceo@corp.test>", "Subject: s"], "x");
    let outer = format!(
        "{PASS_CORP}\r\nFrom: employee@corp.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"OUT\"\r\n\r\n\
         --OUT\r\nContent-Type: text/plain\r\n\r\nfyi\r\n--OUT\r\nContent-Type: message/rfc822\r\n\r\n{inner}\r\n--OUT--\r\n"
    );
    let record = triage(outer.as_bytes(), &ids(), &policy())?;
    assert_eq!(record.reporter, "forward");
    assert!(record.internal_claimed);
    assert!(has_reason(&record, "attached_claim"));
    Ok(())
}


#[test]
fn a_spoofed_internal_from_gives_no_internal_domain_observable() -> Result<(), Box<dyn std::error::Error>> {
    let text = mail(&[FAIL_CORP, "From: emp@corp.test", "Subject: s"], "x");
    let record = triage(text.as_bytes(), &ids(), &policy())?;
    let found = observables(&record, &policy());
    assert!(found.contains(&(ObservableKind::Email, "emp@corp.test".to_owned())));
    assert!(!found.iter().any(|(kind, value)| *kind == ObservableKind::Domain && value == "corp.test"));
    Ok(())
}


#[test]
fn a_genuine_forward_with_an_internal_return_path_stays_a_forward() -> Result<(), Box<dyn std::error::Error>> {
    let text = mail(
        &[PASS_CORP, "From: employee@corp.test", "Return-Path: <employee@corp.test>", "Subject: fyi"],
        "x",
    );
    let record = triage(text.as_bytes(), &ids(), &policy())?;
    assert_eq!(record.reporter, "forward");
    assert!(!has_reason(&record, "internal_unauthenticated"));
    Ok(())
}
