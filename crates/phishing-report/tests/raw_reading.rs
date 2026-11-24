use cases::model::ObservableKind;
use phishing_report::model::{ReporterPolicy, Triage};
use phishing_report::observables::observables;
use phishing_report::triage::triage;


const DEPTH: usize = 5;


const NAMES: [&str; 4] = ["sol", "quest", "num", "bsol"];


fn run(raw: &str) -> Result<Triage, Box<dyn std::error::Error>> {
    Ok(triage(raw.as_bytes(), &["mx.example.org".to_owned()], &ReporterPolicy::default())?)
}


fn hosts(record: &Triage) -> Vec<String> {
    observables(record, &ReporterPolicy::default())
        .into_iter()
        .filter(|(kind, _)| *kind == ObservableKind::Domain)
        .map(|(_, value)| value)
        .collect()
}


fn wrap(inner: &str) -> String {
    format!("From: a@x.test\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: message/rfc822\r\n\r\n{inner}\r\n--B--\r\n")
}


fn plain(body: &str) -> String {
    format!("From: a@x.test\r\nContent-Type: text/plain\r\n\r\n{body}\r\n")
}


fn reasons(record: &Triage, wanted: &str) -> bool {
    record.uncertain_reasons.iter().any(|reason| reason == wanted)
}


#[test]
fn an_entity_ended_authority_lists_the_raw_host_in_plain_text_and_nested() -> Result<(), Box<dyn std::error::Error>> {
    let found = NAMES.iter().try_fold(0, |count, name| -> Result<usize, Box<dyn std::error::Error>> {
        let body = format!("Click https://good.test&{name};@evil.test/login now");
        let direct = run(&plain(&body))?;
        let nested = run(&wrap(&plain(&body)))?;
        assert!(hosts(&direct).contains(&"evil.test".to_owned()), "direct {name}: {:?}", hosts(&direct));
        assert!(hosts(&nested).contains(&"evil.test".to_owned()), "nested {name}: {:?}", hosts(&nested));
        Ok(count + 1)
    })?;
    assert_eq!(found, NAMES.len());
    Ok(())
}


#[test]
fn a_link_only_at_level_four_names_the_nesting_cut() -> Result<(), Box<dyn std::error::Error>> {
    let deepest = plain("see https://evil.test/x");
    let text = (0..DEPTH).fold(deepest, |inner, _| wrap(&inner));
    let record = run(&text)?;
    assert!(record.original_uncertain);
    assert!(reasons(&record, "nesting_cut"), "{:?}", record.uncertain_reasons);
    Ok(())
}


#[test]
fn a_link_only_in_a_second_attached_message_names_the_unopened_one() -> Result<(), Box<dyn std::error::Error>> {
    let first = plain("one");
    let second = plain("see https://evil.test/x");
    let head = "From: a@x.test\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n";
    let part = "--B\r\nContent-Type: message/rfc822\r\n\r\n";
    let text = format!("{head}{part}{first}\r\n{part}{second}\r\n--B--\r\n");
    let record = run(&text)?;
    assert!(record.original_uncertain);
    assert!(reasons(&record, "messages_unopened"), "{:?}", record.uncertain_reasons);
    Ok(())
}
