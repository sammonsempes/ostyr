use cases::model::ObservableKind;
use phishing_report::model::{ReporterPolicy, Triage};
use phishing_report::observables::observables;
use phishing_report::triage::triage;


const BASE64_BODY: &str = "aHR0cHM6Ly9wbGFpbi5ldmlsLnRlc3QveA==";


fn run(raw: &str) -> Result<Triage, Box<dyn std::error::Error>> {
    Ok(triage(raw.as_bytes(), &["mx.example.org".to_owned()], &ReporterPolicy::default())?)
}


fn mail(content_type: &str) -> String {
    format!("From: a@x.test\r\nMIME-Version: 1.0\r\nContent-Type: {content_type}\r\nContent-Transfer-Encoding: base64\r\n\r\n{BASE64_BODY}\r\n")
}


fn reasons(content_type: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(run(&mail(content_type))?.uncertain_reasons)
}


#[test]
fn an_undecodable_charset_names_the_record_uncertain() -> Result<(), Box<dyn std::error::Error>> {
    ["utf-32", "ibm037", "UTF-32LE"].iter().try_for_each(|label| {
        let record = run(&mail(&format!("text/plain; charset={label}")))?;
        assert_eq!(record.uncertain_reasons, ["charset_undecoded"], "{label}");
        assert_eq!(record.counts.charset_undecoded, 1);
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert_eq!(reasons("text/html; charset=\"ibm037\"")?, ["charset_undecoded"]);
    Ok(())
}


#[test]
fn a_decodable_or_absent_charset_is_not_flagged() -> Result<(), Box<dyn std::error::Error>> {
    ["utf-8", "UTF8", "us-ascii", "utf-16", "utf-7", "iso-2022-jp", "shift_jis", "gb18030"]
        .iter()
        .try_for_each(|label| {
            assert!(reasons(&format!("text/plain; charset={label}"))?.is_empty(), "{label}");
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
    assert!(reasons("text/plain")?.is_empty());
    let record = run(&mail("text/plain; charset=utf-8"))?;
    let hosts: Vec<String> = observables(&record, &ReporterPolicy::default())
        .into_iter()
        .filter(|(kind, _)| *kind == ObservableKind::Domain)
        .map(|(_, value)| value)
        .collect();
    assert!(hosts.iter().any(|host| host == "plain.evil.test"));
    Ok(())
}


#[test]
fn a_non_text_part_with_an_undecodable_charset_is_not_this_rules_business() -> Result<(), Box<dyn std::error::Error>> {
    assert!(reasons("application/octet-stream; charset=utf-32")?.is_empty());
    Ok(())
}
