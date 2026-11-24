use cases::model::ObservableKind;
use phishing_report::model::{ReporterPolicy, Triage};
use phishing_report::observables::observables;
use phishing_report::triage::triage;


const BODY_COUNT: usize = 5;


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


fn mail_with_body(content_type: &str, body: &[u8]) -> String {
    let encoded = data_encoding::BASE64.encode(body);
    format!("From: a@x.test\r\nMIME-Version: 1.0\r\nContent-Type: {content_type}\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n")
}


#[test]
fn a_body_holding_a_replacement_nul_or_escape_is_flagged_under_any_label() -> Result<(), Box<dyn std::error::Error>> {
    let bodies: [&[u8]; BODY_COUNT] = [
        b"https://\x82\x85\x82\x96\x82\x89\x82\x8c.test/x",
        b"https://pl\x1b(Bain.evil.test/x",
        b"h\0t\0t\0p\0s\0:\0/\0/\0e\0.\0t\0",
        b"\xff\xfeh\0t\0t\0p\0s\0",
        b"https://a.test/\xc3\x28",
    ];
    ["shift_jis", "gb18030", "iso-2022-jp", "utf-8"].iter().try_for_each(|label| {
        bodies.iter().try_for_each(|body| {
            let record = run(&mail_with_body(&format!("text/plain; charset={label}"), body))?;
            assert_eq!(record.uncertain_reasons, ["charset_undecoded"], "{label} {body:?}");
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    })?;
    let record = run(&mail_with_body("text/plain", b"h\0t\0t\0p\0"))?;
    assert_eq!(record.uncertain_reasons, ["charset_undecoded"]);
    let clean = run(&mail_with_body("text/plain; charset=shift_jis", b"https://plain.evil.test/x"))?;
    assert!(clean.uncertain_reasons.is_empty());
    Ok(())
}


#[test]
fn a_duplicated_charset_parameter_is_flagged() -> Result<(), Box<dyn std::error::Error>> {
    [
        "text/plain; charset=utf-8; charset=utf-32",
        "text/plain; charset=utf-8; CHARSET=us-ascii",
        "text/plain; charset=utf-8; charset*=utf-8''utf-32",
    ]
    .iter()
    .try_for_each(|content_type| {
        assert_eq!(reasons(content_type)?, ["charset_undecoded"], "{content_type}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert!(reasons("text/plain; charset=utf-8; format=flowed")?.is_empty());
    Ok(())
}
