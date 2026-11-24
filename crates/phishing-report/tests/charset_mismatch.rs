use cases::model::ObservableKind;
use phishing_report::limits::Limits;
use phishing_report::model::{ReporterPolicy, Triage};
use phishing_report::observables::observables;
use phishing_report::triage::{triage, triage_with};


const TINY_PART: usize = 30;


const DIFFERING_CASES: usize = 2;


const ORDINARY_CASES: usize = 7;


fn mail_with(headers: &str, body: &[u8]) -> Vec<u8> {
    let encoded = data_encoding::BASE64.encode(body);
    format!("From: a@x.test\r\nMIME-Version: 1.0\r\n{headers}Content-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n").into_bytes()
}


fn run(label: &str, body: &[u8]) -> Result<Triage, Box<dyn std::error::Error>> {
    Ok(triage(
        &mail_with(&format!("Content-Type: text/plain; charset={label}\r\n"), body),
        &[],
        &ReporterPolicy::default(),
    )?)
}


fn domains(record: &Triage) -> Vec<String> {
    observables(record, &ReporterPolicy::default())
        .into_iter()
        .filter(|(kind, _)| *kind == ObservableKind::Domain)
        .map(|(_, value)| value)
        .collect()
}


fn host_of(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(url::Url::parse(url)?.host_str().ok_or("no host")?.to_owned())
}


fn bom_prefixed(url: &[u8]) -> Vec<u8> {
    [b"\xef\xbb\xbf".as_slice(), url].concat()
}


#[test]
fn a_utf_8_bom_under_a_label_that_hides_it_lists_the_host_and_flags() -> Result<(), Box<dyn std::error::Error>> {
    let body = bom_prefixed(b"https://hidden.evil.test/x");
    [
        "utf-16le",
        "utf-16be",
        "windows-1252",
        "iso-8859-1",
        "iso-8859-2",
        "iso-8859-15",
        "koi8-r",
        "macintosh",
    ]
    .iter()
    .try_for_each(|label| {
        let record = run(label, &body)?;
        let expected: &[&str] = if label.starts_with("utf-16") {
            &["charset_undecoded", "charset_mismatch"]
        } else {
            &["charset_mismatch"]
        };
        assert_eq!(record.uncertain_reasons, expected, "{label}");
        assert_eq!(record.counts.charset_mismatch, 1, "{label}");
        assert!(
            domains(&record).contains(&host_of("https://hidden.evil.test/x")?),
            "{label} {:?}",
            domains(&record)
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_table_that_differs_from_whatwg_lists_the_whatwg_host_and_flags() -> Result<(), Box<dyn std::error::Error>> {
    let cases: [(&str, &[u8], &str); DIFFERING_CASES] = [
        ("macintosh", b"https://a\xcd.test/x", "https://a\u{d5}.test/x"),
        ("koi8-u", b"https://a\xae.test/x", "https://a\u{45e}.test/x"),
    ];
    cases.iter().try_for_each(|(label, body, rendered)| {
        let record = run(label, body)?;
        assert!(
            record.uncertain_reasons.iter().any(|reason| reason == "charset_mismatch"),
            "{label} {:?}",
            record.uncertain_reasons
        );
        assert!(
            domains(&record).contains(&host_of(rendered)?),
            "{label} {:?} {record:?}",
            domains(&record)
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn the_ordinary_forms_are_not_flagged() -> Result<(), Box<dyn std::error::Error>> {
    let utf_8 = "https://plain.evil.test/\u{e9}".as_bytes();
    let cases: [(&str, &[u8]); ORDINARY_CASES] = [
        ("utf-8", utf_8),
        ("us-ascii", b"https://plain.evil.test/x"),
        ("windows-1252", b"https://plain.evil.test/x"),
        ("iso-8859-9", b"https://plain.evil.test/x"),
        ("koi8-r", b"https://plain.evil.test/x"),
        ("macintosh", b"https://plain.evil.test/x"),
        ("utf-8", b"\xef\xbb\xbfhttps://plain.evil.test/x"),
    ];
    cases.iter().try_for_each(|(label, body)| {
        let record = run(label, body)?;
        assert!(record.uncertain_reasons.is_empty(), "{label} {:?}", record.uncertain_reasons);
        assert!(domains(&record).contains(&host_of("https://plain.evil.test/x")?), "{label}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_part_without_a_label_has_no_whatwg_reading() -> Result<(), Box<dyn std::error::Error>> {
    let raw = mail_with("Content-Type: text/plain\r\n", b"https://plain.evil.test/\xff");
    let record = triage(&raw, &[], &ReporterPolicy::default())?;
    assert_eq!(record.counts.charset_mismatch, 0);
    Ok(())
}


#[test]
fn a_part_whose_raw_bytes_are_unreadable_is_flagged() -> Result<(), Box<dyn std::error::Error>> {
    let raw = "From: a@x.test\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit; x=y\r\n\r\nhttps://plain.evil.test/x\r\n";
    let record = triage(raw.as_bytes(), &[], &ReporterPolicy::default())?;
    assert_eq!(record.uncertain_reasons, ["charset_mismatch", "header_region_ambiguous"]);
    assert_eq!(record.counts.charset_mismatch, 1);
    Ok(())
}


#[test]
fn raw_bytes_over_the_part_limit_are_flagged_not_decoded() -> Result<(), Box<dyn std::error::Error>> {
    let body: Vec<u8> = "https://p.test/x".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let limits = Limits {
        part_bytes: TINY_PART,
        ..Limits::default()
    };
    let raw = mail_with("Content-Type: text/plain; charset=utf-16le\r\n", &body);
    let record = triage_with(&raw, &[], &ReporterPolicy::default(), &limits)?;
    assert!(body.len() > TINY_PART);
    assert_eq!(record.uncertain_reasons, ["charset_undecoded", "charset_mismatch"]);
    Ok(())
}
