use cases::model::ObservableKind;
use phishing_report::model::{ReporterPolicy, Triage};
use phishing_report::observables::observables;
use phishing_report::triage::triage;


const BODY_COUNT: usize = 3;


const LONG_PADDING: usize = 2000;


const MULTIBYTE_PADDING: usize = 600;


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
    ["utf-32", "ibm037", "UTF-32LE", "utf-7", "ibm850", "850", "us_ascii"]
        .iter()
        .try_for_each(|label| {
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
    [
        "utf-8",
        "UTF8",
        "us-ascii",
        "iso-2022-jp",
        "shift_jis",
        "gb18030",
        "windows-1252",
        "iso-8859-1",
    ]
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
        b"https://pl\x1b(Bain.evil.test/x",
        b"h\0t\0t\0p\0s\0:\0/\0/\0e\0.\0t\0",
        b"https://a.test/\xff\xff",
    ];
    ["shift_jis", "gb18030", "utf-8"].iter().try_for_each(|label| {
        bodies.iter().try_for_each(|body| {
            let record = run(&mail_with_body(&format!("text/plain; charset={label}"), body))?;
            assert!(
                record.uncertain_reasons.iter().any(|reason| reason == "charset_undecoded"),
                "{label} {body:?}"
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    })?;
    let bom = run(&mail_with_body("text/plain; charset=utf-8", b"\xff\xfeh\0t\0t\0p\0s\0"))?;
    assert_eq!(bom.uncertain_reasons, ["charset_undecoded", "charset_mismatch"]);
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


fn domains(record: &Triage) -> Vec<String> {
    observables(record, &ReporterPolicy::default())
        .into_iter()
        .filter(|(kind, _)| *kind == ObservableKind::Domain)
        .map(|(_, value)| value)
        .collect()
}


fn host_of(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(url)?;
    Ok(parsed.host_str().ok_or("no host")?.to_owned())
}


#[test]
fn valid_utf_8_bytes_under_a_multi_byte_label_list_the_host_the_client_renders() -> Result<(), Box<dyn std::error::Error>> {
    let body = b"https://\xd0\xb0\xd0\xb0\xd0\xb0.test/x";
    let cases = [
        ("gbk", "https://\u{90aa}\u{90aa}\u{90aa}.test/x"),
        ("gb18030", "https://\u{90aa}\u{90aa}\u{90aa}.test/x"),
        ("shift_jis", "https://\u{ff90}\u{ff70}\u{ff90}\u{ff70}\u{ff90}\u{ff70}.test/x"),
        ("euc-jp", "https://\u{8212}\u{8212}\u{8212}.test/x"),
        ("euc-kr", "https://\u{9035}\u{9035}\u{9035}.test/x"),
        ("big5", "https://\u{8a04}\u{8a04}\u{8a04}.test/x"),
    ];
    cases.iter().try_for_each(|(label, rendered)| {
        let record = run(&mail_with_body(&format!("text/plain; charset={label}"), body))?;
        let hosts = domains(&record);
        assert!(hosts.contains(&host_of(rendered)?), "{label} {hosts:?}");
        assert!(!hosts.iter().any(|host| host == "xn--80aaa.test"), "{label}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_gbk_no_break_space_run_no_longer_cuts_the_url() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&mail_with_body("text/plain; charset=gbk", b"https://a\xc2\xa0b.test/x"))?;
    assert!(domains(&record).contains(&host_of("https://a\u{807d}b.test/x")?));
    Ok(())
}


#[test]
fn an_unlabelled_part_declaring_a_foreign_charset_in_a_meta_tag_is_flagged() -> Result<(), Box<dyn std::error::Error>> {
    [
        "<meta charset=\"shift_jis\">https://plain.evil.test/x",
        "<META CHARSET=shift_jis>https://plain.evil.test/x",
        "<html><meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1252\">https://plain.evil.test/x",
    ]
    .iter()
    .try_for_each(|body| {
        let record = run(&mail_with_body("text/html", body.as_bytes()))?;
        assert_eq!(record.uncertain_reasons, ["charset_undecoded"], "{body}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let clean = [
        "<meta charset=\"utf-8\">https://plain.evil.test/x",
        "<meta charset=us-ascii>https://plain.evil.test/x",
        "<meta name=\"a\">https://plain.evil.test/x",
        "<meta>https://plain.evil.test/x",
    ];
    clean.iter().try_for_each(|body| {
        let record = run(&mail_with_body("text/html", body.as_bytes()))?;
        assert!(record.uncertain_reasons.is_empty(), "{body}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let labelled = run(&mail_with_body(
        "text/html; charset=utf-8",
        b"<meta charset=\"shift_jis\">https://plain.evil.test/x",
    ))?;
    assert!(labelled.uncertain_reasons.is_empty());
    let late = format!("{}<meta charset=\"shift_jis\">", "a".repeat(LONG_PADDING));
    assert!(run(&mail_with_body("text/html", late.as_bytes()))?.uncertain_reasons.is_empty());
    let multibyte = format!("{}<meta charset=\"shift_jis\">", "\u{e9}".repeat(MULTIBYTE_PADDING));
    assert!(run(&mail_with_body("text/html", multibyte.as_bytes()))?.uncertain_reasons.is_empty());
    Ok(())
}


#[test]
fn a_replacement_or_user_defined_label_is_flagged_over_ascii() -> Result<(), Box<dyn std::error::Error>> {
    [
        "hz-gb-2312",
        "hz_gb_2312",
        "iso-2022-cn",
        "iso-2022-kr",
        "csiso2022kr",
        "replacement",
        "x-user-defined",
    ]
    .iter()
    .try_for_each(|label| {
        assert_eq!(reasons(&format!("text/plain; charset={label}"))?, ["charset_undecoded"], "{label}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_genuine_iso_2022_jp_part_is_not_flagged_for_its_escape() -> Result<(), Box<dyn std::error::Error>> {
    let plain = run(&mail_with_body("text/plain; charset=iso-2022-jp", b"\x1b(Bhttps://plain.evil.test/x"))?;
    assert!(plain.uncertain_reasons.is_empty());
    assert!(domains(&plain).iter().any(|host| host == "plain.evil.test"));
    let hidden = run(&mail_with_body("text/plain; charset=iso-2022-jp", b"https://pl\x1b(Bain.evil.test/x"))?;
    assert!(domains(&hidden).iter().any(|host| host == "plain.evil.test"));
    let other = run(&mail_with_body("text/plain; charset=utf-8", b"\x1b(Bhttps://plain.evil.test/x"))?;
    assert_eq!(other.uncertain_reasons, ["charset_undecoded"]);
    Ok(())
}


#[test]
fn a_continuation_without_a_first_part_is_flagged() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(reasons("text/plain; charset=utf-; charset*1=8")?, ["charset_undecoded"]);
    assert_eq!(reasons("text/plain; charset =utf-; charset *2=8")?, ["charset_undecoded"]);
    assert!(reasons("text/plain; charset*0=utf-; charset*1=8")?.is_empty());
    Ok(())
}
