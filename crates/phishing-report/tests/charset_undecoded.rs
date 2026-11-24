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
        "<meta charset=\"UTF-8\" name=a>https://plain.evil.test/x",
        "<meta charset=us-ascii>https://plain.evil.test/x",
        "<meta charset=ascii>https://plain.evil.test/x",
        "<html><meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1252\">https://plain.evil.test/x",
    ]
    .iter()
    .try_for_each(|body| {
        let record = run(&mail_with_body("text/html", body.as_bytes()))?;
        assert_eq!(record.uncertain_reasons, ["charset_undecoded"], "{body}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let clean = ["<meta charset=\"utf-8\">https://plain.evil.test/x"];
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
    assert_eq!(
        run(&mail_with_body("text/html", late.as_bytes()))?.uncertain_reasons,
        ["charset_undecoded"]
    );
    let multibyte = format!("{}<meta charset=\"shift_jis\">", "\u{e9}".repeat(MULTIBYTE_PADDING));
    assert_eq!(
        run(&mail_with_body("text/html", multibyte.as_bytes()))?.uncertain_reasons,
        ["charset_undecoded"]
    );
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


const PLAIN_URL: &str = "https://plain.evil.test/x";


#[test]
fn a_meta_tag_read_two_ways_is_flagged() -> Result<(), Box<dyn std::error::Error>> {
    [
        "<meta data-x=\"charset=utf-8\" charset=\"shift_jis\">",
        "<meta content=\">\" charset=\"shift_jis\">",
        "<meta\r\ncharset=\"utf-8\"\r\nCHARSET=\"shift_jis\">",
        "<!-- x --><meta charset=utf-8 charset=shift_jis>",
        "<meta content='>' charset=utf-8>",
        "<meta\r\nCHARSET = \"utf-8\"\r\n>",
        "<meta x\"=\">\" charset=shift_jis>",
        "<meta x=\"<\" y='>' charset=shift_jis>",
        "<meta charset=\"utf-8",
        "<meta name=viewport",
        "<meta charset=utf-8 charset=utf-8>",
        "<meta x=\"<meta charset=utf-8>\" charset=shift_jis>",
        "<meta content=\"> charset=utf-8>",
        "<meta name=\"a\">",
        "<meta>",
        "<meta name=\"viewport\" content=\"width=device-width\">",
        "<meta name=\"viewport\" content=\"width=device-width\"><meta charset=\"utf-8\">",
    ]
    .iter()
    .try_for_each(|tag| {
        let record = run(&mail_with_body("text/html", format!("{tag}{PLAIN_URL}").as_bytes()))?;
        assert_eq!(record.uncertain_reasons, ["charset_undecoded"], "{tag}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_meta_tag_read_one_way_is_not_flagged() -> Result<(), Box<dyn std::error::Error>> {
    [
        "<meta charset=\"utf-8\">",
        "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">",
        "<meta charset=utf-8><meta charset='utf-8' />",
    ]
    .iter()
    .try_for_each(|tag| {
        let record = run(&mail_with_body("text/html", format!("{tag}{PLAIN_URL}").as_bytes()))?;
        assert!(record.uncertain_reasons.is_empty(), "{tag}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


fn two_content_types(first: &str, second: &str) -> String {
    format!("From: a@x.test\r\nMIME-Version: 1.0\r\nContent-Type: {first}\r\nContent-Type: {second}\r\n\r\nhello {PLAIN_URL}\r\n")
}


#[test]
fn two_content_type_headers_with_different_charsets_are_flagged() -> Result<(), Box<dyn std::error::Error>> {
    [
        ("text/plain; charset=utf-8", "text/plain; charset=shift_jis"),
        ("text/plain; charset=utf-8", "text/plain"),
        ("text/plain", "text/plain; charset=\"UTF-8\"; format=flowed"),
        ("text/plain; x=\"a;charset=utf-8\"", "text/plain; charset=utf-8"),
    ]
    .iter()
    .try_for_each(|(first, second)| {
        let record = run(&two_content_types(first, second))?;
        assert!(record.uncertain_reasons.contains(&"charset_undecoded".to_owned()), "{first} / {second}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    [("text/plain; charset=utf-8", "text/plain; charset=UTF-8"), ("text/plain", "text/plain")]
        .iter()
        .try_for_each(|(first, second)| {
            let record = run(&two_content_types(first, second))?;
            assert!(record.uncertain_reasons.contains(&"charset_undecoded".to_owned()), "{first} / {second}");
            Ok::<(), Box<dyn std::error::Error>>(())
        })
}


#[test]
fn a_content_type_with_a_backslash_or_a_repeated_charset_text_is_flagged() -> Result<(), Box<dyn std::error::Error>> {
    [
        "text/plain; x=\"\\\"; charset=utf-8; y=\"; charset=shift_jis",
        "text/plain; charset=utf-8; charset=shift_jis",
        "text/plain; x=\"charset\"; charset=utf-8",
        "text/plain; charset=utf-8; x=charset",
        "text/plain; x=\"a\\\"b\"; charset=utf-8",
        "text/plain; charset*0=utf-; charset=8",
        "text/plain; charset*0=utf-; x=charset",
    ]
    .iter()
    .try_for_each(|content_type| {
        assert_eq!(reasons(content_type)?, ["charset_undecoded"], "{content_type}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_header_that_is_not_the_last_content_type_is_judged_too() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&two_content_types("text/plain; charset=utf-8; charset=shift_jis", "text/plain"))?;
    assert!(record.uncertain_reasons.contains(&"charset_undecoded".to_owned()));
    Ok(())
}


#[test]
fn only_the_allowlisted_utf_8_meta_forms_are_not_flagged() -> Result<(), Box<dyn std::error::Error>> {
    [
        "<meta charset=\"utf-8\">",
        "<META  CHARSET=\"UTF-8\">",
        "<meta charset='utf-8'>",
        "<meta charset=utf-8>",
        "<meta charset=\"utf-8\" />",
        "<meta charset='utf-8' />",
        "<meta charset=utf-8 />",
        "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">",
        "<meta http-equiv=\"content-type\"\r\n content=\"text/html; charset=utf-8\" />",
        "<meta http-equiv='content-type' content='text/html; charset=utf-8'>",
        "<meta http-equiv='content-type' content='text/html; charset=utf-8' />",
    ]
    .iter()
    .try_for_each(|tag| {
        let record = run(&mail_with_body("text/html", format!("{tag}{PLAIN_URL}").as_bytes()))?;
        assert!(record.uncertain_reasons.is_empty(), "{tag}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    [
        "<meta charset=\"utf-8\" data-x>",
        "<meta content=\"text/html; charset=utf-8\" http-equiv=\"content-type\">",
        "<meta charset=\"utf8\">",
        "<meta charset=\"utf-8\" >",
    ]
    .iter()
    .try_for_each(|tag| {
        let record = run(&mail_with_body("text/html", format!("{tag}{PLAIN_URL}").as_bytes()))?;
        assert_eq!(record.uncertain_reasons, ["charset_undecoded"], "{tag}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn continuations_are_judged_on_parameter_names() -> Result<(), Box<dyn std::error::Error>> {
    [
        "text/plain; x=\"charset*0\"; charset*1=8",
        "text/plain; charset*01=utf-8",
        "text/plain; charset*0=utf-; charset*01=8",
        "text/plain; charset*=utf-8''x",
        "text/plain; charset*a=x",
        "text/plain; charset*x=utf-8",
        "text/plain; charset*0*x=utf-8",
        "text/plain; charset* =",
        "text/plain; charset*0=utf-; charset*x=8",
        "text/plain; charset*1*=8",
    ]
    .iter()
    .try_for_each(|content_type| {
        assert_eq!(reasons(content_type)?, ["charset_undecoded"], "{content_type}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    [
        "text/plain; x=\"charset*0\"",
        "text/plain; x=\"charset*01\"",
        "text/plain; charset*0*=utf-; charset*1*=8",
        "text/plain; charset*0=utf-; charset*1=8",
    ]
    .iter()
    .try_for_each(|content_type| {
        assert!(reasons(content_type)?.is_empty(), "{content_type}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


const LATE_PADDING: usize = 1200;


const STRADDLE_PADDING: usize = 1010;


fn run_bytes(raw: &[u8]) -> Result<Triage, Box<dyn std::error::Error>> {
    Ok(triage(raw, &["mx.example.org".to_owned()], &ReporterPolicy::default())?)
}


fn with_headers(headers: &[u8]) -> Vec<u8> {
    let mut raw = b"From: a@x.test\r\nMIME-Version: 1.0\r\n".to_vec();
    raw.extend_from_slice(headers);
    raw.extend_from_slice(format!("\r\nhello {PLAIN_URL}\r\n").as_bytes());
    raw
}


#[test]
fn a_content_type_that_is_not_utf_8_is_flagged_on_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let cases: Vec<&[u8]> = vec![
        b"Content-Type: text/plain; charset=utf-8\r\nContent-Type: text/plain; charset=shift_jis; x=\xFF\r\n",
        b"Content-Type: text/plain; charset=utf-8; charset=shift_jis; x=\xFF\r\nContent-Type: text/plain\r\n",
        b"Content-Type: text/plain; x=\"\\\"; charset=utf-8; y=\xFF\"; charset=shift_jis\r\n",
        b"Content-Type: text/plain; charset=utf-8\r\nCONTENT-TYPE: text/plain (\xFF)\r\n",
        b"Content-Type: text/plain; x=\xFF\r\n",
    ];
    cases.iter().try_for_each(|headers| {
        let record = run_bytes(&with_headers(headers))?;
        assert!(record.uncertain_reasons.contains(&"charset_undecoded".to_owned()), "{headers:?}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_meta_tag_past_byte_1024_is_judged_too() -> Result<(), Box<dyn std::error::Error>> {
    let padding = "x".repeat(LATE_PADDING);
    let late = format!("<title>{padding}</title><meta charset=shift_jis>{PLAIN_URL}");
    assert_eq!(
        run(&mail_with_body("text/html", late.as_bytes()))?.uncertain_reasons,
        ["charset_undecoded"]
    );
    let straddle = format!("{}<meta charset=shift_jis>{PLAIN_URL}", "x".repeat(STRADDLE_PADDING));
    assert_eq!(
        run(&mail_with_body("text/html", straddle.as_bytes()))?.uncertain_reasons,
        ["charset_undecoded"]
    );
    let allowed = format!("<title>{padding}</title><meta charset=utf-8>{PLAIN_URL}");
    assert!(run(&mail_with_body("text/html", allowed.as_bytes()))?.uncertain_reasons.is_empty());
    Ok(())
}


#[test]
fn a_meta_spelled_with_character_references_or_unlisted_is_flagged() -> Result<(), Box<dyn std::error::Error>> {
    [
        "<meta http-equiv=\"Content-Type\" content=\"text/html; &#99;harset=shift_jis\">",
        "<meta http-equiv=\"Content-Type\" content=\"text/html; &#x63;&#x68;&#x61;&#x72;&#x73;&#x65;&#x74;=shift_jis\">",
        "<meta content=\"text/html; c&#104;arset=shift_jis\" http-equiv=content-type>",
        "<meta http-equiv=content-type content=\"text/html; &#67;HARSET=shift_jis\">",
        "<meta http-equiv=content-type content=\"text/html; charset&#61;shift_jis\">",
        "<meta name=viewport content=\"width=device-width\">",
    ]
    .iter()
    .try_for_each(|tag| {
        let record = run(&mail_with_body("text/html", format!("<html><head>{tag}</head>{PLAIN_URL}").as_bytes()))?;
        assert_eq!(record.uncertain_reasons, ["charset_undecoded"], "{tag}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_meta_tag_without_a_close_inside_the_window_is_flagged_and_a_labelled_part_is_not() -> Result<(), Box<dyn std::error::Error>> {
    let long = format!("<meta charset=utf-8{}>", " ".repeat(LONG_PADDING));
    assert_eq!(
        run(&mail_with_body("text/html", long.as_bytes()))?.uncertain_reasons,
        ["charset_undecoded"]
    );
    let repeated = "<meta ".repeat(LONG_PADDING);
    assert_eq!(
        run(&mail_with_body("text/html", repeated.as_bytes()))?.uncertain_reasons,
        ["charset_undecoded"]
    );
    let labelled = run(&mail_with_body("text/html; charset=utf-8", b"<meta name=viewport>"))?;
    assert!(labelled.uncertain_reasons.is_empty());
    Ok(())
}


#[test]
fn an_xml_declaration_naming_an_encoding_is_flagged() -> Result<(), Box<dyn std::error::Error>> {
    [
        "<?xml version=\"1.0\" encoding=\"shift_jis\"?><html></html>",
        "<?XML version=\"1.0\" ENCODING=\"shift_jis\"?><html></html>",
        "<html><?xml encoding=shift_jis ?></html>",
        "<?xml version=\"a>\" encoding=shift_jis?>",
        "<?xml version=\"1.0\" encoding=\"utf-8\"",
    ]
    .iter()
    .try_for_each(|body| {
        let record = run(&mail_with_body("text/html", format!("{body}{PLAIN_URL}").as_bytes()))?;
        assert_eq!(record.uncertain_reasons, ["charset_undecoded"], "{body}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    ["<?xml version=\"1.0\"?><html>encoding</html>", "<?xml version=\"1.0\"?>"]
        .iter()
        .try_for_each(|body| {
            let record = run(&mail_with_body("text/html", format!("{body}{PLAIN_URL}").as_bytes()))?;
            assert!(record.uncertain_reasons.is_empty(), "{body}");
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
    let labelled = run(&mail_with_body("text/html; charset=utf-8", b"<?xml encoding=shift_jis?>"))?;
    assert!(labelled.uncertain_reasons.is_empty());
    Ok(())
}


#[test]
fn an_encoded_word_in_a_content_type_is_flagged() -> Result<(), Box<dyn std::error::Error>> {
    [
        "text/html; charset==?utf-8?q?shift=5Fjis?=",
        "text/html; charset=\"=?utf-8?q?shift=5Fjis?=\"",
        "text/html; charset==?us-ascii?b?c2hpZnRfamlz?=",
        "text/html; charset=utf-8; name==?utf-8?q?a?=",
        "text/html; name=\"=?utf-8?q?a?=\"",
    ]
    .iter()
    .try_for_each(|content_type| {
        assert!(
            reasons(content_type)?.iter().any(|reason| reason == "charset_undecoded"),
            "{content_type}"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert!(reasons("text/html; charset=utf-8; name=\"a=b\"")?.is_empty());
    Ok(())
}
