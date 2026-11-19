use cases::model::ObservableKind;
use data_encoding::BASE64;
use phishing_report::error::TriageError;
use phishing_report::limits::Limits;
use phishing_report::model::{AttachmentInfo, AuthVerdicts, Counts, Triage};
use phishing_report::observables::observables;
use phishing_report::triage::{triage, triage_with, triage_with_rule};
use regex::Regex;


const LEVELS: usize = 50;


const LONG_HEADER: usize = 400;


const SMALL_HEADER_BYTES: usize = 100;


const MANY_HEADERS: usize = 100_000;


const MANY_PARTS: usize = 100_000;


const HEADER_CAP: usize = 3;


const PART_CAP: usize = 2;


const TWO: usize = 2;


const THREE: usize = 3;


const SHA_HELLO: &str = "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969";


const HELLO_SIZE: usize = 5;


fn mail(headers: &[&str], body: &str) -> String {
    format!("{}\r\n\r\n{body}", headers.join("\r\n"))
}


fn part(headers: &[&str], body: &str) -> String {
    format!("--BND\r\n{}\r\n\r\n{body}\r\n", headers.join("\r\n"))
}


fn multipart(headers: &[&str], parts: &[String]) -> String {
    let mut all = headers.to_vec();
    all.push("MIME-Version: 1.0");
    all.push("Content-Type: multipart/mixed; boundary=\"BND\"");
    mail(&all, &format!("{}--BND--\r\n", parts.concat()))
}


fn attachment(name: &str, content_type: &str, body: &str) -> String {
    let disposition = format!("Content-Disposition: attachment; filename=\"{name}\"");
    let kind = format!("Content-Type: {content_type}");
    part(
        &[&kind, &disposition, "Content-Transfer-Encoding: base64"],
        &BASE64.encode(body.as_bytes()),
    )
}


fn run(text: &str) -> Result<Triage, TriageError> {
    triage(text.as_bytes())
}


#[test]
fn a_plain_message_gives_its_fields() -> Result<(), Box<dyn std::error::Error>> {
    let text = multipart(
        &[
            "Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=a@b.example; dkim=fail; dmarc=pass",
            "Return-Path: <bounce@evil.example>",
            "From: \"Boss\" <Boss@Evil.Example>",
            "Subject: =?utf-8?B?SGVsbG8=?= urgent",
        ],
        &[
            part(
                &["Content-Type: text/html", "Content-Transfer-Encoding: quoted-printable"],
                "<a href=3D\"http://xn--pypal-4ve.example/a?x=3D1&amp;y=3D2\">x</a> http://soft=\r\nbreak.example/p. data:text/html;base64,AAAA",
            ),
            attachment("inv.exe", "application/octet-stream", "Hello"),
        ],
    );
    let record = run(&text)?;
    assert_eq!(record.sender.as_deref(), Some("Boss@Evil.Example"));
    assert_eq!(record.return_path.as_deref(), Some("bounce@evil.example"));
    assert_eq!(record.subject.as_deref(), Some("Hello urgent"));
    assert_eq!(
        record.auth,
        AuthVerdicts {
            spf: Some("pass".into()),
            dkim: Some("fail".into()),
            dmarc: Some("pass".into())
        }
    );
    assert_eq!(
        record.urls,
        [
            "http://xn--pypal-4ve.example/a?x=1&y=2",
            "http://softbreak.example/p",
            "data:text/html;base64,AAAA"
        ]
    );
    assert_eq!(
        record.attachments,
        [AttachmentInfo {
            file_name: Some("inv.exe".into()),
            content_type: "application/octet-stream".into(),
            size: HELLO_SIZE,
            sha256: SHA_HELLO.into()
        }]
    );
    assert_eq!(record.counts, Counts::default());
    Ok(())
}


#[test]
fn a_forged_header_lower_in_the_message_is_never_the_verdict() -> Result<(), Box<dyn std::error::Error>> {
    let text = mail(
        &[
            "Authentication-Results: mx.example.org; spf=fail; dkim=none; dmarc=fail",
            "Authentication-Results: forged.example; spf=pass; dkim=pass; dmarc=pass",
            "From: a@b.example",
        ],
        "hello",
    );
    let record = run(&text)?;
    assert_eq!(
        record.auth,
        AuthVerdicts {
            spf: Some("fail".into()),
            dkim: Some("none".into()),
            dmarc: Some("fail".into())
        }
    );
    assert_eq!(record.counts.auth_refused, 1);
    Ok(())
}


#[test]
fn every_header_of_the_run_with_the_topmost_id_is_merged_and_a_lower_one_is_not() -> Result<(), Box<dyn std::error::Error>> {
    let text = mail(
        &[
            "Return-Path: <a@b.example>",
            "Authentication-Results: mx.lab.test; dmarc=pass (p=none dis=none) header.from=lab.test",
            "authentication-results: MX.lab.test; spf=pass smtp.mailfrom=lab.test",
            "Authentication-Results: mx.lab.test;\r\n\tdkim=pass header.d=lab.test;\r\n\tdkim-atps=neutral",
            "Received: from x by mx.lab.test",
            "From: a@b.example",
            "Authentication-Results: mx.lab.test; spf=fail; dkim=fail; dmarc=fail",
        ],
        "hello",
    );
    let record = run(&text)?;
    assert_eq!(
        record.auth,
        AuthVerdicts {
            spf: Some("pass".into()),
            dkim: Some("pass".into()),
            dmarc: Some("pass".into())
        }
    );
    assert_eq!(record.counts, Counts::default());
    Ok(())
}


#[test]
fn an_oversized_topmost_header_gives_no_verdict() -> Result<(), Box<dyn std::error::Error>> {
    let long = format!("Authentication-Results: mx.lab.test; spf=pass; x={}", "y".repeat(LONG_HEADER));
    let text = mail(&[&long, "Authentication-Results: mx.lab.test; dkim=pass", "From: a@b.example"], "hello");
    let limits = Limits {
        header_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    let record = triage_with(text.as_bytes(), &limits)?;
    assert_eq!(record.auth, AuthVerdicts::default());
    assert_eq!(record.counts.headers_skipped, 1);
    assert_eq!(record.counts.auth_refused, 1);
    Ok(())
}


#[test]
fn a_message_without_an_authentication_header_has_no_verdict() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&mail(&["From: a@b.example"], "hello"))?;
    assert_eq!(record.auth, AuthVerdicts::default());
    assert_eq!(record.counts, Counts::default());
    Ok(())
}


fn forward(inner: &str, wrapper_headers: &[&str]) -> String {
    multipart(
        wrapper_headers,
        &[
            part(&["Content-Type: text/plain"], "please look http://wrapper.example/"),
            part(&["Content-Type: message/rfc822"], inner),
        ],
    )
}


fn forged_inner() -> String {
    mail(
        &[
            "Authentication-Results: forged.example; spf=pass; dkim=pass; dmarc=pass",
            "From: phisher@evil.example",
            "Return-Path: <phisher@evil.example>",
            "Subject: Your invoice",
            "Content-Type: text/plain",
        ],
        "pay at http://evil.example/pay now",
    )
}


#[test]
fn the_verdict_comes_from_the_outer_message_and_the_fields_from_the_attached_one() -> Result<(), Box<dyn std::error::Error>> {
    let wrapper = [
        "Authentication-Results: mx.example.org; spf=softfail; dkim=none; dmarc=none",
        "From: employee@corp.example",
        "Subject: Fwd: Your invoice",
    ];
    let record = run(&forward(&forged_inner(), &wrapper))?;
    assert_eq!(
        record.auth,
        AuthVerdicts {
            spf: Some("softfail".into()),
            dkim: Some("none".into()),
            dmarc: Some("none".into())
        }
    );
    assert_eq!(record.sender.as_deref(), Some("phisher@evil.example"));
    assert_eq!(record.subject.as_deref(), Some("Your invoice"));
    assert_eq!(record.urls, ["http://evil.example/pay"]);
    assert_eq!(record.counts.nesting_cut, 0);
    Ok(())
}


#[test]
fn an_eml_attachment_is_opened_as_the_original_message() -> Result<(), Box<dyn std::error::Error>> {
    let wrapper = [
        "Authentication-Results: mx.example.org; spf=neutral",
        "From: employee@corp.example",
        "Subject: Fwd",
    ];
    let text = multipart(&wrapper, &[attachment("Original.EML", "application/octet-stream", &forged_inner())]);
    let record = run(&text)?;
    assert_eq!(record.sender.as_deref(), Some("phisher@evil.example"));
    assert_eq!(record.auth.spf.as_deref(), Some("neutral"));
    assert_eq!(record.auth.dkim, None);
    Ok(())
}


#[test]
fn a_binary_that_is_not_a_message_stays_an_attachment() -> Result<(), Box<dyn std::error::Error>> {
    let text = multipart(
        &["From: a@b.example"],
        &[attachment("data.eml", "application/octet-stream", "\u{0}\u{1}binary")],
    );
    let record = run(&text)?;
    assert_eq!(record.sender.as_deref(), Some("a@b.example"));
    assert_eq!(record.attachments.len(), 1);
    Ok(())
}


#[test]
fn an_eml_over_the_part_bound_is_not_opened() -> Result<(), Box<dyn std::error::Error>> {
    let text = multipart(
        &["From: wrapper@b.example"],
        &[attachment("o.eml", "application/octet-stream", &forged_inner())],
    );
    let limits = Limits {
        part_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    let record = triage_with(text.as_bytes(), &limits)?;
    assert_eq!(record.sender.as_deref(), Some("wrapper@b.example"));
    assert_eq!(record.counts.attachments_skipped, 1);
    Ok(())
}


fn nested(levels: usize) -> String {
    (1..=levels).fold(mail(&["From: l0@x.example", "Subject: leaf"], "bottom"), |inner, level| {
        let header = format!("From: l{level}@x.example");
        let boundary = format!("Content-Type: multipart/mixed; boundary=\"B{level}\"");
        let body = format!("--B{level}\r\nContent-Type: message/rfc822\r\n\r\n{inner}\r\n--B{level}--\r\n");
        mail(&[&header, "MIME-Version: 1.0", &boundary], &body)
    })
}


#[test]
fn nesting_stops_at_the_limit_and_is_counted() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        nesting: TWO,
        ..Limits::default()
    };
    let record = triage_with(nested(LEVELS).as_bytes(), &limits)?;
    assert_eq!(record.sender, Some(format!("l{}@x.example", LEVELS - TWO)));
    assert_eq!(record.counts.nesting_cut, 1);
    Ok(())
}


#[test]
fn nesting_exactly_at_the_limit_is_not_a_cut() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        nesting: THREE,
        ..Limits::default()
    };
    let record = triage_with(nested(THREE).as_bytes(), &limits)?;
    assert_eq!(record.sender.as_deref(), Some("l0@x.example"));
    assert_eq!(record.counts.nesting_cut, 0);
    let none = Limits {
        nesting: 0,
        ..Limits::default()
    };
    let unopened = triage_with(nested(1).as_bytes(), &none)?;
    assert_eq!(unopened.sender.as_deref(), Some("l1@x.example"));
    assert_eq!(unopened.counts.nesting_cut, 1);
    Ok(())
}


#[test]
fn fifty_levels_under_the_default_limits_finish() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&nested(LEVELS))?;
    assert_eq!(record.sender, Some(format!("l{}@x.example", LEVELS - THREE)));
    assert_eq!(record.counts.nesting_cut, 1);
    Ok(())
}


#[test]
fn a_message_over_the_size_limit_is_refused_and_junk_is_not_a_message() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        message_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    assert_eq!(triage_with(&[b'a'; SMALL_HEADER_BYTES + 1], &limits), Err(TriageError::TooLarge));
    assert_eq!(triage_with(&[b'a'; SMALL_HEADER_BYTES], &limits), Err(TriageError::Unparsable));
    assert_eq!(triage(b""), Err(TriageError::Unparsable));
    Ok(())
}


#[test]
fn an_oversized_header_is_skipped_and_counted() -> Result<(), Box<dyn std::error::Error>> {
    let long = format!("Subject: {}", "s".repeat(LONG_HEADER));
    let limits = Limits {
        header_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    let record = triage_with(mail(&["From: a@b.example", &long], "x").as_bytes(), &limits)?;
    assert_eq!(record.subject, None);
    assert_eq!(record.sender.as_deref(), Some("a@b.example"));
    assert_eq!(record.counts.headers_skipped, 1);
    Ok(())
}


#[test]
fn headers_over_the_count_are_ignored_and_counted() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        headers: HEADER_CAP,
        ..Limits::default()
    };
    let text = mail(&["X-A: 1", "X-B: 2", "X-C: 3", "X-D: 4", "From: late@b.example"], "x");
    let record = triage_with(text.as_bytes(), &limits)?;
    assert_eq!(record.sender, None);
    assert_eq!(record.counts.headers_skipped, TWO);
    Ok(())
}


#[test]
fn a_hundred_thousand_headers_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let headers = "X-H: v\r\n".repeat(MANY_HEADERS);
    let record = run(&format!("From: a@b.example\r\n{headers}\r\nbody"))?;
    assert_eq!(record.sender.as_deref(), Some("a@b.example"));
    assert_eq!(record.counts.headers_skipped, MANY_HEADERS + 1 - Limits::default().headers);
    Ok(())
}


#[test]
fn a_hundred_thousand_one_byte_parts_are_cut_by_the_scan() -> Result<(), Box<dyn std::error::Error>> {
    let body = "--BND\r\nContent-Type: text/plain\r\n\r\nx\r\n".repeat(MANY_PARTS);
    let text = mail(
        &[
            "From: a@b.example",
            "MIME-Version: 1.0",
            "Content-Type: multipart/mixed; boundary=\"BND\"",
        ],
        &body,
    );
    let record = run(&text)?;
    assert_eq!(record.counts.scan_cut, 1);
    assert_eq!(record.sender.as_deref(), Some("a@b.example"));
    Ok(())
}


#[test]
fn parts_over_the_count_are_not_read() -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<String> = (0..MANY_HEADERS.min(THREE * THREE))
        .map(|index| part(&["Content-Type: text/plain"], &format!("http://p{index}.example/")))
        .collect();
    let limits = Limits {
        parts: PART_CAP,
        ..Limits::default()
    };
    let record = triage_with(multipart(&["From: a@b.example"], &parts).as_bytes(), &limits)?;
    assert_eq!(record.urls.len(), 1);
    assert!(record.counts.parts_skipped > 0);
    Ok(())
}


#[test]
fn a_text_part_over_the_decoded_bound_is_skipped_and_counted() -> Result<(), Box<dyn std::error::Error>> {
    let body = format!("http://big.example/ {}", "x".repeat(LONG_HEADER));
    let text = multipart(
        &["From: a@b.example"],
        &[
            part(&["Content-Type: text/plain"], &body),
            part(&["Content-Type: text/html"], &body),
            part(&["Content-Type: text/plain"], "http://small.example/"),
        ],
    );
    let limits = Limits {
        part_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    let record = triage_with(text.as_bytes(), &limits)?;
    assert_eq!(record.urls, ["http://small.example/"]);
    assert_eq!(record.counts.parts_skipped, TWO);
    Ok(())
}


#[test]
fn an_attachment_over_the_decoded_bound_is_skipped_and_counted() -> Result<(), Box<dyn std::error::Error>> {
    let big = "z".repeat(LONG_HEADER);
    let text = multipart(
        &["From: a@b.example"],
        &[
            attachment("big.bin", "application/octet-stream", &big),
            attachment("small.bin", "application/octet-stream", "Hello"),
        ],
    );
    let limits = Limits {
        part_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    let record = triage_with(text.as_bytes(), &limits)?;
    assert_eq!(record.attachments.len(), 1);
    assert_eq!(record.attachments.first().map(|found| found.sha256.as_str()), Some(SHA_HELLO));
    assert_eq!(record.counts.attachments_skipped, 1);
    Ok(())
}


#[test]
fn attachments_over_the_count_are_counted() -> Result<(), Box<dyn std::error::Error>> {
    let text = multipart(
        &["From: a@b.example"],
        &[
            attachment("a.bin", "application/octet-stream", "Hello"),
            attachment("b.bin", "application/octet-stream", "Hello"),
            attachment("c.bin", "application/octet-stream", "Hello"),
        ],
    );
    let limits = Limits {
        attachments: 1,
        ..Limits::default()
    };
    let record = triage_with(text.as_bytes(), &limits)?;
    assert_eq!(record.attachments.len(), 1);
    assert_eq!(record.counts.attachments_skipped, TWO);
    Ok(())
}


#[test]
fn hostile_text_is_replaced_and_counted_never_kept() -> Result<(), Box<dyn std::error::Error>> {
    let long_subject = format!("Subject: pay\u{1b}[31m now {}", "s".repeat(LONG_HEADER));
    let text = multipart(
        &["From: a@b.example", &long_subject],
        &[attachment("invoice\u{202E}fdp.exe", "application/x-msdownload", "Hello")],
    );
    let limits = Limits {
        subject_chars: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    let record = triage_with(text.as_bytes(), &limits)?;
    let subject = record.subject.ok_or("no subject")?;
    assert!(subject.starts_with("pay\u{fffd}[31m now "));
    assert!(subject.ends_with(" chars]"));
    let name = record.attachments.first().and_then(|found| found.file_name.clone()).ok_or("no name")?;
    assert_eq!(name, "invoice\u{fffd}fdp.exe");
    assert_eq!(record.counts.replaced_chars, TWO);
    assert_eq!(record.counts.text_cut, 1);
    Ok(())
}


#[test]
fn an_attachment_without_a_declared_type_or_a_subtype_gets_a_fixed_label() -> Result<(), Box<dyn std::error::Error>> {
    let text = multipart(
        &["From: g: grouped@b.example;"],
        &[
            part(&["Content-Disposition: attachment; filename=\"plain.txt\""], "text"),
            part(&["Content-Type: application", "Content-Disposition: attachment"], "x"),
        ],
    );
    let record = run(&text)?;
    assert_eq!(record.sender.as_deref(), Some("grouped@b.example"));
    let types: Vec<&str> = record.attachments.iter().map(|found| found.content_type.as_str()).collect();
    assert_eq!(types, ["application/octet-stream", "application"]);
    assert_eq!(record.attachments.get(1).and_then(|found| found.file_name.clone()), None);
    Ok(())
}


#[test]
fn an_address_with_a_control_character_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&mail(&["From: <a\u{1b}@b.example>", "Return-Path: no-address-here"], "x"))?;
    assert_eq!(record.sender, None);
    assert_eq!(record.return_path, None);
    assert_eq!(record.counts.addresses_refused, TWO);
    let missing = run(&mail(&["Subject: only"], "x"))?;
    assert_eq!(missing.sender, None);
    assert_eq!(missing.return_path, None);
    assert_eq!(missing.counts.addresses_refused, 0);
    Ok(())
}


#[test]
fn a_pattern_that_did_not_compile_is_counted_in_the_record() -> Result<(), Box<dyn std::error::Error>> {
    let record = triage_with_rule(
        mail(&["From: a@b.example"], "http://a.example/").as_bytes(),
        &Limits::default(),
        &Regex::new(&String::from("(")),
    )?;
    assert!(record.urls.is_empty());
    assert_eq!(record.counts.pattern_failed, 1);
    Ok(())
}


#[test]
fn observables_are_sorted_lowercase_and_deduplicated() -> Result<(), Box<dyn std::error::Error>> {
    let record = Triage {
        sender: Some("Boss@Evil.Example".into()),
        return_path: Some("boss@evil.example".into()),
        urls: vec![
            "http://evil.example/x".into(),
            "http://192.0.2.1/y".into(),
            "data:text/plain,hi".into(),
            "http://other.example/".into(),
        ],
        attachments: vec![
            AttachmentInfo {
                file_name: Some("a.exe".into()),
                content_type: "x/y".into(),
                size: 1,
                sha256: "aa".into(),
            },
            AttachmentInfo {
                file_name: None,
                content_type: "x/y".into(),
                size: 1,
                sha256: "aa".into(),
            },
        ],
        ..Triage::default()
    };
    let found = observables(&record);
    let expected = vec![
        (ObservableKind::Domain, "evil.example".to_owned()),
        (ObservableKind::Domain, "other.example".to_owned()),
        (ObservableKind::Url, "data:text/plain,hi".to_owned()),
        (ObservableKind::Url, "http://192.0.2.1/y".to_owned()),
        (ObservableKind::Url, "http://evil.example/x".to_owned()),
        (ObservableKind::Url, "http://other.example/".to_owned()),
        (ObservableKind::Hash, "aa".to_owned()),
        (ObservableKind::Email, "boss@evil.example".to_owned()),
        (ObservableKind::Filename, "a.exe".to_owned()),
    ];
    assert_eq!(found, expected);
    assert!(observables(&Triage::default()).is_empty());
    Ok(())
}


#[test]
fn an_empty_return_path_gives_no_address() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&mail(&["Return-Path:", "From: a@b.example"], "x"))?;
    assert_eq!(record.return_path, None);
    assert_eq!(record.sender.as_deref(), Some("a@b.example"));
    Ok(())
}
