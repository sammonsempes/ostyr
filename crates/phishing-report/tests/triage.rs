use cases::model::ObservableKind;
use data_encoding::BASE64;
use phishing_report::error::TriageError;
use phishing_report::limits::Limits;
use phishing_report::model::{AttachmentInfo, AuthVerdicts, Counts, ReporterPolicy, Triage, UrlHit};
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


const FOUR: usize = 4;


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


const PAD_BYTES: usize = 24 * 1024 * 1024;


const PAD_LINE: usize = 78;


const SIBLINGS: usize = 240;


const INTERNAL: &str = "corp.example";


const INTERNAL_TEST: &str = "corp.test";


const ID: &str = "mx.example.org";


fn trusted() -> Vec<String> {
    vec![ID.to_owned()]
}


fn policy() -> ReporterPolicy {
    ReporterPolicy {
        internal_domains: vec![INTERNAL.to_owned(), INTERNAL_TEST.to_owned()],
    }
}


fn run(text: &str) -> Result<Triage, TriageError> {
    triage(text.as_bytes(), &trusted(), &policy())
}


fn verdict(record: &AuthVerdicts) -> (&str, &str, &str) {
    (record.spf.as_str(), record.dkim.as_str(), record.dmarc.as_str())
}


fn links(record: &Triage) -> Vec<&str> {
    record.urls.iter().map(|hit| hit.url.as_str()).collect()
}


fn padding() -> String {
    format!("{}\r\n", "A".repeat(PAD_LINE - TWO)).repeat(PAD_BYTES / PAD_LINE)
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
    assert_eq!(verdict(&record.auth), ("pass", "fail", "pass"));
    assert_eq!(record.reporter_auth, None);
    assert_eq!(
        links(&record),
        [
            "http://xn--pypal-4ve.example/a?x=1&y=2",
            "http://softbreak.example/p",
            "data:text/html;base64,AAAA",
            "http://xn--pypal-4ve.example/a?x=1&amp;y=2"
        ]
    );
    assert!(record.urls.iter().all(|hit| hit.level == 0));
    assert_eq!(record.levels.len(), 1);
    assert_eq!(
        record.attachments,
        [AttachmentInfo {
            level: 0,
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
fn a_header_with_another_id_is_never_the_verdict() -> Result<(), Box<dyn std::error::Error>> {
    let text = mail(
        &[
            "Authentication-Results: mx.example.org; spf=fail; dkim=none; dmarc=fail",
            "Authentication-Results: forged.example; spf=pass; dkim=pass; dmarc=pass",
            "From: a@b.example",
        ],
        "hello",
    );
    let record = run(&text)?;
    assert_eq!(verdict(&record.auth), ("fail", "none", "fail"));
    assert_eq!(record.counts.auth_untrusted, 1);
    Ok(())
}


#[test]
fn a_forged_pass_without_a_receiver_header_is_unknown() -> Result<(), Box<dyn std::error::Error>> {
    let text = mail(
        &[
            "Return-Path: <phisher@evil.test>",
            "Received: from evil.test by mx.corp.test",
            "Authentication-Results: mx.corp.test; spf=pass; dkim=pass; dmarc=pass header.from=bank.test",
            "From: security@bank.test",
        ],
        "http://evil.test/login",
    );
    let record = run(&text)?;
    assert_eq!(verdict(&record.auth), ("unknown", "unknown", "unknown"));
    assert_eq!(record.auth.reason.as_deref(), Some("no_trusted_header"));
    let none = triage(text.as_bytes(), &[], &policy())?;
    assert_eq!(none.auth.reason.as_deref(), Some("no_trusted_header"));
    Ok(())
}


#[test]
fn a_quoted_semicolon_and_an_encoded_word_cannot_inject_a_verdict() -> Result<(), Box<dyn std::error::Error>> {
    let word = format!("=?utf-8?B?{}?=", BASE64.encode(b";dmarc=pass"));
    let quoted = "Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=\"x; dmarc=pass y\"@evil.test; dmarc=fail header.from=bank.test";
    let encoded = format!("Authentication-Results: mx.example.org; dkim=none smtp.mailfrom={word}@evil.test; dmarc=fail");
    let record = run(&mail(&[quoted, "From: a@b.example"], "x"))?;
    assert_eq!(verdict(&record.auth), ("fail", "unknown", "fail"));
    let second = run(&mail(&[&encoded, "From: a@b.example"], "x"))?;
    assert_eq!(verdict(&second.auth), ("unknown", "none", "fail"));
    let broken = run(&mail(
        &["Authentication-Results: mx.example.org; spf=pass x=\"open", "From: a@b.example"],
        "x",
    ))?;
    assert_eq!(verdict(&broken.auth), ("unknown", "unknown", "unknown"));
    assert_eq!(broken.counts.auth_refused, 1);
    Ok(())
}


#[test]
fn every_trusted_header_is_merged_and_a_forged_twin_is_a_conflict() -> Result<(), Box<dyn std::error::Error>> {
    let text = mail(
        &[
            "Return-Path: <a@b.example>",
            "Authentication-Results: mx.example.org; dmarc=fail (p=none dis=none) header.from=lab.test",
            "authentication-results: MX.example.org; spf=pass smtp.mailfrom=lab.test",
            "Authentication-Results: mx.example.org;\r\n\tdkim=pass header.d=lab.test;\r\n\tdkim-atps=neutral",
            "From: a@b.example",
            "Authentication-Results: mx.example.org; dmarc=pass; spf=pass",
        ],
        "hello",
    );
    let record = run(&text)?;
    assert_eq!(verdict(&record.auth), ("pass", "pass", "conflict"));
    assert_eq!(record.counts, Counts::default());
    Ok(())
}


#[test]
fn an_oversized_authentication_header_gives_no_verdict() -> Result<(), Box<dyn std::error::Error>> {
    let long = format!("Authentication-Results: mx.example.org; spf=pass; x={}", "y".repeat(LONG_HEADER));
    let text = mail(
        &[&long, "Authentication-Results: mx.example.org; dkim=pass", "From: a@b.example"],
        "hello",
    );
    let limits = Limits {
        header_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    let record = triage_with(text.as_bytes(), &trusted(), &policy(), &limits)?;
    assert_eq!(verdict(&record.auth), ("unknown", "unknown", "unknown"));
    assert_eq!(record.auth.reason.as_deref(), Some("oversized_header"));
    assert_eq!(record.counts.headers_skipped, 1);
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


fn original(auth: &str) -> String {
    mail(
        &[
            auth,
            "From: phisher@evil.example",
            "Return-Path: <phisher@evil.example>",
            "Subject: Your invoice",
            "Content-Type: text/plain",
        ],
        "pay at http://evil.example/pay now",
    )
}


const WRAPPER_AUTH: &str = "Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass header.from=corp.example";


const FORGED_AUTH: &str = "Authentication-Results: forged.example; spf=pass; dkim=pass; dmarc=pass";


#[test]
fn the_verdict_is_the_originals_and_the_forwards_is_reported_apart() -> Result<(), Box<dyn std::error::Error>> {
    let wrapper = [WRAPPER_AUTH, "From: employee@corp.example", "Subject: Fwd: Your invoice"];
    let inner = original("Authentication-Results: mx.example.org; spf=fail; dkim=none; dmarc=fail");
    let record = run(&forward(&inner, &wrapper))?;
    assert_eq!(verdict(&record.auth), ("unknown", "unknown", "unknown"));
    assert_eq!(record.auth.reason.as_deref(), Some("attached_original"));
    assert_eq!(record.counts.auth_nested_ignored, 1);
    assert_eq!(record.reporter, "forward");
    assert_eq!(record.original_level, Some(1));
    let reporter = record.reporter_auth.ok_or("no reporter verdict")?;
    assert_eq!(verdict(&reporter), ("pass", "pass", "pass"));
    assert_eq!(record.sender.as_deref(), Some("phisher@evil.example"));
    assert_eq!(record.subject.as_deref(), Some("Your invoice"));
    assert_eq!(
        record.urls,
        [
            UrlHit {
                level: 0,
                url: "http://wrapper.example/".into()
            },
            UrlHit {
                level: 1,
                url: "http://evil.example/pay".into()
            }
        ]
    );
    assert_eq!(record.counts.nesting_cut, 0);
    assert_eq!(record.counts.messages_unopened, 0);
    let forged = run(&forward(&original(FORGED_AUTH), &wrapper))?;
    assert_eq!(forged.auth.reason.as_deref(), Some("attached_original"));
    assert_eq!(verdict(&forged.auth), ("unknown", "unknown", "unknown"));
    Ok(())
}


#[test]
fn a_forged_twin_below_the_receivers_header_inside_the_original_is_a_conflict() -> Result<(), Box<dyn std::error::Error>> {
    let inner = mail(
        &[
            "Authentication-Results: mx.example.org; dmarc=fail",
            "Authentication-Results: mx.example.org; dmarc=pass",
            "From: phisher@evil.example",
        ],
        "x",
    );
    let record = run(&forward(&inner, &[WRAPPER_AUTH, "From: employee@corp.example"]))?;
    assert_eq!(record.auth.dmarc, "unknown");
    assert_eq!(record.auth.reason.as_deref(), Some("attached_original"));
    assert_eq!(record.counts.auth_nested_ignored, TWO);
    Ok(())
}


#[test]
fn an_eml_attachment_is_opened_as_the_original_message() -> Result<(), Box<dyn std::error::Error>> {
    let wrapper = [WRAPPER_AUTH, "From: employee@corp.example", "Subject: Fwd"];
    let inner = original("Authentication-Results: mx.example.org; spf=neutral");
    let text = multipart(&wrapper, &[attachment("Original.EML", "application/octet-stream", &inner)]);
    let record = run(&text)?;
    assert_eq!(record.sender.as_deref(), Some("phisher@evil.example"));
    assert_eq!(verdict(&record.auth), ("unknown", "unknown", "unknown"));
    assert_eq!(links(&record), ["http://evil.example/pay"]);
    assert_eq!(record.counts.messages_unopened, 0);
    Ok(())
}


#[test]
fn a_decoy_message_inside_the_original_never_replaces_it() -> Result<(), Box<dyn std::error::Error>> {
    let decoy = mail(
        &["From: ceo@corp.example", "Subject: Q3 plan", "Content-Type: text/plain"],
        "see http://decoy.example/",
    );
    let phish = multipart(
        &["From: phisher@evil.example", "Subject: Your invoice"],
        &[
            part(&["Content-Type: text/html"], "<a href=\"https://evil.example/steal\">pay</a>"),
            attachment("invoice.exe", "application/octet-stream", "Hello"),
            part(&["Content-Type: message/rfc822"], &decoy),
        ],
    );
    let record = run(&forward(&phish, &[WRAPPER_AUTH, "From: employee@corp.example"]))?;
    assert_eq!(record.sender.as_deref(), Some("phisher@evil.example"));
    assert_eq!(record.subject.as_deref(), Some("Your invoice"));
    assert_eq!(
        links(&record),
        ["http://wrapper.example/", "https://evil.example/steal", "http://decoy.example/"]
    );
    let tags: Vec<usize> = record.urls.iter().map(|hit| hit.level).collect();
    assert_eq!(tags, [0, 1, TWO]);
    assert!(record
        .attachments
        .iter()
        .any(|found| found.level == 1 && found.file_name.as_deref() == Some("invoice.exe")));
    let senders: Vec<Option<&str>> = record.levels.iter().map(|level| level.sender.as_deref()).collect();
    assert_eq!(
        senders,
        [Some("employee@corp.example"), Some("phisher@evil.example"), Some("ceo@corp.example")]
    );
    let levels: Vec<usize> = record.levels.iter().map(|level| level.level).collect();
    assert_eq!(levels, [0, 1, TWO]);
    Ok(())
}


#[test]
fn a_second_attached_message_beside_the_first_is_counted_unopened() -> Result<(), Box<dyn std::error::Error>> {
    let first = mail(&["From: first@x.example"], "one");
    let second = mail(&["From: second@x.example"], "two");
    let text = multipart(
        &[WRAPPER_AUTH, "From: employee@corp.example"],
        &[
            part(&["Content-Type: message/rfc822"], &first),
            part(&["Content-Type: message/rfc822"], &second),
        ],
    );
    let record = run(&text)?;
    assert_eq!(record.sender.as_deref(), Some("first@x.example"));
    assert_eq!(record.counts.messages_unopened, 1);
    Ok(())
}


#[test]
fn a_binary_that_is_not_a_message_stays_an_attachment() -> Result<(), Box<dyn std::error::Error>> {
    let text = multipart(
        &["From: a@b.example"],
        &[
            attachment("data.eml", "application/octet-stream", "\u{0}\u{1}binary"),
            attachment("data.bin", "application/octet-stream", "\u{0}\u{1}binary"),
            part(&["Content-Type: text/plain"], "plain"),
        ],
    );
    let record = run(&text)?;
    assert_eq!(record.sender.as_deref(), Some("a@b.example"));
    assert_eq!(record.attachments.len(), TWO);
    Ok(())
}


#[test]
fn an_eml_over_the_part_bound_is_not_opened() -> Result<(), Box<dyn std::error::Error>> {
    let text = multipart(
        &["From: wrapper@b.example"],
        &[attachment("o.eml", "application/octet-stream", &original(FORGED_AUTH))],
    );
    let limits = Limits {
        part_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    let record = triage_with(text.as_bytes(), &trusted(), &policy(), &limits)?;
    assert_eq!(record.sender.as_deref(), Some("wrapper@b.example"));
    assert_eq!(record.counts.attachments_skipped, 1);
    assert_eq!(record.counts.messages_unopened, 1);
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
    let record = triage_with(nested(LEVELS).as_bytes(), &trusted(), &policy(), &limits)?;
    assert_eq!(record.sender, Some(format!("l{LEVELS}@x.example")));
    assert_eq!(record.levels.len(), THREE);
    assert_eq!(record.counts.nesting_cut, 1);
    assert_eq!(record.counts.scan_cut, 1);
    Ok(())
}


#[test]
fn nesting_exactly_at_the_limit_is_not_a_cut() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        nesting: THREE,
        ..Limits::default()
    };
    let record = triage_with(nested(THREE).as_bytes(), &trusted(), &policy(), &limits)?;
    assert_eq!(
        record.levels.last().and_then(|level| level.sender.clone()),
        Some("l0@x.example".to_owned())
    );
    assert_eq!(record.counts.nesting_cut, 0);
    let none = Limits {
        nesting: 0,
        ..Limits::default()
    };
    let unopened = triage_with(nested(1).as_bytes(), &trusted(), &policy(), &none)?;
    assert_eq!(unopened.sender.as_deref(), Some("l1@x.example"));
    assert_eq!(unopened.counts.nesting_cut, 1);
    Ok(())
}


#[test]
fn fifty_levels_under_the_default_limits_finish() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&nested(LEVELS))?;
    assert_eq!(record.levels.len(), FOUR);
    assert_eq!(record.counts.nesting_cut, 1);
    assert_eq!(record.counts.scan_cut, 1);
    Ok(())
}


#[test]
fn many_sibling_messages_and_a_large_part_are_cut_before_the_parse() -> Result<(), Box<dyn std::error::Error>> {
    let small = mail(&["From: a@b.test", "Subject: s"], "x");
    let siblings = part(&["Content-Type: message/rfc822"], &small).repeat(SIBLINGS);
    let big = part(
        &[
            "Content-Type: application/octet-stream",
            "Content-Disposition: attachment; filename=\"p.bin\"",
        ],
        &padding(),
    );
    let text = multipart(&["From: x@evil.test"], &[siblings, big]);
    assert!(text.len() > PAD_BYTES);
    let record = run(&text)?;
    assert_eq!(record.counts.scan_cut, 1);
    assert!(record.attachments.iter().all(|found| found.size < PAD_BYTES));
    Ok(())
}


#[test]
fn fifty_levels_with_a_large_innermost_body_are_cut_before_the_parse() -> Result<(), Box<dyn std::error::Error>> {
    let deepest = mail(&["From: deep@evil.test", "Subject: deep"], &padding());
    let text = (0..LEVELS).fold(deepest, |inner, level| {
        let sender = format!("From: l{level}@evil.test");
        mail(&[&sender, "MIME-Version: 1.0", "Content-Type: message/rfc822"], &inner)
    });
    assert!(text.len() > PAD_BYTES);
    let record = run(&text)?;
    assert_eq!(record.counts.scan_cut, 1);
    assert!(record.counts.nesting_cut <= 1);
    Ok(())
}


#[test]
fn a_message_over_the_size_limit_is_refused_and_junk_is_not_a_message() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        message_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    assert_eq!(
        triage_with(&[b'a'; SMALL_HEADER_BYTES + 1], &trusted(), &policy(), &limits),
        Err(TriageError::TooLarge)
    );
    assert_eq!(
        triage_with(&[b'a'; SMALL_HEADER_BYTES], &trusted(), &policy(), &limits),
        Err(TriageError::Unparsable)
    );
    assert_eq!(triage(b"", &[], &policy()), Err(TriageError::Unparsable));
    Ok(())
}


#[test]
fn an_oversized_header_is_skipped_and_counted() -> Result<(), Box<dyn std::error::Error>> {
    let long = format!("Subject: {}", "s".repeat(LONG_HEADER));
    let limits = Limits {
        header_bytes: SMALL_HEADER_BYTES,
        ..Limits::default()
    };
    let record = triage_with(mail(&["From: a@b.example", &long], "x").as_bytes(), &trusted(), &policy(), &limits)?;
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
    let record = triage_with(text.as_bytes(), &trusted(), &policy(), &limits)?;
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
    let parts: Vec<String> = (0..THREE * THREE)
        .map(|index| part(&["Content-Type: text/plain"], &format!("http://p{index}.example/")))
        .collect();
    let limits = Limits {
        parts: PART_CAP,
        ..Limits::default()
    };
    let record = triage_with(multipart(&["From: a@b.example"], &parts).as_bytes(), &trusted(), &policy(), &limits)?;
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
    let record = triage_with(text.as_bytes(), &trusted(), &policy(), &limits)?;
    assert_eq!(links(&record), ["http://small.example/"]);
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
    let record = triage_with(text.as_bytes(), &trusted(), &policy(), &limits)?;
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
    let record = triage_with(text.as_bytes(), &trusted(), &policy(), &limits)?;
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
    let record = triage_with(text.as_bytes(), &trusted(), &policy(), &limits)?;
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
        &trusted(),
        &policy(),
        &Limits::default(),
        &Regex::new(&String::from("(")),
    )?;
    assert!(record.urls.is_empty());
    assert_eq!(record.counts.pattern_failed, 1);
    Ok(())
}


#[test]
fn urls_hidden_by_character_references_are_listed_from_the_original() -> Result<(), Box<dyn std::error::Error>> {
    let inner = mail(
        &["From: p@evil.test", "Content-Type: text/html"],
        "<a href=\"https&#58;//a.evil.test/a\">x</a> <a href=\"&#104;ttps://b.evil.test/b\">y</a> <a href=\"https&colon;//c.evil.test/c\">z</a> &nope;",
    );
    let record = run(&forward(&inner, &[WRAPPER_AUTH, "From: employee@corp.example"]))?;
    assert_eq!(
        links(&record),
        [
            "http://wrapper.example/",
            "https://a.evil.test/a",
            "https://b.evil.test/b",
            "https://c.evil.test/c"
        ]
    );
    assert_eq!(record.counts.html_refs_undecoded, 1);
    Ok(())
}


const REFUSED_LINK: &str = "<a href='https://ph&#9;ish.evil.test/a&#27;b'>x</a>";


const INNER_REFUSED_LINK: &str = "<a href='https://ph&#9;ish.evil.test/c&#27;d'>x</a> <a href='https://deep.evil.test/e&#27;f'>y</a>";


#[test]
fn a_refused_url_lists_its_host_from_a_raw_message() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&mail(&["From: p@evil.test", "Content-Type: text/html"], REFUSED_LINK))?;
    assert!(!links(&record).iter().any(|url| url.contains("phish.evil.test")));
    assert_eq!(record.refused_hosts, ["phish.evil.test"]);
    assert_eq!(record.counts.url_refused_host_kept, 1);
    assert!(observables(&record, &policy()).contains(&(ObservableKind::Domain, "phish.evil.test".to_owned())));
    Ok(())
}


#[test]
fn a_refused_host_is_carried_to_the_nested_level_and_not_listed_twice() -> Result<(), Box<dyn std::error::Error>> {
    let inner = mail(&["From: p@evil.test", "Content-Type: text/html"], INNER_REFUSED_LINK);
    let text = multipart(
        &["From: employee@corp.example"],
        &[
            part(&["Content-Type: text/html"], REFUSED_LINK),
            part(&["Content-Type: message/rfc822"], &inner),
        ],
    );
    let record = run(&text)?;
    assert_eq!(record.refused_hosts, ["phish.evil.test", "deep.evil.test"]);
    assert_eq!(record.counts.url_refused_host_kept, TWO);
    Ok(())
}


#[test]
fn an_inner_refused_host_that_repeats_no_outer_host_is_listed_after_the_outer_one() -> Result<(), Box<dyn std::error::Error>> {
    let inner = mail(
        &["From: p@evil.test", "Content-Type: text/html"],
        "<a href='https://deep.evil.test/e&#27;f'>y</a>",
    );
    let text = multipart(
        &["From: employee@corp.example"],
        &[
            part(&["Content-Type: text/html"], REFUSED_LINK),
            part(&["Content-Type: message/rfc822"], &inner),
        ],
    );
    let record = run(&text)?;
    assert_eq!(record.refused_hosts, ["phish.evil.test", "deep.evil.test"]);
    Ok(())
}


#[test]
fn observables_are_sorted_lowercase_and_deduplicated() -> Result<(), Box<dyn std::error::Error>> {
    let hit = |url: &str| UrlHit { level: 0, url: url.into() };
    let record = Triage {
        sender: Some("Boss@Evil.Example".into()),
        return_path: Some("boss@evil.example".into()),
        urls: vec![
            hit("http://evil.example/x"),
            hit("http://192.0.2.1/y"),
            hit("data:text/plain,hi"),
            hit("http://other.example/"),
        ],
        attachments: vec![
            AttachmentInfo {
                level: 0,
                file_name: Some("a.exe".into()),
                content_type: "x/y".into(),
                size: 1,
                sha256: "aa".into(),
            },
            AttachmentInfo {
                level: 0,
                file_name: None,
                content_type: "x/y".into(),
                size: 1,
                sha256: "aa".into(),
            },
        ],
        ..Triage::default()
    };
    let found = observables(&record, &ReporterPolicy::default());
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
    assert!(observables(&Triage::default(), &ReporterPolicy::default()).is_empty());
    Ok(())
}


#[test]
fn a_header_that_cannot_be_read_back_raw_gives_no_verdict() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = b"Authentication-Results: mx.example.org; spf=pass x=\xff\r\nFrom: a@b.example\r\n\r\nx".to_vec();
    let record = triage(&bytes, &trusted(), &policy()).map_err(|error| format!("plain: {error}"))?;
    assert_eq!(verdict(&record.auth), ("unknown", "unknown", "unknown"));
    assert_eq!(record.counts.auth_refused, 1);
    Ok(())
}


#[test]
fn an_empty_return_path_gives_no_address() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&mail(&["Return-Path:", "From: a@b.example"], "x"))?;
    assert_eq!(record.return_path, None);
    assert_eq!(record.sender.as_deref(), Some("a@b.example"));
    Ok(())
}


const INNER_PAD_BYTES: usize = 17 * 1024 * 1024;


const EML_PAD_BYTES: usize = 8 * 1024 * 1024;


fn small_message() -> String {
    mail(&["From: a@b.test", "Subject: s"], "x")
}


fn siblings_with_padding(content_type: &str, bytes: usize) -> String {
    let children = part(&[content_type], &small_message()).repeat(SIBLINGS);
    let pad = padding();
    let big = part(&["Content-Type: application/octet-stream"], pad.get(..bytes).unwrap_or(&pad));
    multipart(&["From: x@evil.test", "Subject: s"], &[children, big])
}


#[test]
fn an_encoded_nested_message_with_many_children_is_refused_before_the_decode() -> Result<(), Box<dyn std::error::Error>> {
    let inner = siblings_with_padding("Content-Type: message/rfc822", INNER_PAD_BYTES);
    let encoded = data_encoding::BASE64_MIME.encode(inner.as_bytes());
    let forward = multipart(
        &["From: employee@corp.test", "Subject: Fwd: suspicious"],
        &[
            part(&["Content-Type: text/plain"], "please check"),
            part(&["Content-Type: message/rfc822", "Content-Transfer-Encoding: base64"], &encoded),
            part(&["Content-Type: text/plain"], "see http://after.evil.test/x"),
        ],
    );
    assert!(forward.len() > INNER_PAD_BYTES);
    let record = run(&forward)?;
    assert_eq!(record.counts.nested_refused, 1);
    assert_eq!(record.counts.scan_cut, 0);
    assert_eq!(record.counts.scan_lost_part, Some(TWO));
    assert!(record.counts.scan_lost_bytes > 0);
    assert!(record.attachments.iter().all(|found| found.size < PAD_BYTES));
    Ok(())
}


#[test]
fn an_attached_eml_with_many_children_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let inner = siblings_with_padding("Content-Type: message/rfc822", EML_PAD_BYTES);
    let forward = multipart(
        &[
            "Authentication-Results: mx.example.org; dmarc=pass header.from=corp.test",
            "From: employee@corp.test",
            "Subject: Fwd",
        ],
        &[attachment("orig.eml", "application/octet-stream", &inner)],
    );
    let record = run(&forward)?;
    assert_eq!(record.counts.scan_cut, 1);
    assert_eq!(record.levels.len(), THREE);
    Ok(())
}


#[test]
fn folded_commented_and_spaced_message_types_are_all_counted() -> Result<(), Box<dyn std::error::Error>> {
    [
        "Content-Type: message\r\n /rfc822",
        "Content-Type: message(x)/rfc822",
        "Content-Type: message /rfc822",
    ]
    .iter()
    .try_for_each(|content_type| {
        let record = run(&siblings_with_padding(content_type, PAD_BYTES))?;
        if record.counts.scan_cut == 1 && record.counts.scan_lost_bytes >= PAD_BYTES {
            Ok(())
        } else {
            Err(format!("not cut: {content_type:?}").into())
        }
    })
}


#[test]
fn digest_siblings_are_cut_before_the_parse() -> Result<(), Box<dyn std::error::Error>> {
    let children = "--D\r\n\r\nFrom: a@b.test\r\n\r\nx\r\n".repeat(SIBLINGS);
    let text = mail(
        &["From: x@evil.test", "MIME-Version: 1.0", "Content-Type: multipart/digest; boundary=\"D\""],
        &format!("{children}--D\r\nContent-Type: application/octet-stream\r\n\r\n{}--D--\r\n", padding()),
    );
    let record = run(&text)?;
    assert_eq!(record.counts.scan_cut, 1);
    assert!(record.counts.scan_lost_bytes >= PAD_BYTES);
    Ok(())
}


#[test]
fn body_text_naming_message_types_does_not_hide_a_later_url() -> Result<(), Box<dyn std::error::Error>> {
    let body = format!("{}http://hidden.evil.test/after\r\n", "see message/rfc822 docs\r\n".repeat(THREE * THREE));
    let inner = mail(&["From: p@evil.test", "Subject: s", "Content-Type: text/plain"], &body);
    let forward = multipart(
        &["From: employee@corp.test", "Subject: Fwd"],
        &[part(&["Content-Type: message/rfc822"], &inner)],
    );
    let record = run(&forward)?;
    assert_eq!(record.counts.scan_cut, 0);
    assert_eq!(record.counts.scan_lost_bytes, 0);
    assert_eq!(links(&record), ["http://hidden.evil.test/after"]);
    Ok(())
}
