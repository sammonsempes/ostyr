use phishing_report::limits::Limits;
use phishing_report::mime::{embedded_header, header_found, Kind};
use phishing_report::scan::scan;


const SIBLINGS: usize = 40;


fn encoded_part(content_type: &str) -> String {
    format!(
        "From: a@b.test\r\n\r\n--S\r\n{content_type}\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n--S\r\nContent-Type: text/plain\r\n\r\nhttp://kept.test/\r\n"
    )
}


fn refused(raw: &str) -> usize {
    scan(raw.as_bytes(), &Limits::default()).refused
}


#[test]
fn spellings_the_parser_reads_as_message_are_refused_when_encoded() -> Result<(), Box<dyn std::error::Error>> {
    let spellings = [
        "Content-Type: message/rfc822",
        "Content-Type: \\message/rfc822",
        "Content-Type: message\\/rfc822",
        "Content-Type: (a \\) message/rfc822",
        "Content-Type: mess(x)age/rfc822",
        "Content-Type: \"message\"/rfc822",
        "Content-Type: message /rfc822",
        "Content-Type: text/plain\r\nContent-Type: message/rfc822",
        "Content-Type: message/rfc822\r\nContent-Type: text/plain",
        "Content-Type: (message)/rfc822\r\nContent-Type: text/plain",
        "Content-Type: text/plain\r\nContent-Type: (x)",
        "Content-Type: text/plain\r\nContent-Type: ;",
        "Content-Type: text/plain\r\nContent-Type:",
        "Content-Type:",
    ];
    let missed: Vec<&&str> = spellings.iter().filter(|spelling| refused(&encoded_part(spelling)) != 1).collect();
    assert!(missed.is_empty(), "not refused: {missed:?}");
    Ok(())
}


#[test]
fn clear_types_are_not_refused_for_their_encoding() -> Result<(), Box<dyn std::error::Error>> {
    let clear = [
        "Content-Type: application/pdf; name=\"a--b.pdf\"",
        "Content-Type: application/octet-stream; name=\"message.eml\"",
        "Content-Type: image/png",
        "  Content-Type:  text/html ; charset=\"utf-8\"",
        "X-Other: 1",
    ];
    let wrong: Vec<&&str> = clear.iter().filter(|content_type| refused(&encoded_part(content_type)) != 0).collect();
    assert!(wrong.is_empty(), "refused: {wrong:?}");
    Ok(())
}


#[test]
fn a_digest_child_with_an_empty_or_odd_type_is_a_message() -> Result<(), Box<dyn std::error::Error>> {
    let head = "Content-Type: multipart/digest; boundary=D\r\n\r\n";
    let child = |header: &str| format!("{head}--D\r\n{header}Content-Transfer-Encoding: base64\r\n\r\nQUJD\r\n");
    assert_eq!(refused(&child("")), 1);
    assert_eq!(refused(&child("Content-Type:\r\n")), 1);
    assert_eq!(refused(&child("Content-Type: text/plain\r\nContent-Type: ;\r\n")), 1);
    assert_eq!(refused(&child("Content-Type: text/plain\r\n")), 0);
    let merged = format!(
        "{head}--D\r\nContent-Type: text/plain\r\n\r\nhello\r\nContent-Type: text/plain\r\n--D\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n"
    );
    assert_eq!(refused(&merged), 1);
    Ok(())
}


#[test]
fn body_lines_never_count_toward_the_nested_budget() -> Result<(), Box<dyn std::error::Error>> {
    let body = "Content-Type: see message/rfc822 docs\r\n\r\n".repeat(SIBLINGS);
    let raw = format!("From: a@b.test\r\n\r\n{body}http://late.test/\r\n");
    let scanned = scan(raw.as_bytes(), &Limits::default());
    assert!(!scanned.cut);
    assert_eq!(scanned.lost_bytes, 0);
    assert_eq!(scanned.usable, raw.as_bytes());
    let signature = "Thanks -- Bob\r\nContent-Type: message/rfc822\r\n\r\n".repeat(SIBLINGS);
    let unrelated = format!("From: a@b.test\r\n\r\n{signature}");
    let counted = scan(unrelated.as_bytes(), &Limits::default());
    assert!(counted.cut);
    assert!(counted.lost_bytes > 0);
    Ok(())
}


#[test]
fn a_boundary_with_the_header_on_the_same_line_or_inside_a_header_block_is_counted() -> Result<(), Box<dyn std::error::Error>> {
    let same_line = "x\r\n--DContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n";
    let scanned = scan(same_line.as_bytes(), &Limits::default());
    assert!(scanned.cut);
    assert_eq!(scanned.lost_part, Some(0));
    let split = "Content-Type: message/rfc822\r\n--D\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n";
    assert_eq!(refused(split), 1);
    let mid_line = "x\r\nfoo --DContent-Transfer-Encoding: base64\r\n\r\n";
    assert!(!scan(mid_line.as_bytes(), &Limits::default()).cut);
    let plain = "x\r\n--D\r\nContent-Type: text/plain\r\n\r\ny\r\n--D--\r\n";
    assert_eq!(scan(plain.as_bytes(), &Limits::default()).usable, plain.as_bytes());
    Ok(())
}


#[test]
fn a_nested_message_header_block_is_read_after_its_part() -> Result<(), Box<dyn std::error::Error>> {
    let raw = "Content-Type: message/rfc822\r\n\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n";
    assert_eq!(refused(raw), 1);
    let limits = Limits {
        nested_messages: 1,
        ..Limits::default()
    };
    assert!(scan(raw.as_bytes(), &limits).cut);
    Ok(())
}


#[test]
fn header_values_are_judged_whole() -> Result<(), Box<dyn std::error::Error>> {
    let clear = header_found(Kind::Type, b" text/plain ; charset=x", false);
    assert!(clear.clear && !clear.message && !clear.digest);
    assert!(!header_found(Kind::Type, b"message/rfc822", false).clear);
    assert!(!header_found(Kind::Type, b"text/ plain", false).clear);
    assert!(!header_found(Kind::Type, b"text/pl/ain", false).clear);
    assert!(!header_found(Kind::Type, b"text", false).clear);
    assert!(!header_found(Kind::Type, b"text/plain", true).clear);
    assert!(!header_found(Kind::Type, b"x)y/z", false).clear);
    assert!(header_found(Kind::Type, b"multi(x)part/dig\\est", false).digest);
    assert!(!header_found(Kind::Type, b"(a;b) message/rfc822", false).clear);
    assert!(header_found(Kind::Type, b"mess(x)age/rfc822", false).message);
    assert!(header_found(Kind::Encoding, b" Base64", false).encoded);
    assert!(!header_found(Kind::Encoding, b" 7BIT", false).encoded);
    assert!(!header_found(Kind::Other, b"x", true).encoded);
    assert_eq!(
        embedded_header(b"--D Content-Type : Message/rfc822").map(|found| found.0),
        Some(Kind::Type)
    );
    assert_eq!(
        embedded_header(b"--DContent-Transfer-Encoding: base64").map(|found| found.0),
        Some(Kind::Encoding)
    );
    assert_eq!(embedded_header(b"--D"), None);
    Ok(())
}


#[test]
fn an_ordinary_mail_keeps_its_urls_and_attachments() -> Result<(), Box<dyn std::error::Error>> {
    let raw = concat!(
        "From: a@b.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"----=_Part_1\"\r\n\r\n",
        "------=_Part_1\r\nContent-Type: multipart/alternative; boundary=\"----=_Part_2\"\r\n\r\n",
        "------=_Part_2\r\nContent-Type: text/plain\r\n\r\nhttp://plain.test/\r\n",
        "------=_Part_2\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<a href=3D\"http://html.test/\">x</a>\r\n",
        "------=_Part_2--\r\n",
        "------=_Part_1\r\nContent-Type: application/pdf; name=\"a--b.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n",
        "------=_Part_1\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: 7bit\r\n\r\n",
        "From: c@d.test\r\nSubject: fwd\r\nContent-Type: text/plain\r\n\r\nhttp://inner.test/\r\n------=_Part_1--\r\n",
    );
    let scanned = scan(raw.as_bytes(), &Limits::default());
    assert_eq!(scanned.usable, raw.as_bytes());
    assert_eq!(scanned.refused, 0);
    assert!(!scanned.cut);
    Ok(())
}


#[test]
fn a_line_of_colons_is_not_a_header() -> Result<(), Box<dyn std::error::Error>> {
    let raw = "From: a@b.test\r\n:::\r\nSubject: s\r\n\r\nbody\r\n";
    let scanned = scan(raw.as_bytes(), &Limits::default());
    assert_eq!(scanned.usable, raw.as_bytes());
    assert_eq!(scanned.refused, 0);
    Ok(())
}
