use phishing_report::limits::Limits;
use phishing_report::model::{ReporterPolicy, Triage};
use phishing_report::triage::triage_with;


const REASON: &str = "scan_refused";


const LINK: &str = "<a href=\"https://good.test&#64;evil.test/\">x</a>";


const BASE64_LINK: &str = "PGEgaHJlZj0iaHR0cHM6Ly9nb29kLnRlc3QmIzY0O2V2aWwudGVzdC8iPng8L2E+";


fn run(raw: &str) -> Result<Triage, Box<dyn std::error::Error>> {
    Ok(triage_with(
        raw.as_bytes(),
        &["mx.example.org".to_owned()],
        &ReporterPolicy::default(),
        &Limits::default(),
    )?)
}


fn listed(record: &Triage) -> bool {
    record.urls.iter().any(|hit| hit.url == "https://good.test@evil.test/")
}


fn flagged(record: &Triage) -> bool {
    record.original_uncertain && record.uncertain_reasons.iter().any(|reason| reason == REASON)
}


fn part_headers(content_type: &str, encoding: &str) -> String {
    format!("Content-Type: {content_type}\r\nContent-Transfer-Encoding: {encoding}\r\n")
}


fn placements(part_head: &str, body: &str) -> Vec<String> {
    let top = format!("From: p@sender.test\r\n{part_head}\r\n{body}\r\n");
    let mixed = format!("From: p@sender.test\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n{part_head}\r\n{body}\r\n--B--\r\n");
    let alt = mixed.replace("multipart/mixed", "multipart/alternative");
    let nested = format!(
        "From: p@sender.test\r\nContent-Type: multipart/mixed; boundary=O\r\n\r\n--O\r\nContent-Type: message/rfc822\r\n\r\n{top}\r\n--O--\r\n"
    );
    vec![top, mixed, alt, nested]
}


#[test]
fn a_blanked_header_never_hides_a_link() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (part_headers("text/html (x)", "base64"), BASE64_LINK),
        (part_headers("text/html (x)", "quoted-printable"), LINK),
        (part_headers("message/rfc822", "base64"), BASE64_LINK),
        (part_headers("text/html (x)", "BASE64"), BASE64_LINK),
    ];
    for (head, body) in &cases {
        for (place, raw) in placements(head, body).iter().enumerate() {
            match run(raw) {
                Ok(record) => assert!(flagged(&record) || listed(&record), "{raw:?} -> {record:?}"),
                Err(error) => assert!(place == 0 && error.to_string() == "the bytes are not a message", "{raw:?}: {error}"),
            }
        }
    }
    Ok(())
}


#[test]
fn a_bare_cr_in_a_part_header_reads_as_markup() -> Result<(), Box<dyn std::error::Error>> {
    for raw in placements("X-A: 1\rContent-Type: text/html\r\n", LINK) {
        let record = run(&raw)?;
        assert!(listed(&record), "{raw:?} -> {record:?}");
    }
    Ok(())
}


#[test]
fn an_ordinary_plain_part_is_not_flagged() -> Result<(), Box<dyn std::error::Error>> {
    let record = run("From: p@sender.test\r\nContent-Type: text/plain\r\n\r\nhello https://a.test/x\r\n")?;
    assert!(!flagged(&record));
    Ok(())
}


#[test]
fn a_blanked_part_is_read_as_markup_and_the_record_is_flagged() -> Result<(), Box<dyn std::error::Error>> {
    let placed = placements(&part_headers("text/html (x)", "quoted-printable"), LINK);
    let raw = placed.get(1).ok_or("mixed")?;
    let record = run(raw)?;
    assert!(flagged(&record), "{record:?}");
    assert!(listed(&record), "{record:?}");
    Ok(())
}
