use phishing_report::auth::{oversized_id, oversized_untrusted};
use phishing_report::limits::Limits;
use phishing_report::model::{ReporterPolicy, Triage};
use phishing_report::triage::triage_with;


const ID: &str = "mx.example.org";


const TRUSTED_PASS: &str = "Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass header.from=a.example";


const BIG: usize = 17_000;


const SMALL_BOUND: usize = 100;


const THOUSANDS: usize = 1000;


const HEADER_CAP: usize = 8;


const SEVEN: usize = 7;


const FORTY: usize = 40;


const ELEVEN: usize = 11;


const TWELVE: usize = 12;


fn trusted() -> Vec<String> {
    vec![ID.to_owned()]
}


fn mail(headers: &[String]) -> String {
    format!("{}\r\nFrom: a@b.example\r\nSubject: x\r\n\r\nhello\r\n", headers.join("\r\n"))
}


fn run(headers: &[String], limits: &Limits) -> Result<Triage, Box<dyn std::error::Error>> {
    Ok(triage_with(mail(headers).as_bytes(), &trusted(), &ReporterPolicy::default(), limits)?)
}


fn trusted_pass() -> String {
    TRUSTED_PASS.to_owned()
}


fn closed(record: &Triage) -> bool {
    record.auth.reason.as_deref() == Some("oversized_header")
}


fn foreign(id: &str) -> String {
    format!("Authentication-Results: {id}; none (x{})", "x".repeat(BIG))
}


#[test]
fn an_oversized_foreign_header_beside_a_trusted_pass_keeps_the_pass() -> Result<(), Box<dyn std::error::Error>> {
    let record = run(&[trusted_pass(), foreign("other.test")], &Limits::default())?;
    assert_eq!(record.auth.dmarc, "pass");
    assert_eq!(record.auth.reason, None);
    assert_eq!(record.counts.auth_oversized_untrusted, 1);
    assert_eq!(record.counts.headers_skipped, 1);
    let before = run(&[foreign("other.test"), trusted_pass()], &Limits::default())?;
    assert_eq!(before.auth.dmarc, "pass");
    let dotted = run(&[trusted_pass(), foreign("mx.example.org.")], &Limits::default())?;
    assert_eq!(dotted.auth.dmarc, "pass");
    assert_eq!(dotted.counts.auth_oversized_untrusted, 1);
    Ok(())
}


#[test]
fn an_oversized_header_of_the_trusted_id_fails_closed_in_every_spelling() -> Result<(), Box<dyn std::error::Error>> {
    let pad = "y".repeat(BIG);
    let spellings = [
        foreign(ID),
        foreign("MX.Example.ORG"),
        format!("Authentication-Results:\r\n   \t{ID}; none (x{pad})"),
        format!("Authentication-Results: (a (nested) comment) {ID}; none (x{pad})"),
        format!("Authentication-Results: ({pad}) {ID}; spf=pass"),
        format!("Authentication-Results: ((x{pad})) {ID}; spf=pass"),
        format!("Authentication-Results: \"{pad}\" {ID}; spf=pass"),
        format!("Authentication-Results: ({pad}\\) {ID}; spf=pass"),
        format!("Authentication-Results: {pad}{ID}; spf=pass"),
        format!("Authentication-Results: (unbalanced {pad}"),
    ];
    spellings.iter().try_for_each(|header| {
        let record = run(&[trusted_pass(), header.clone()], &Limits::default())?;
        assert!(closed(&record), "{}", header.chars().take(SMALL_BOUND).collect::<String>());
        assert_eq!(record.counts.auth_oversized_untrusted, 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn an_id_cut_at_the_bound_fails_closed_and_one_ended_inside_it_is_read() -> Result<(), Box<dyn std::error::Error>> {
    let short = "Authentication-Results: mx.example.org; dmarc=pass".to_owned();
    let ended = format!("Authentication-Results: other.test; none (x{})", "x".repeat(SMALL_BOUND));
    let cut = format!("Authentication-Results: {}; none", "z".repeat(SMALL_BOUND));
    let limits = Limits {
        header_bytes: FORTY,
        ..Limits::default()
    };
    let read = run(&[short.clone(), ended], &limits)?;
    assert_eq!(read.counts.auth_oversized_untrusted, 1);
    assert_eq!(read.auth.dmarc, "pass");
    let failed = run(&[short, cut], &limits)?;
    assert_eq!(failed.counts.auth_oversized_untrusted, 0);
    assert!(closed(&failed));
    Ok(())
}


#[test]
fn a_multibyte_character_across_the_bound_does_not_panic() -> Result<(), Box<dyn std::error::Error>> {
    let header = format!("Authentication-Results: other.t\u{e9}\u{e9}st; none ({})", "x".repeat(SMALL_BOUND));
    let results = (SEVEN..TWELVE + SEVEN)
        .map(|bound| {
            let limits = Limits {
                header_bytes: bound,
                ..Limits::default()
            };
            run(&[trusted_pass(), header.clone()], &limits).map(|record| record.counts.auth_oversized_untrusted)
        })
        .collect::<Result<Vec<usize>, _>>()?;
    assert!(results.iter().all(|count| *count <= 1));
    Ok(())
}


#[test]
fn thousands_of_oversized_foreign_headers_are_counted_inside_the_header_cap() -> Result<(), Box<dyn std::error::Error>> {
    let mut headers = vec![trusted_pass()];
    headers.extend((0..THOUSANDS).map(|_| foreign("other.test")));
    let limits = Limits {
        headers: HEADER_CAP,
        ..Limits::default()
    };
    let record = run(&headers, &limits)?;
    assert_eq!(record.counts.auth_oversized_untrusted, SEVEN);
    assert_eq!(record.auth.dmarc, "pass");
    Ok(())
}


#[test]
fn the_id_reader_follows_the_header_tokenizer() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(oversized_id(b" mx.Example.org; spf=pass").as_deref(), Some(ID));
    assert_eq!(oversized_id(b" (c) mx.example.org (d) spf").as_deref(), Some(ID));
    assert_eq!(oversized_id(b" ;spf=pass").as_deref(), Some(""));
    assert_eq!(oversized_id(b" \"a b\" c").as_deref(), Some("\"a"));
    assert_eq!(oversized_id(b"   "), None);
    assert_eq!(oversized_id(b" mx.example.org"), None);
    assert_eq!(oversized_id(b" \"mx.example.org; x"), None);
    assert_eq!(oversized_id(b" (mx.example.org; x"), None);
    assert_eq!(oversized_id(b""), None);
    assert_eq!(oversized_id(b" ab\xff ").as_deref(), Some("ab\u{fffd}"));
    Ok(())
}


#[test]
fn the_untrusted_verdict_needs_a_readable_foreign_id() -> Result<(), Box<dyn std::error::Error>> {
    let ids = trusted();
    assert!(oversized_untrusted(Some(b" other.test; x"), SMALL_BOUND, &ids));
    assert!(oversized_untrusted(Some(b" other.test; x"), TWELVE, &ids));
    assert!(!oversized_untrusted(Some(b" other.test; x"), ELEVEN, &ids));
    assert!(!oversized_untrusted(Some(b" mx.example.org; x"), SMALL_BOUND, &ids));
    assert!(!oversized_untrusted(Some(b" (mx.example.org; x"), SMALL_BOUND, &ids));
    assert!(!oversized_untrusted(None, SMALL_BOUND, &ids));
    Ok(())
}
