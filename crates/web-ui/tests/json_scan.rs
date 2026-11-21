use std::error::Error;
use types::TestResult;
use web_ui::api::{scan_cert_detail, scan_cert_list, scan_hunt_list, HUNT_LIMIT, MAX_BODY_BYTES, MAX_CERT_DNS_NAMES, MAX_CERT_SIGHTINGS, MAX_ITEMS};
use web_ui::error::ApiFailure;
use web_ui::model::Language;
use web_ui::pages::clip;


#[path = "support/types.rs"]
mod types;


const MARKER: &str = "peer-json-marker";


const CLIP_LIMIT: usize = 64;


const SHORT_LIMIT: usize = 4;


const BYTES_PER_NAME: usize = 3;


const ENVELOPE_SLACK: usize = 64;


fn names_of(count: usize) -> String {
    vec!["\"\""; count].join(",")
}


#[test]
fn clip_marks_every_refused_character_and_keeps_nfd() -> TestResult {
    let cases = [
        ("ad\u{3164}min.corp", "ad\u{fffd}min.corp"),
        ("x\u{202e}y", "x\u{fffd}y"),
        ("x\u{1b}[31m", "x\u{fffd}[31m"),
        ("a\u{200b}b", "a\u{fffd}b"),
        ("cafe\u{301}", "cafe\u{301}"),
        ("admin.corp", "admin.corp"),
    ];
    cases
        .iter()
        .for_each(|(input, shown)| assert_eq!(clip(Language::English, input, CLIP_LIMIT), *shown));
    assert_ne!(
        clip(Language::English, "ad\u{3164}min.corp", CLIP_LIMIT),
        clip(Language::English, "admin.corp", CLIP_LIMIT)
    );
    assert_eq!(
        clip(Language::English, "\u{1b}\u{1b}\u{1b}abc", SHORT_LIMIT),
        "\u{fffd}\u{fffd}\u{fffd}a... [2 omitted]"
    );
    Ok(())
}


#[test]
fn a_json_failure_holds_no_peer_text() -> TestResult {
    let body = format!("{{\"items\": \"{MARKER}\"}}");
    let failure = scan_cert_list(body.as_bytes()).err().ok_or("no failure")?;
    assert!(matches!(
        failure,
        ApiFailure::Json {
            category: "data",
            line: 1,
            ..
        }
    ));
    let truncated = ApiFailure::from(serde_json::from_str::<Vec<u8>>("[").err().ok_or("no error")?);
    assert!(matches!(truncated, ApiFailure::Json { category: "eof", .. }));
    let syntax = ApiFailure::from(serde_json::from_str::<u8>("x").err().ok_or("no error")?);
    assert!(matches!(syntax, ApiFailure::Json { category: "syntax", .. }));
    let io_failure = ApiFailure::from(serde_json::Error::io(std::io::Error::other(MARKER)));
    assert!(matches!(io_failure, ApiFailure::Json { category: "io", .. }));
    [failure, io_failure].iter().for_each(|shown| {
        assert!(!format!("{shown}").contains(MARKER));
        assert!(!format!("{shown:?}").contains(MARKER));
        assert!(shown.source().is_none());
    });
    Ok(())
}


#[test]
fn a_list_of_empty_names_is_refused_before_the_typed_decode() -> TestResult {
    let names = names_of(MAX_BODY_BYTES / BYTES_PER_NAME);
    let body = format!("{{\"items\":[{{\"dns_names\":[{names}]}}]}}");
    assert!(body.len() <= MAX_BODY_BYTES + ENVELOPE_SLACK);
    let failure = scan_cert_list(body.as_bytes()).err().ok_or("accepted")?;
    assert!(matches!(failure, ApiFailure::Malformed("too many DNS names")));
    let detail = format!("{{\"dns_names\":[{names}],\"sightings\":[]}}");
    let refused = scan_cert_detail(detail.as_bytes()).err().ok_or("accepted")?;
    assert!(matches!(refused, ApiFailure::Malformed("too many DNS names")));
    Ok(())
}


#[test]
fn counts_at_the_bound_pass_and_one_more_is_refused() -> TestResult {
    let at_bound = format!("{{\"items\":[{}]}}", vec!["{\"dns_names\":[]}"; MAX_ITEMS].join(","));
    scan_cert_list(at_bound.as_bytes())?;
    let over = format!("{{\"items\":[{}]}}", vec!["{\"dns_names\":[]}"; MAX_ITEMS + 1].join(","));
    assert!(matches!(scan_cert_list(over.as_bytes()), Err(ApiFailure::Malformed("too many items"))));
    let names_ok = format!("{{\"items\":[{{\"dns_names\":[{}]}}]}}", names_of(MAX_CERT_DNS_NAMES));
    scan_cert_list(names_ok.as_bytes())?;
    let bad_item = "{\"items\":[1]}";
    assert!(matches!(scan_cert_list(bad_item.as_bytes()), Err(ApiFailure::Json { .. })));
    let sightings_ok = format!("{{\"dns_names\":[],\"sightings\":[{}]}}", names_of(MAX_CERT_SIGHTINGS));
    scan_cert_detail(sightings_ok.as_bytes())?;
    let sightings_over = format!("{{\"dns_names\":[],\"sightings\":[{}]}}", names_of(MAX_CERT_SIGHTINGS + 1));
    assert!(matches!(
        scan_cert_detail(sightings_over.as_bytes()),
        Err(ApiFailure::Malformed("too many sightings"))
    ));
    Ok(())
}


#[test]
fn a_hunt_list_over_the_limit_sent_is_refused_before_the_typed_decode() -> TestResult {
    let at_bound = format!("{{\"items\":[{}]}}", names_of(HUNT_LIMIT as usize));
    scan_hunt_list(at_bound.as_bytes())?;
    let over = format!("{{\"items\":[{}]}}", names_of(HUNT_LIMIT as usize + 1));
    assert!(matches!(scan_hunt_list(over.as_bytes()), Err(ApiFailure::Malformed("too many items"))));
    let huge = format!("{{\"items\":[{}]}}", names_of(MAX_BODY_BYTES / BYTES_PER_NAME));
    assert!(matches!(scan_hunt_list(huge.as_bytes()), Err(ApiFailure::Malformed("too many items"))));
    let wrong = format!("{{\"items\": \"{MARKER}\"}}");
    let failure = scan_hunt_list(wrong.as_bytes()).err().ok_or("accepted")?;
    assert!(!format!("{failure}").contains(MARKER) && !format!("{failure:?}").contains(MARKER));
    Ok(())
}
