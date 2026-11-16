#[path = "common/standin.rs"]
mod standin;
#[path = "common/support.rs"]
mod support;
#[path = "common/types.rs"]
mod types;


use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use intel_feeds::config::{FeedConfig, FeedFormat, TaxiiConfig};
use intel_feeds::error::{EntryError, FeedError, TaxiiError};
use intel_feeds::formats::parse_feed;
use intel_feeds::limits::{MAX_DOCUMENT_BYTES, MAX_OBJECT_BYTES, MAX_TAXII_NEXT_BYTES, MAX_TAXII_OBJECTS_PER_PAGE};
use intel_feeds::model::{Collector, FeedSummary};
use intel_feeds::taxii::{
    absorb_page, basic_header, has_room, next_token_ok, object_iocs, page_objects, parse_cursor, poll_collection, poll_feed, request_pairs,
    settle_cursor, status_error, taxii_agent, transport_error, CursorStatus, Envelope, Page, PollOutcome, PollState,
};
use serde_json::{json, Value};
use siem_ingest::clickhouse::new_agent;
use standin::{reply, requests, start, with_header, Reply, Standin};
use std::fs;
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use support::feed;
use tempfile::tempdir;
use time::macros::datetime;
use time::{Date, OffsetDateTime, Time};
use tracing::Dispatch;
use types::TestResult;


const SECRET_MODE: u32 = 0o600;


#[cfg(unix)]
const GROUP_MODE: u32 = 0o640;


const BODY: &str = "{\"more\":false,\"objects\":[{\"type\":\"indicator\",\"pattern\":\"[domain-name:value = 'bad.example']\"}]}";


const BODY_MARK: &str = "BODYMARK-31ab";


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


const STATUS_OK: u16 = 200;


const MANY_PAGES: u32 = 10;


const PREVIOUS: OffsetDateTime = datetime!(2026-11-01 00:00:00 UTC);


const LAST_THREE: OffsetDateTime = datetime!(2026-11-03 11:03:00 UTC);


const ELEVEN: OffsetDateTime = datetime!(2026-11-03 11:00:00 UTC);


const FRACTION: OffsetDateTime = datetime!(2026-11-03 11:00:00.123 UTC);


const SKEW_EDGE: OffsetDateTime = datetime!(2026-11-03 12:05:00 UTC);


const SHIFTED: OffsetDateTime = datetime!(2026-11-01 02:00:00 +02:00);


const OUT_OF_RANGE: OffsetDateTime = datetime!(9999-12-31 23:00:00 -02:00);


const NOW: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const COLLECTION: &str = "91a7b528-80eb-42ed-a74d-c6fbd5a26116";


const PASSWORD: &str = "TAXIIPW-77c1";


const USER: &str = "analyst";


const LONG_TIMEOUT_MS: u64 = 600_000;


const SHORT_TIMEOUT_MS: u64 = 500;


const PAGE_LIMIT: u32 = 500;


const THREE: u32 = 3;


const TWO: u32 = 2;


const BAD_TOKENS: [&str; 8] = ["a/b", "a&b=c", "a?b", "https://evil.example/x", "", "a b", "caf\u{e9}", "a%2Fb"];


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const DATE_HEADER: &str = "X-TAXII-Date-Added-Last";


const SECRET_BODY: &str = "SERVERSECRET-0d5f";


const STATUS_CASES: [(u16, &str); 11] = [
    (401, "the TAXII server refused the credentials"),
    (403, "the TAXII server refused the credentials"),
    (404, "the TAXII collection is unknown to the server"),
    (406, "the TAXII server refused version 2.1"),
    (415, "the TAXII server refused version 2.1"),
    (429, "the TAXII server is unavailable"),
    (500, "the TAXII server is unavailable"),
    (503, "the TAXII server is unavailable"),
    (418, "the TAXII server answered status 418"),
    (302, "the TAXII server answered status 302"),
    (204, "the TAXII server answered status 204"),
];


fn idle() -> Duration {
    Duration::ZERO
}


fn spent() -> Duration {
    Duration::from_millis(LONG_TIMEOUT_MS)
}


fn indicator(host: u32) -> Value {
    json!({
        "type": "indicator",
        "spec_version": "2.1",
        "id": format!("indicator--00000000-0000-4000-8000-{host:012}"),
        "created": "2026-11-01T00:00:00.000Z",
        "modified": "2026-11-02T00:00:00.000Z",
        "valid_from": "2026-11-01T00:00:00.000Z",
        "pattern_type": "stix",
        "pattern": format!("[ipv4-addr:value = '203.0.113.{host}']"),
    })
}


fn envelope(objects: &[Value], more: bool, next: Option<&str>) -> String {
    json!({ "more": more, "next": next, "objects": objects }).to_string()
}


fn taxii_feed(port: u16, max_pages: u32) -> FeedConfig {
    let mut config = feed("hub", FeedFormat::Taxii21);
    config.taxii = Some(TaxiiConfig {
        api_root: format!("https://127.0.0.1:{port}/taxii2/root/"),
        collection: COLLECTION.to_owned(),
        user: USER.to_owned(),
        password_file: PathBuf::from("password"),
        ca_file: None,
        timeout_ms: LONG_TIMEOUT_MS,
        max_pages,
        page_limit: PAGE_LIMIT,
    });
    config
}


fn attempt_with(
    standin: &Standin,
    config: &FeedConfig,
    after: Option<OffsetDateTime>,
    elapsed: &dyn Fn() -> Duration,
) -> Result<Result<PollOutcome, TaxiiError>, Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let agent = new_agent(Some(standin.ca_pem.as_bytes()), true)?;
    Ok(poll_collection(&agent, config, PASSWORD.as_bytes(), after, NOW, elapsed))
}


fn attempt(
    standin: &Standin,
    config: &FeedConfig,
    after: Option<OffsetDateTime>,
) -> Result<Result<PollOutcome, TaxiiError>, Box<dyn std::error::Error>> {
    attempt_with(standin, config, after, &idle)
}


fn expected_auth() -> String {
    format!("Basic {}", STANDARD.encode(format!("{USER}:{PASSWORD}")))
}


fn pages_handler(total: usize) -> impl Fn(&str, &str) -> Reply + Send + Sync + 'static {
    move |_method, target| {
        let page = (1..total).find(|number| target.contains(&format!("next=p{}", number + 1))).unwrap_or(0);
        let host = u32::try_from(page + 1).unwrap_or(0);
        let more = page + 1 < total;
        let next = format!("p{}", page + TWO as usize);
        with_header(
            reply(STATUS_OK, &envelope(&[indicator(host)], more, more.then_some(next.as_str()))),
            DATE_HEADER,
            &format!("2026-11-03T11:0{}:00.000Z", page + 1),
        )
    }
}


fn fixed(body: String, header: Option<&'static str>) -> impl Fn(&str, &str) -> Reply + Send + Sync + 'static {
    move |_method, _target| {
        header.map_or_else(
            || reply(STATUS_OK, &body),
            |value| with_header(reply(STATUS_OK, &body), DATE_HEADER, value),
        )
    }
}


#[test]
fn three_pages_are_followed_and_the_cursor_is_the_last_header() -> TestResult {
    let standin = start(pages_handler(THREE as usize))?;
    let config = taxii_feed(standin.port, MANY_PAGES);
    let outcome = attempt(&standin, &config, Some(PREVIOUS))??;
    assert_eq!((outcome.pages, outcome.more_left, outcome.next_refused), (THREE, false, false));
    assert_eq!(outcome.iocs.len(), THREE as usize);
    assert_eq!(outcome.summary.parsed, u64::from(THREE));
    assert_eq!((outcome.cursor, outcome.next_added_after), (CursorStatus::Advanced, Some(LAST_THREE)));
    let base = format!("GET /taxii2/root/collections/{COLLECTION}/objects/?added_after=2026-11-01T00%3A00%3A00Z&limit=500&match%5Btype%5D=indicator");
    let auth = format!(" auth={}", expected_auth());
    assert_eq!(
        requests(&standin),
        vec![format!("{base}{auth}"), format!("{base}&next=p2{auth}"), format!("{base}&next=p3{auth}")]
    );
    Ok(())
}


#[test]
fn the_page_cap_stops_a_server_that_never_ends() -> TestResult {
    let standin = start(|_method, _target| {
        with_header(
            reply(STATUS_OK, &envelope(&[indicator(1)], true, Some("again"))),
            DATE_HEADER,
            "2026-11-03T11:00:00Z",
        )
    })?;
    let outcome = attempt(&standin, &taxii_feed(standin.port, TWO), None)??;
    assert_eq!((outcome.pages, outcome.more_left, outcome.next_refused), (TWO, true, false));
    let log = requests(&standin);
    assert_eq!(log.len(), TWO as usize);
    assert!(log.iter().all(|entry| !entry.contains("added_after")));
    assert_eq!(outcome.next_added_after, Some(ELEVEN));
    Ok(())
}


#[test]
fn a_next_with_more_false_is_not_followed() -> TestResult {
    let standin = start(fixed(envelope(&[indicator(1)], false, Some("ignored")), None))?;
    let outcome = attempt(&standin, &taxii_feed(standin.port, THREE), None)??;
    assert_eq!((outcome.pages, outcome.more_left, requests(&standin).len()), (1, false, 1));
    Ok(())
}


#[test]
fn an_oversized_body_is_refused() -> TestResult {
    let standin = start(|_method, _target| {
        let mut answer = reply(STATUS_OK, "");
        answer.body = vec![b' '; MAX_DOCUMENT_BYTES + TWO as usize];
        answer.declared = answer.body.len();
        answer
    })?;
    let error = attempt(&standin, &taxii_feed(standin.port, 1), None)?.err().ok_or("no error")?;
    assert!(matches!(error, TaxiiError::PageTooLarge));
    Ok(())
}


#[test]
fn a_page_of_tiny_objects_is_refused_before_it_is_materialised() -> TestResult {
    let many = format!(
        "{{\"more\":false,\"objects\":[{}]}}",
        vec!["{}"; MAX_TAXII_OBJECTS_PER_PAGE + 1].join(",")
    );
    let standin = start(fixed(many, None))?;
    let refused = attempt(&standin, &taxii_feed(standin.port, 1), None)?.err().ok_or("no error")?;
    assert!(matches!(refused, TaxiiError::TooManyObjects));
    Ok(())
}


#[test]
fn the_object_count_is_exact_and_ignores_text_inside_strings() -> TestResult {
    let wrap = |item: &str, count: usize| format!("{{\"objects\":[{}]}}", vec![item; count].join(","));
    let exact = wrap("{}", MAX_TAXII_OBJECTS_PER_PAGE);
    let parsed: Envelope = serde_json::from_str(&exact)?;
    assert_eq!(page_objects(parsed.objects)?.len(), MAX_TAXII_OBJECTS_PER_PAGE);
    let one_more = wrap("{}", MAX_TAXII_OBJECTS_PER_PAGE + 1);
    let excess: Envelope = serde_json::from_str(&one_more)?;
    assert!(matches!(page_objects(excess.objects), Err(TaxiiError::TooManyObjects)));
    let noisy_text = wrap(r#"{"a":"x,\"y,\\","b":[1,2,3],"c":{"d":[4,5]}}"#, MAX_TAXII_OBJECTS_PER_PAGE);
    let noisy: Envelope = serde_json::from_str(&noisy_text)?;
    assert_eq!(page_objects(noisy.objects)?.len(), MAX_TAXII_OBJECTS_PER_PAGE);
    let nothing: Envelope = serde_json::from_str("{}")?;
    assert!(page_objects(nothing.objects)?.is_empty());
    let scalar: Envelope = serde_json::from_str("{\"objects\":5}")?;
    assert!(matches!(page_objects(scalar.objects), Err(TaxiiError::Envelope(_))));
    Ok(())
}


#[test]
fn a_bad_object_is_skipped_and_counted_never_fatal() -> TestResult {
    let broken = json!({ "type": "indicator", "id": "indicator--1" });
    let unsupported = json!({ "type": "indicator", "pattern": "[a AND b]" });
    let other = json!({ "type": "malware", "name": "x" });
    let huge = json!({ "type": "indicator", "pattern": "x".repeat(MAX_OBJECT_BYTES) });
    let body = envelope(&[indicator(1), broken, unsupported, other, huge, indicator(TWO)], false, None);
    let standin = start(fixed(body, None))?;
    let outcome = attempt(&standin, &taxii_feed(standin.port, 1), None)??;
    assert_eq!(outcome.iocs.len(), TWO as usize);
    assert_eq!(outcome.summary.skipped.get("missing_field"), Some(&1));
    assert_eq!(outcome.summary.skipped.get("object_too_large"), Some(&1));
    assert_eq!(outcome.summary.unsupported, 1);
    assert_eq!((outcome.cursor, outcome.next_added_after), (CursorStatus::Missing, None));
    Ok(())
}


#[test]
fn an_unparsable_object_text_is_a_skip() -> TestResult {
    let config = feed("hub", FeedFormat::Taxii21);
    assert!(matches!(object_iocs(&config, NOW, "{"), Err(EntryError::NotAnObject)));
    assert!(object_iocs(&config, NOW, &json!({ "type": "x" }).to_string())?.is_empty());
    Ok(())
}


#[test]
fn a_page_that_is_not_an_envelope_is_refused() -> TestResult {
    let standin = start(fixed("not json".to_owned(), None))?;
    let error = attempt(&standin, &taxii_feed(standin.port, 1), None)?.err().ok_or("no error")?;
    assert!(matches!(error, TaxiiError::Envelope(_)));
    let direct = absorb_page(
        &taxii_feed(1, 1),
        NOW,
        PollState {
            collector: Collector::default(),
            next: None,
            more: true,
            stalled: false,
            pages: 0,
            numbered: 0,
            last_added: None,
        },
        Page {
            body: b"5".to_vec(),
            last_added: None,
        },
    );
    assert!(matches!(direct, Err(TaxiiError::Envelope(_))));
    Ok(())
}


#[test]
fn every_status_class_is_a_fixed_error_without_server_text() -> TestResult {
    STATUS_CASES.iter().try_for_each(|(status, text)| -> TestResult {
        let code = *status;
        let standin = start(move |_method, _target| with_header(reply(code, SECRET_BODY), "Location", "http://169.254.169.254/latest"))?;
        let error = attempt(&standin, &taxii_feed(standin.port, THREE), None)?.err().ok_or("no error")?;
        assert_eq!(error.to_string(), *text);
        assert_eq!(status_error(code).to_string(), *text);
        let shown = format!("{error} {error:?}");
        assert!(!shown.contains(SECRET_BODY) && !shown.contains(PASSWORD) && !shown.contains("Basic") && !shown.contains("169.254"));
        assert_eq!(requests(&standin).len(), 1);
        Ok(())
    })
}


#[test]
fn a_next_that_is_not_an_opaque_token_stops_the_poll_loudly() -> TestResult {
    let oversized = "x".repeat(MAX_TAXII_NEXT_BYTES + 1);
    let mut tokens = BAD_TOKENS.iter().copied().chain([oversized.as_str()]);
    tokens.try_for_each(|token| -> TestResult {
        let body = envelope(&[indicator(1)], true, Some(token));
        let standin = start(fixed(body, Some("2026-11-03T11:00:00Z")))?;
        let outcome = attempt(&standin, &taxii_feed(standin.port, THREE), None)??;
        assert_eq!((outcome.pages, outcome.more_left, outcome.next_refused), (1, true, true), "{token}");
        assert_eq!(requests(&standin).len(), 1);
        assert_eq!(outcome.iocs.len(), 1);
        assert_eq!(outcome.cursor, CursorStatus::Advanced);
        assert!(!next_token_ok(token));
        Ok(())
    })?;
    let standin = start(fixed(json!({ "more": true, "objects": [] }).to_string(), None))?;
    let absent = attempt(&standin, &taxii_feed(standin.port, THREE), None)??;
    assert_eq!(
        (absent.pages, absent.more_left, absent.next_refused, requests(&standin).len()),
        (1, true, true, 1)
    );
    Ok(())
}


#[test]
fn an_allowed_token_travels_as_one_query_value() -> TestResult {
    let token = "AbC-1_2.3~4=5+6";
    assert!(next_token_ok(token) && next_token_ok(&"x".repeat(MAX_TAXII_NEXT_BYTES)));
    let config = taxii_feed(1, 1);
    let taxii = config.taxii.as_ref().ok_or("no section")?;
    assert_eq!(
        request_pairs(taxii, None, Some(token)),
        vec![
            ("limit", "500".to_owned()),
            ("match[type]", "indicator".to_owned()),
            ("next", token.to_owned())
        ]
    );
    let first = envelope(&[indicator(1)], true, Some(token));
    let second = envelope(&[indicator(TWO)], false, None);
    let standin = start(move |_method, target| reply(STATUS_OK, if target.contains("next=") { &second } else { &first }))?;
    let outcome = attempt(&standin, &taxii_feed(standin.port, THREE), None)??;
    assert_eq!(outcome.pages, TWO);
    let log = requests(&standin);
    let last = log.last().ok_or("no request")?;
    assert!(last.contains("&next=AbC-1_2.3~4%3D5%2B6 auth="), "{last}");
    Ok(())
}


#[test]
fn the_cursor_is_sent_in_utc_and_an_unwritable_one_sends_nothing() -> TestResult {
    let standin = start(fixed(envelope(&[], false, None), None))?;
    let shifted = SHIFTED;
    attempt(&standin, &taxii_feed(standin.port, 1), Some(shifted))??;
    let log = requests(&standin);
    assert!(
        log.iter().any(|entry| entry.contains("added_after=2026-11-01T00%3A00%3A00Z&limit=500")),
        "{log:?}"
    );
    let unwritable = OffsetDateTime::new_utc(Date::MIN, Time::MIDNIGHT);
    let error = attempt(&standin, &taxii_feed(standin.port, 1), Some(unwritable))?
        .err()
        .ok_or("no error")?;
    assert!(matches!(error, TaxiiError::Cursor(_)));
    let out_of_range = OUT_OF_RANGE;
    let range_error = attempt(&standin, &taxii_feed(standin.port, 1), Some(out_of_range))?
        .err()
        .ok_or("no error")?;
    assert!(matches!(range_error, TaxiiError::CursorRange));
    assert_eq!(requests(&standin).len(), 1);
    Ok(())
}


#[test]
fn the_cursor_header_is_checked_and_the_old_cursor_is_kept() -> TestResult {
    let previous = PREVIOUS;
    let cases = [
        ("2026-11-03T11:00:00.123Z", CursorStatus::Advanced, Some(FRACTION)),
        ("2026-11-03T13:00:00+02:00", CursorStatus::Advanced, Some(ELEVEN)),
        ("2026-11-03T12:05:00Z", CursorStatus::Advanced, Some(SKEW_EDGE)),
        ("2026-11-03T12:05:01Z", CursorStatus::InFuture, Some(previous)),
        ("2030-01-01T00:00:00Z", CursorStatus::InFuture, Some(previous)),
        ("yesterday", CursorStatus::Malformed, Some(previous)),
        ("10000-01-01T00:00:00Z", CursorStatus::Malformed, Some(previous)),
        ("9999-12-31T23:00:00-02:00", CursorStatus::Malformed, Some(previous)),
        ("0000-01-01T00:00:00+00:01", CursorStatus::Malformed, Some(previous)),
        ("", CursorStatus::Malformed, Some(previous)),
    ];
    cases.iter().try_for_each(|(text, status, expected)| -> TestResult {
        assert_eq!(settle_cursor(Some(previous), Some(text.as_bytes()), NOW), (*expected, *status), "{text}");
        Ok(())
    })?;
    let long = "2".repeat(MAX_TAXII_NEXT_BYTES);
    assert_eq!(
        settle_cursor(Some(previous), Some(long.as_bytes()), NOW),
        (Some(previous), CursorStatus::Malformed)
    );
    assert_eq!(
        settle_cursor(Some(previous), Some(&NOT_UTF8), NOW),
        (Some(previous), CursorStatus::Malformed)
    );
    assert_eq!(settle_cursor(Some(previous), None, NOW), (Some(previous), CursorStatus::Missing));
    assert_eq!(settle_cursor(None, None, NOW), (None, CursorStatus::Missing));
    assert!(parse_cursor(b" 2026-11-03T11:00:00Z ", NOW).is_ok());
    Ok(())
}


#[test]
fn a_future_cursor_header_keeps_the_old_cursor_end_to_end() -> TestResult {
    let previous = PREVIOUS;
    let standin = start(fixed(envelope(&[indicator(1)], false, None), Some("2030-01-01T00:00:00Z")))?;
    let outcome = attempt(&standin, &taxii_feed(standin.port, 1), Some(previous))??;
    assert_eq!((outcome.cursor, outcome.next_added_after), (CursorStatus::InFuture, Some(previous)));
    let malformed = start(fixed(envelope(&[indicator(1)], false, None), Some("yesterday")))?;
    let kept = attempt(&malformed, &taxii_feed(malformed.port, 1), Some(previous))??;
    assert_eq!((kept.cursor, kept.next_added_after), (CursorStatus::Malformed, Some(previous)));
    Ok(())
}


#[test]
fn a_spent_deadline_sends_nothing() -> TestResult {
    let standin = start(fixed(envelope(&[indicator(1)], false, None), None))?;
    let error = attempt_with(&standin, &taxii_feed(standin.port, 1), None, &spent)?
        .err()
        .ok_or("no error")?;
    assert!(matches!(error, TaxiiError::Timeout));
    assert!(requests(&standin).is_empty());
    Ok(())
}


#[test]
fn a_timeout_before_the_headers_is_a_timeout() -> TestResult {
    assert!(matches!(
        transport_error(ureq::Error::Timeout(ureq::Timeout::Global)),
        TaxiiError::Timeout
    ));
    assert!(matches!(transport_error(ureq::Error::ConnectionFailed), TaxiiError::Transport(_)));
    Ok(())
}


#[test]
fn a_body_cut_short_is_a_body_error_with_its_cause() -> TestResult {
    let standin = start(|_method, _target| {
        let mut answer = reply(STATUS_OK, "{\"more\":");
        answer.declared = MAX_TAXII_NEXT_BYTES;
        answer
    })?;
    let error = attempt(&standin, &taxii_feed(standin.port, 1), None)?.err().ok_or("no error")?;
    assert!(matches!(error, TaxiiError::Body(_)), "{error}");
    assert!(std::error::Error::source(&error).is_some());
    Ok(())
}


#[test]
fn a_body_that_stalls_hits_the_timeout() -> TestResult {
    let standin = start(|_method, _target| {
        let mut answer = reply(STATUS_OK, "{\"more\":");
        answer.declared = MAX_DOCUMENT_BYTES;
        answer.hold = true;
        answer
    })?;
    let mut config = taxii_feed(standin.port, 1);
    config.taxii.as_mut().ok_or("no section")?.timeout_ms = SHORT_TIMEOUT_MS;
    let error = attempt(&standin, &config, None)?.err().ok_or("no error")?;
    assert!(matches!(error, TaxiiError::Timeout), "{error}");
    Ok(())
}


#[test]
fn an_untrusted_certificate_is_a_transport_error_with_a_fixed_text() -> TestResult {
    let standin = start(fixed(envelope(&[], false, None), None))?;
    let agent = new_agent(None, true)?;
    let error = poll_collection(&agent, &taxii_feed(standin.port, 1), PASSWORD.as_bytes(), None, NOW, &idle)
        .err()
        .ok_or("no error")?;
    assert!(matches!(error, TaxiiError::Transport(_)));
    assert_eq!(error.to_string(), "the TAXII request failed");
    assert!(!format!("{error:?}").contains(PASSWORD));
    Ok(())
}


#[test]
fn a_feed_without_a_taxii_section_or_with_a_bad_one_does_no_io() -> TestResult {
    let standin = start(fixed(envelope(&[indicator(1)], false, None), None))?;
    let agent = new_agent(Some(standin.ca_pem.as_bytes()), true)?;
    let bare = feed("hub", FeedFormat::Taxii21);
    assert!(matches!(
        poll_collection(&agent, &bare, PASSWORD.as_bytes(), None, NOW, &idle),
        Err(TaxiiError::NoSection)
    ));
    assert!(matches!(poll_feed(&bare, None, NOW, &idle), Err(TaxiiError::NoSection)));
    let mut bad = taxii_feed(standin.port, 1);
    bad.taxii.as_mut().ok_or("no section")?.collection = "../x".to_owned();
    assert!(matches!(
        poll_collection(&agent, &bad, PASSWORD.as_bytes(), None, NOW, &idle),
        Err(TaxiiError::Settings(_))
    ));
    assert!(matches!(poll_feed(&bad, None, NOW, &idle), Err(TaxiiError::Settings(_))));
    assert!(requests(&standin).is_empty());
    Ok(())
}


#[test]
fn the_basic_header_is_user_colon_password() -> TestResult {
    assert_eq!(basic_header(USER, PASSWORD.as_bytes()).as_str(), expected_auth());
    Ok(())
}


#[test]
fn has_room_needs_more_a_usable_next_and_a_free_slot() -> TestResult {
    let state = |more: bool, stalled: bool| PollState {
        collector: Collector {
            iocs: Vec::new(),
            summary: FeedSummary::default(),
        },
        next: None,
        more,
        stalled,
        pages: 0,
        numbered: 0,
        last_added: None,
    };
    assert!(has_room(&state(true, false), 1));
    assert!(!has_room(&state(false, false), 1));
    assert!(!has_room(&state(true, true), 1));
    assert!(!has_room(&state(true, false), 0));
    Ok(())
}


#[cfg(unix)]
fn write_secret(path: &Path, content: &str, mode: u32) -> std::io::Result<()> {
    fs::write(path, content)?;
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
}


#[cfg(not(unix))]
fn write_secret(path: &Path, content: &str, _mode: u32) -> std::io::Result<()> {
    fs::write(path, content)
}


fn feed_in(dir: &Path, port: u16) -> FeedConfig {
    let mut config = feed("hub", FeedFormat::Taxii21);
    config.taxii = Some(TaxiiConfig {
        api_root: format!("https://127.0.0.1:{port}/taxii2/root"),
        collection: "c-1".to_owned(),
        user: USER.to_owned(),
        password_file: dir.join("password"),
        ca_file: Some(dir.join("ca.pem")),
        timeout_ms: LONG_TIMEOUT_MS,
        max_pages: 1,
        page_limit: 1,
    });
    config
}


#[test]
fn a_poll_reads_the_password_and_the_ca_from_their_files() -> TestResult {
    let standin = start(|_method, _target| with_header(reply(STATUS_OK, BODY), "X-TAXII-Date-Added-Last", "2026-11-03T11:00:00Z"))?;
    let dir = tempdir()?;
    write_secret(&dir.path().join("password"), &format!("{PASSWORD}\n"), SECRET_MODE)?;
    fs::write(dir.path().join("ca.pem"), &standin.ca_pem)?;
    let outcome = poll_feed(&feed_in(dir.path(), standin.port), None, NOW, &idle)?;
    assert_eq!((outcome.iocs.len(), outcome.cursor), (1, CursorStatus::Advanced));
    let expected = format!(" auth=Basic {}", STANDARD.encode(format!("{USER}:{PASSWORD}")));
    assert_eq!(
        requests(&standin),
        vec![format!(
            "GET /taxii2/root/collections/c-1/objects/?limit=1&match%5Btype%5D=indicator{expected}"
        )]
    );
    Ok(())
}


#[test]
fn a_missing_or_invalid_ca_file_is_refused_before_any_request() -> TestResult {
    let standin = start(|_method, _target| reply(STATUS_OK, BODY))?;
    let dir = tempdir()?;
    write_secret(&dir.path().join("password"), PASSWORD, SECRET_MODE)?;
    let config = feed_in(dir.path(), standin.port);
    assert!(matches!(poll_feed(&config, None, NOW, &idle), Err(TaxiiError::CaFile(_))));
    fs::write(dir.path().join("ca.pem"), "not a certificate")?;
    assert!(matches!(poll_feed(&config, None, NOW, &idle), Err(TaxiiError::Agent(_))));
    let section = config.taxii.as_ref().ok_or("no section")?;
    assert!(matches!(taxii_agent(section), Err(TaxiiError::Agent(_))));
    assert!(requests(&standin).is_empty());
    Ok(())
}


#[test]
fn a_missing_password_file_is_refused_before_any_request() -> TestResult {
    let standin = start(|_method, _target| reply(STATUS_OK, BODY))?;
    let dir = tempdir()?;
    fs::write(dir.path().join("ca.pem"), &standin.ca_pem)?;
    let error = poll_feed(&feed_in(dir.path(), standin.port), None, NOW, &idle).err().ok_or("no error")?;
    assert!(matches!(error, TaxiiError::Password(_)));
    assert_eq!(error.to_string(), "the TAXII password file could not be used");
    assert!(requests(&standin).is_empty());
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_group_readable_or_linked_password_file_is_refused_before_any_request() -> TestResult {
    let standin = start(|_method, _target| reply(STATUS_OK, BODY))?;
    let dir = tempdir()?;
    fs::write(dir.path().join("ca.pem"), &standin.ca_pem)?;
    write_secret(&dir.path().join("password"), PASSWORD, GROUP_MODE)?;
    let config = feed_in(dir.path(), standin.port);
    assert!(matches!(poll_feed(&config, None, NOW, &idle), Err(TaxiiError::Password(_))));
    fs::remove_file(dir.path().join("password"))?;
    write_secret(&dir.path().join("real"), PASSWORD, SECRET_MODE)?;
    std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("password"))?;
    assert!(matches!(poll_feed(&config, None, NOW, &idle), Err(TaxiiError::Password(_))));
    assert!(requests(&standin).is_empty());
    Ok(())
}


#[test]
fn a_taxii_feed_is_polled_never_read_from_a_file() -> TestResult {
    let config = feed("hub", FeedFormat::Taxii21);
    let outcome = parse_feed(&config, &mut BufReader::new(&b""[..]), NOW);
    assert!(matches!(outcome, Err(FeedError::PollOnly)));
    Ok(())
}


#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_| io::Error::other("poisoned"))?.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn a_trace_subscriber_never_sees_the_credentials_or_the_body() -> TestResult {
    LazyLock::force(&ANCHOR);
    tracing_log::LogTracer::init()?;
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let body = format!("{{\"more\":false,\"objects\":[{{\"type\":\"x\",\"note\":\"{BODY_MARK}\"}}]}}");
    let standin = start(move |_method, _target| reply(STATUS_OK, &body))?;
    let mut config = feed("hub", FeedFormat::Taxii21);
    config.taxii = Some(TaxiiConfig {
        api_root: format!("https://127.0.0.1:{}/root", standin.port),
        collection: "c-1".to_owned(),
        user: USER.to_owned(),
        password_file: PathBuf::from("password"),
        ca_file: None,
        timeout_ms: LONG_TIMEOUT_MS,
        max_pages: 1,
        page_limit: 1,
    });
    let agent = new_agent(Some(standin.ca_pem.as_bytes()), true)?;
    let outcome = tracing::subscriber::with_default(subscriber, || poll_collection(&agent, &config, PASSWORD.as_bytes(), None, NOW, &idle))?;
    assert_eq!(outcome.pages, 1);
    assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    assert!(tracing::level_filters::STATIC_MAX_LEVEL <= tracing::level_filters::LevelFilter::DEBUG);
    let logged = String::from_utf8(capture.0.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(logged.contains("taxii poll finished"), "{logged}");
    assert!(logged.contains("ureq"), "{logged}");
    let encoded = STANDARD.encode(format!("{USER}:{PASSWORD}"));
    assert!(
        !logged.contains(PASSWORD) && !logged.contains(&encoded) && !logged.contains(BODY_MARK),
        "{logged}"
    );
    assert!(!logged.to_ascii_lowercase().contains("authorization"), "{logged}");
    Ok(())
}
