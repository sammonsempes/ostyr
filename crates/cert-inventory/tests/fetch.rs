#[path = "standin/mod.rs"]
mod standin;
#[path = "common/types.rs"]
mod types;


use cert_inventory::ct::{unexpected_for_domains, DEFAULT_LIMITS};
use cert_inventory::error::{CtError, FetchError, TransportKind};
use cert_inventory::fetch::{get_range, get_sth, open_log, status_error, CtLog, RangeRequest, Sth, MAX_RANGE, MAX_STH_BYTES};
use cert_inventory::model::CtLimits;
use data_encoding::BASE64;
use rcgen::{CertificateParams, KeyPair};
use serde_json::json;
use standin::{reply, requests, start, Reply, Standin};
use std::error::Error;
use std::net::TcpListener;
use std::time::Duration;
use types::TestResult;


const STATUS_OK: u16 = 200;


const STATUS_FOUND: u16 = 302;


const STATUS_BAD_REQUEST: u16 = 400;


const STATUS_NOT_FOUND: u16 = 404;


const STATUS_TOO_MANY: u16 = 429;


const STATUS_UNAVAILABLE: u16 = 503;


const TIMEOUT: Duration = Duration::from_secs(20);


const SHORT_TIMEOUT: Duration = Duration::from_secs(1);


const TREE_SIZE: u64 = 1000;


const TIMESTAMP: u64 = 1_700_000_000_123;


const LENGTH_SKIP: usize = 5;


const FIVE_ENTRIES_END: u64 = 4;


const THREE: usize = 3;


const TWO: usize = 2;


const START_AFTER: u64 = 5;


const DECOYS: usize = 1000;


const DECOY_START: u64 = 100;


const HUGE_DECLARED: usize = 1_000_000;


const MARKER_REPEAT: usize = 200;


const SMALL_JSON_LIMIT: usize = 64;


const OVER_STH: usize = MAX_STH_BYTES + 1;


const MARKER: &str = "SECRET-MARKER-FROM-THE-LOG";


const ENTRIES_PATH: &str = "/ct/v1/get-entries?start=100&end=104";


fn x509_leaf(der: &[u8]) -> Vec<u8> {
    let length = der.len().to_be_bytes().iter().skip(LENGTH_SKIP).copied().collect::<Vec<u8>>();
    [&[0u8, 0][..], &TIMESTAMP.to_be_bytes(), &[0, 0], &length, der].concat()
}


fn leaf_for(names: &[String]) -> Result<Vec<u8>, Box<dyn Error>> {
    let certificate = CertificateParams::new(names.to_vec())?.self_signed(&KeyPair::generate()?)?;
    Ok(x509_leaf(certificate.der()))
}


fn answer(leaves: &[Vec<u8>]) -> String {
    let entries = leaves
        .iter()
        .map(|leaf| json!({ "leaf_input": BASE64.encode(leaf), "extra_data": "" }))
        .collect::<Vec<_>>();
    json!({ "entries": entries }).to_string()
}


fn names(zone: &str) -> Vec<String> {
    vec![zone.to_string()]
}


fn log_of(standin: &Standin, timeout: Duration) -> Result<CtLog, Box<dyn Error>> {
    Ok(open_log(
        &format!("https://127.0.0.1:{}/", standin.port),
        Some(standin.ca_pem.as_bytes()),
        timeout,
    )?)
}


fn request(start: u64, end: u64) -> RangeRequest {
    RangeRequest {
        start,
        end,
        tree_size: TREE_SIZE,
    }
}


fn count_leaves(count: usize) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let leaf = leaf_for(&names("host.example.org"))?;
    Ok(vec![leaf; count])
}


fn chain_text(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |current| (*current).source())
        .map(|current| format!("{current} {current:?}"))
        .collect::<Vec<_>>()
        .join(" | ")
}


fn serve_entries(body: String) -> Result<Standin, Box<dyn Error>> {
    start(move |_method, _path| reply(STATUS_OK, &body))
}


fn serve_status(status: u16) -> Result<Standin, Box<dyn Error>> {
    start(move |_method, _path| reply(status, ""))
}


#[test]
fn a_short_answer_gives_the_next_start() -> TestResult {
    let standin = serve_entries(answer(&count_leaves(TWO)?))?;
    let log = log_of(&standin, TIMEOUT)?;
    let fetched = get_range(&log, &request(DECOY_START, DECOY_START + FIVE_ENTRIES_END), &DEFAULT_LIMITS)?;
    assert_eq!(fetched.returned, TWO as u64);
    assert_eq!(fetched.next_start, DECOY_START + TWO as u64);
    assert_eq!(fetched.outcome.entries.len(), TWO);
    assert_eq!(requests(&standin), vec![format!("GET {ENTRIES_PATH} auth=false")]);
    Ok(())
}


#[test]
fn skipped_entries_count_as_returned() -> TestResult {
    let body = json!({ "entries": [{ "leaf_input": "!!!!", "extra_data": "" }] }).to_string();
    let standin = serve_entries(body)?;
    let fetched = get_range(&log_of(&standin, TIMEOUT)?, &request(0, 0), &DEFAULT_LIMITS)?;
    assert_eq!(fetched.returned, 1);
    assert_eq!(fetched.next_start, 1);
    assert_eq!(fetched.outcome.skipped_malformed, 1);
    Ok(())
}


#[test]
fn more_entries_than_asked_are_refused() -> TestResult {
    let standin = serve_entries(answer(&count_leaves(THREE)?))?;
    let outcome = get_range(&log_of(&standin, TIMEOUT)?, &request(0, 1), &DEFAULT_LIMITS);
    assert!(matches!(outcome, Err(FetchError::Ct(CtError::TooManyEntries { max: TWO }))));
    Ok(())
}


#[test]
fn an_empty_answer_for_a_valid_range_is_refused() -> TestResult {
    let standin = serve_entries(answer(&[]))?;
    let outcome = get_range(&log_of(&standin, TIMEOUT)?, &request(0, 1), &DEFAULT_LIMITS);
    assert!(matches!(outcome, Err(FetchError::Empty)));
    Ok(())
}


#[test]
fn a_body_over_the_cap_is_refused() -> TestResult {
    let standin = serve_entries(answer(&count_leaves(1)?))?;
    let limits = CtLimits {
        max_json_bytes: SMALL_JSON_LIMIT,
        ..DEFAULT_LIMITS
    };
    let outcome = get_range(&log_of(&standin, TIMEOUT)?, &request(0, 1), &limits);
    assert!(matches!(outcome, Err(FetchError::Ct(CtError::JsonTooLarge { .. }))));
    Ok(())
}


#[test]
fn a_huge_declared_body_is_cut_at_the_cap() -> TestResult {
    let standin = start(|_method, _path| Reply {
        declared: HUGE_DECLARED,
        body: vec![b' '; HUGE_DECLARED],
        ..reply(STATUS_OK, "")
    })?;
    let limits = CtLimits {
        max_json_bytes: SMALL_JSON_LIMIT,
        ..DEFAULT_LIMITS
    };
    let outcome = get_range(&log_of(&standin, TIMEOUT)?, &request(0, 1), &limits);
    assert!(matches!(outcome, Err(FetchError::Ct(CtError::JsonTooLarge { .. }))));
    Ok(())
}


#[test]
fn a_bad_range_is_refused_before_any_request() -> TestResult {
    let standin = serve_entries(answer(&count_leaves(THREE)?))?;
    let log = log_of(&standin, TIMEOUT)?;
    assert!(matches!(
        get_range(&log, &request(START_AFTER, START_AFTER - 1), &DEFAULT_LIMITS),
        Err(FetchError::StartAfterEnd)
    ));
    assert!(matches!(
        get_range(&log, &request(0, TREE_SIZE), &DEFAULT_LIMITS),
        Err(FetchError::BeyondTree { .. })
    ));
    assert!(matches!(
        get_range(&log, &request(0, u64::MAX), &DEFAULT_LIMITS),
        Err(FetchError::BeyondTree { .. })
    ));
    assert!(matches!(
        get_range(&log, &request(0, MAX_RANGE), &DEFAULT_LIMITS),
        Err(FetchError::RangeTooWide { max: MAX_RANGE })
    ));
    assert!(requests(&standin).is_empty());
    Ok(())
}


#[test]
fn a_tree_size_of_u64_max_still_bounds_the_range() -> TestResult {
    let standin = serve_entries(answer(&count_leaves(1)?))?;
    let log = log_of(&standin, TIMEOUT)?;
    let wide = RangeRequest {
        start: 0,
        end: u64::MAX - 1,
        tree_size: u64::MAX,
    };
    assert!(matches!(get_range(&log, &wide, &DEFAULT_LIMITS), Err(FetchError::RangeTooWide { .. })));
    let last = RangeRequest {
        start: u64::MAX - 1,
        end: u64::MAX - 1,
        tree_size: u64::MAX,
    };
    assert_eq!(get_range(&log, &last, &DEFAULT_LIMITS)?.next_start, u64::MAX);
    Ok(())
}


#[test]
fn the_widest_allowed_range_is_requested() -> TestResult {
    let standin = serve_entries(answer(&count_leaves(1)?))?;
    get_range(&log_of(&standin, TIMEOUT)?, &request(0, MAX_RANGE - 1), &DEFAULT_LIMITS)?;
    assert_eq!(requests(&standin).len(), 1);
    Ok(())
}


#[test]
fn a_redirect_is_not_followed() -> TestResult {
    let standin = start(|_method, _path| Reply {
        location: Some("https://169.254.169.254/latest/meta-data".to_string()),
        ..reply(STATUS_FOUND, "")
    })?;
    let outcome = get_range(&log_of(&standin, TIMEOUT)?, &request(0, 1), &DEFAULT_LIMITS);
    assert!(matches!(outcome, Err(FetchError::Status(STATUS_FOUND))));
    assert_eq!(requests(&standin).len(), 1);
    Ok(())
}


#[test]
fn each_status_has_a_typed_error() -> TestResult {
    let cases = [
        (STATUS_BAD_REQUEST, "refused the range"),
        (STATUS_TOO_MANY, "rate-limited"),
        (STATUS_UNAVAILABLE, "5xx"),
        (STATUS_NOT_FOUND, "unexpected HTTP status 404"),
    ];
    cases.iter().try_for_each(|(status, text)| -> TestResult {
        let standin = serve_status(*status)?;
        let error = get_range(&log_of(&standin, TIMEOUT)?, &request(0, 1), &DEFAULT_LIMITS)
            .err()
            .ok_or("no error")?;
        assert!(error.to_string().contains(text), "{error}");
        assert!(get_sth(&log_of(&standin, TIMEOUT)?).is_err());
        Ok(())
    })?;
    assert!(matches!(status_error(STATUS_OK), FetchError::Status(STATUS_OK)));
    Ok(())
}


#[test]
fn the_tree_head_is_read() -> TestResult {
    let body = json!({ "tree_size": TREE_SIZE, "timestamp": TIMESTAMP, "sha256_root_hash": "x", "tree_head_signature": "y" }).to_string();
    let standin = serve_entries(body)?;
    let sth = get_sth(&log_of(&standin, TIMEOUT)?)?;
    assert_eq!(
        sth,
        Sth {
            tree_size: TREE_SIZE,
            timestamp: TIMESTAMP
        }
    );
    assert_eq!(requests(&standin), vec!["GET /ct/v1/get-sth auth=false".to_string()]);
    Ok(())
}


#[test]
fn an_oversized_tree_head_is_refused() -> TestResult {
    let standin = serve_entries(" ".repeat(OVER_STH))?;
    let outcome = get_sth(&log_of(&standin, TIMEOUT)?);
    assert!(matches!(outcome, Err(FetchError::SthTooLarge { max: MAX_STH_BYTES })));
    Ok(())
}


#[test]
fn a_wrongly_typed_field_never_echoes_the_log_text() -> TestResult {
    let long = MARKER.repeat(MARKER_REPEAT);
    let sth_body = json!({ "tree_size": long, "timestamp": 1 }).to_string();
    let entries_body = json!({ "entries": long }).to_string();
    let nested_body = json!({ "entries": [{ "leaf_input": [long] }] }).to_string();
    [sth_body, entries_body, nested_body].into_iter().try_for_each(|body| -> TestResult {
        let standin = serve_entries(body)?;
        let log = log_of(&standin, TIMEOUT)?;
        let errors = [get_sth(&log).err(), get_range(&log, &request(0, 1), &DEFAULT_LIMITS).err()];
        let text = errors.iter().flatten().map(|error| chain_text(error)).collect::<Vec<_>>().join(" ");
        assert!(!text.is_empty());
        assert!(!text.contains(MARKER), "{text}");
        let anyhow_like = errors.iter().flatten().map(|error| format!("{error:#?}")).collect::<String>();
        assert!(!anyhow_like.contains(MARKER));
        Ok(())
    })
}


#[test]
fn a_wrongly_typed_tree_size_is_a_json_error() -> TestResult {
    let standin = serve_entries(json!({ "tree_size": "x", "timestamp": 1 }).to_string())?;
    let outcome = get_sth(&log_of(&standin, TIMEOUT)?);
    assert!(matches!(outcome, Err(FetchError::Ct(CtError::Json { .. }))));
    Ok(())
}


#[test]
fn a_short_body_is_a_body_error() -> TestResult {
    let standin = start(|_method, _path| Reply {
        declared: HUGE_DECLARED,
        ..reply(STATUS_OK, "{")
    })?;
    let outcome = get_range(&log_of(&standin, TIMEOUT)?, &request(0, 1), &DEFAULT_LIMITS);
    assert!(matches!(outcome, Err(FetchError::Body)));
    Ok(())
}


#[test]
fn a_slow_log_hits_the_deadline() -> TestResult {
    let standin = start(|_method, _path| Reply {
        declared: HUGE_DECLARED,
        hold: true,
        ..reply(STATUS_OK, "{")
    })?;
    let outcome = get_range(&log_of(&standin, SHORT_TIMEOUT)?, &request(0, 1), &DEFAULT_LIMITS);
    assert!(matches!(outcome, Err(FetchError::Body | FetchError::Transport(TransportKind::Timeout))));
    Ok(())
}


#[test]
fn a_log_that_never_answers_hits_the_deadline() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let log = open_log(&format!("http://127.0.0.1:{port}"), None, SHORT_TIMEOUT)?;
    let outcome = get_sth(&log);
    assert!(matches!(outcome, Err(FetchError::Transport(TransportKind::Timeout))));
    Ok(())
}


#[test]
fn an_untrusted_certificate_is_a_tls_error() -> TestResult {
    let standin = serve_status(STATUS_OK)?;
    let log = open_log(&format!("https://127.0.0.1:{}", standin.port), None, TIMEOUT)?;
    let outcome = get_sth(&log);
    assert!(matches!(outcome, Err(FetchError::Transport(TransportKind::Tls))), "{outcome:?}");
    Ok(())
}


#[test]
fn a_closed_port_is_another_transport_error() -> TestResult {
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let log = open_log(&format!("http://127.0.0.1:{port}"), None, TIMEOUT)?;
    assert!(matches!(get_sth(&log), Err(FetchError::Transport(TransportKind::Other))));
    Ok(())
}


#[test]
fn log_urls_are_checked() -> TestResult {
    assert!(matches!(open_log("http://example.org", None, TIMEOUT), Err(FetchError::Url(_))));
    assert!(matches!(open_log("https://example.org/?x=1", None, TIMEOUT), Err(FetchError::Url(_))));
    assert!(matches!(
        open_log("https://example.org", Some(b"not a pem"), TIMEOUT),
        Err(FetchError::Agent(_))
    ));
    let good = open_log("https://example.org/log/", None, TIMEOUT)?;
    assert_eq!(good.url, "https://example.org/log");
    let forged = CtLog {
        url: "http://example.org".to_string(),
        ..good
    };
    assert!(matches!(get_sth(&forged), Err(FetchError::Url(_))));
    Ok(())
}


#[test]
fn a_rogue_certificate_behind_decoy_names_is_reported() -> TestResult {
    let mut decoys = (0..DECOYS).map(|index| format!("decoy{index}.example.net")).collect::<Vec<_>>();
    decoys.push("rogue.victim.example".to_string());
    let rogue = leaf_for(&decoys)?;
    let honest = leaf_for(&names("fine.example.org"))?;
    let standin = serve_entries(answer(&[honest, rogue]))?;
    let fetched = get_range(&log_of(&standin, TIMEOUT)?, &request(0, 1), &DEFAULT_LIMITS)?;
    let watched = vec!["victim.example".to_string()];
    let unexpected = unexpected_for_domains(&fetched.outcome.entries, &watched, &[], &[]);
    assert_eq!(unexpected.len(), 1);
    assert!(unexpected
        .iter()
        .all(|entry| entry.all_dns_names.contains(&"rogue.victim.example".to_string())));
    Ok(())
}
