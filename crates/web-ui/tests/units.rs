#[path = "support/types.rs"]
mod types;


use axum::http::{HeaderMap, HeaderValue, StatusCode};
use types::TestResult;
use web_ui::api::{
    alerts_path, assets_path, cases_path, cert_filter, certs_path, check_asset_detail, check_asset_page, classify, conflict_failure, encode_asset_id,
    get_alert, get_case, unreadable_failure, valid_asset_cursor, valid_asset_id, valid_cert_cursor, valid_cursor, valid_id, valid_token,
    MAX_ASSET_ATTRIBUTES, MAX_ASSET_CURSOR_CHARS, MAX_ASSET_ID_BYTES, MAX_ASSET_KEYS, MAX_COMMENT_CHARS, MAX_CURSOR_CHARS, MAX_TOKEN_BYTES,
};
use web_ui::api::{hunts_path, valid_hunt_cursor, valid_pack_id, MAX_HUNT_CURSOR_CHARS, MAX_PACK_ID_CHARS};
use web_ui::api::{oncall_path, parse_oncall_id, valid_oncall_text, MAX_ONCALL_FINGERPRINT_BYTES, ONCALL_STATES};
use web_ui::api::{
    parse_dhcp_address, parse_dhcp_mac, parse_dhcp_time, parse_dhcp_window, scan_dhcp_intervals, valid_dhcp_hostname, DHCP_LIMIT,
    MAX_DHCP_LABEL_CHARS,
};
use web_ui::api::{
    posture_path, scan_state_items, valid_posture_account, valid_posture_cursor, MAX_POSTURE_ACCOUNT_BYTES, MAX_POSTURE_CURSOR_BYTES,
    MAX_POSTURE_RUN_ID_BYTES, POSTURE_LIMIT,
};
use web_ui::api::{
    shell_list_path, shell_open_filter, valid_shell_cursor, valid_shell_filter_requester, valid_shell_hash, valid_shell_reference,
    valid_shell_subject, MAX_SHELL_CURSOR_BYTES, MAX_SHELL_I64_CHARS, MAX_SHELL_REFERENCE_BYTES, MAX_SHELL_SUBJECT_BYTES,
};
use web_ui::api::{
    states_path, valid_state_asset, valid_state_cursor, valid_state_id, verdict_filter, MAX_STATE_ASSET_CHARS, MAX_STATE_CURSOR_HEX,
    MAX_STATE_ID_CHARS,
};
use web_ui::api::{
    valid_vuln_asset, valid_vuln_cursor, valid_vuln_field, vuln_score, vulns_path, MAX_VULN_CURSOR_BYTES, MAX_VULN_FIELD_BYTES, VULN_CVSS_MAX,
    VULN_EPSS_MAX,
};
use web_ui::client::build_client;
use web_ui::config::DEFAULT_LIMITS;
use web_ui::error::{ApiFailure, SessionError};
use web_ui::model::Language;
use web_ui::model::ShellQuery;
use web_ui::model::VulnView;
use web_ui::model::{ApiSection, WebLimits};
use web_ui::model::{AssetDetailView, AssetPageView};
use web_ui::pages::window_time;
use web_ui::pages::{oncall_state_key, readable_vuln, vuln_row};
use web_ui::routes::{comment_limits, comment_shaped, expiring_before, COMMENT_FORM_BYTES};
use web_ui::server::wall_seconds;
use web_ui::session::{clear_cookie, cookie_value, csrf_matches, new_secret, session_key, set_cookie};


const HASH_REPEATS: usize = 4;


const CONFLICT: u16 = 409;


const UNPROCESSABLE: u16 = 422;


const CONNECTIONS: usize = 4;


const SOURCE: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7));


const MAX_AGE: u64 = 5;


const SECRET_CHARS: usize = 43;


const HEX_REPEAT: usize = 4;


const ID_LENGTH: usize = 64;


const TEAPOT: u16 = 418;


const LIMIT: u32 = 7;


fn no_randomness(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


#[test]
fn cookies_are_read_from_every_header_and_pair() -> TestResult {
    let mut headers = HeaderMap::new();
    headers.append("cookie", HeaderValue::from_static("a=1; b=2"));
    headers.append("cookie", HeaderValue::from_bytes(b"\xff=1")?);
    headers.append("cookie", HeaderValue::from_static("novalue; c=3"));
    assert_eq!(cookie_value(&headers, "b").as_deref(), Some("2"));
    assert_eq!(cookie_value(&headers, "c").as_deref(), Some("3"));
    assert_eq!(cookie_value(&headers, "novalue"), None);
    assert_eq!(cookie_value(&headers, "absent"), None);
    assert_eq!(cookie_value(&HeaderMap::new(), "a"), None);
    Ok(())
}


#[test]
fn cookie_text_and_secrets() -> TestResult {
    assert_eq!(set_cookie("n", "v", MAX_AGE), "n=v; Max-Age=5; Path=/; Secure; HttpOnly; SameSite=Strict");
    assert!(clear_cookie("n").starts_with("n=; Max-Age=0;"));
    assert!(csrf_matches("abc", "abc"));
    assert!(!csrf_matches("abc", "abd"));
    assert!(!csrf_matches("abc", "ab"));
    assert!(!csrf_matches("abc", ""));
    let first = new_secret(core_auth::random::os_random)?;
    assert_ne!(first, new_secret(core_auth::random::os_random)?);
    assert_eq!(first.len(), SECRET_CHARS);
    assert!(matches!(new_secret(no_randomness), Err(SessionError::Random(_))));
    assert_eq!(session_key("x").len(), ID_LENGTH);
    assert_ne!(session_key("x"), session_key("y"));
    Ok(())
}


#[test]
fn identifier_cursor_and_token_alphabets() -> TestResult {
    assert!(valid_id(&"0123456789abcdef".repeat(HEX_REPEAT)));
    assert!(!valid_id(&"A".repeat(ID_LENGTH)));
    assert!(!valid_id(&"a".repeat(ID_LENGTH - 1)));
    assert!(!valid_id(&"g".repeat(ID_LENGTH)));
    assert!(valid_cursor("aZ09-_="));
    assert!(!valid_cursor(""));
    assert!(!valid_cursor("a b"));
    assert!(!valid_cursor("a/b"));
    assert!(!valid_cursor(&"a".repeat(MAX_CURSOR_CHARS + 1)));
    assert!(valid_cursor(&"a".repeat(MAX_CURSOR_CHARS)));
    assert!(valid_token("abc.def-1"));
    assert!(!valid_token(""));
    assert!(!valid_token("a b"));
    assert!(!valid_token(&"a".repeat(MAX_TOKEN_BYTES + 1)));
    Ok(())
}


#[test]
fn statuses_map_to_failure_classes() -> TestResult {
    assert!(classify(StatusCode::OK).is_ok());
    assert!(matches!(classify(StatusCode::BAD_REQUEST), Err(ApiFailure::BadRequest)));
    assert!(matches!(classify(StatusCode::UNAUTHORIZED), Err(ApiFailure::Unauthorized)));
    assert!(matches!(classify(StatusCode::FORBIDDEN), Err(ApiFailure::Forbidden)));
    assert!(matches!(classify(StatusCode::NOT_FOUND), Err(ApiFailure::NotFound)));
    assert!(matches!(classify(StatusCode::TOO_MANY_REQUESTS), Err(ApiFailure::Throttled)));
    assert!(matches!(classify(StatusCode::IM_A_TEAPOT), Err(ApiFailure::Status(TEAPOT))));
    Ok(())
}


#[test]
fn the_alerts_query_is_encoded() -> TestResult {
    assert_eq!(alerts_path(None, None), "alerts?");
    assert_eq!(alerts_path(Some("a=b&c"), Some(LIMIT)), "alerts?cursor=a%3Db%26c&limit=7");
    assert_eq!(alerts_path(None, Some(1)), "alerts?limit=1");
    Ok(())
}


#[tokio::test]
async fn an_invalid_id_is_not_found_without_a_call() -> TestResult {
    let client = build_client(&ApiSection {
        base_url: "http://127.0.0.1:1/".to_owned(),
        ca: None,
        timeout_seconds: 1,
        max_connections: CONNECTIONS,
    })?;
    let token = secrecy::SecretString::from("t".to_owned());
    assert!(matches!(get_alert(&client, SOURCE, &token, "short").await, Err(ApiFailure::NotFound)));
    assert!(matches!(
        get_alert(&client, SOURCE, &token, &"a".repeat(ID_LENGTH)).await,
        Err(ApiFailure::Unavailable(_))
    ));
    Ok(())
}


#[test]
fn a_conflict_is_one_of_the_fixed_codes_or_a_plain_status() -> TestResult {
    for (code, key) in [
        ("transition_not_allowed", "error_transition_not_allowed"),
        ("resolution_required", "error_resolution_required"),
        ("case_changed", "error_case_changed"),
        ("full", "error_comment_full"),
        ("run_changed", "error_run_changed"),
        ("triage_changed", "error_triage_changed"),
    ] {
        let body = format!("{{\"error\":{{\"code\":\"{code}\",\"message\":\"m\"}}}}");
        assert!(
            matches!(conflict_failure(body.as_bytes()), ApiFailure::Conflict(found) if found == key),
            "{code}"
        );
    }
    for body in ["{\"error\":{\"code\":\"other\",\"message\":\"m\"}}", "not json", "{}", ""] {
        assert!(matches!(conflict_failure(body.as_bytes()), ApiFailure::Status(CONFLICT)), "{body}");
    }
    Ok(())
}


#[test]
fn a_422_is_unreadable_only_with_the_fixed_code() -> TestResult {
    let fixed = "{\"error\":{\"code\":\"unreadable_alert\",\"message\":\"m\"}}";
    assert!(matches!(unreadable_failure(fixed.as_bytes()), ApiFailure::Unreadable));
    for body in ["{\"error\":{\"code\":\"other\",\"message\":\"m\"}}", "not json", "{}", ""] {
        assert!(matches!(unreadable_failure(body.as_bytes()), ApiFailure::Status(UNPROCESSABLE)), "{body}");
    }
    Ok(())
}


#[test]
fn a_comment_is_non_empty_and_within_the_cap() -> TestResult {
    assert!(comment_shaped("a") && comment_shaped(&"é".repeat(MAX_COMMENT_CHARS)));
    assert!(!comment_shaped("") && comment_shaped(" \n\t") && !comment_shaped(&"é".repeat(MAX_COMMENT_CHARS + 1)));
    Ok(())
}


#[test]
fn the_comment_route_reads_at_least_a_full_comment() -> TestResult {
    let small = WebLimits {
        form_bytes: 1,
        ..DEFAULT_LIMITS
    };
    assert_eq!(comment_limits(&small).form_bytes, COMMENT_FORM_BYTES);
    assert_eq!(comment_limits(&small).login_max, small.login_max);
    let large = WebLimits {
        form_bytes: COMMENT_FORM_BYTES + 1,
        ..DEFAULT_LIMITS
    };
    assert_eq!(comment_limits(&large).form_bytes, COMMENT_FORM_BYTES + 1);
    Ok(())
}


#[test]
fn the_cases_query_is_encoded() -> TestResult {
    assert_eq!(cases_path(None, None), "cases?");
    assert_eq!(cases_path(Some("a=b&c"), Some(LIMIT)), "cases?cursor=a%3Db%26c&limit=7");
    Ok(())
}


#[tokio::test]
async fn an_invalid_case_id_is_not_found_without_a_call() -> TestResult {
    let client = build_client(&ApiSection {
        base_url: "http://127.0.0.1:1/".to_owned(),
        ca: None,
        timeout_seconds: 1,
        max_connections: CONNECTIONS,
    })?;
    let token = secrecy::SecretString::from("t".to_owned());
    assert!(matches!(get_case(&client, SOURCE, &token, "-x").await, Err(ApiFailure::NotFound)));
    assert!(matches!(get_case(&client, SOURCE, &token, "ok-1").await, Err(ApiFailure::Unavailable(_))));
    Ok(())
}


#[test]
fn asset_ids_cursors_and_paths() -> TestResult {
    for hidden in [
        '\u{200b}',
        '\u{202e}',
        '\u{2028}',
        '\u{feff}',
        '\u{3164}',
        '\u{ad}',
        '\n',
        '\0',
        '\u{e0041}',
        '\u{61c}',
        '\u{115f}',
        '\u{2800}',
        '\u{ffa0}',
        '\u{180e}',
        '\u{206a}',
        '\u{34f}',
        '\u{fe0f}',
        '\u{e000}',
        '\u{378}',
    ] {
        assert!(!valid_asset_id(&format!("a{hidden}b")), "{hidden:?}");
    }
    assert!(valid_asset_id("serial:A/B?c#d %e"));
    assert!(valid_asset_id(&"x".repeat(MAX_ASSET_ID_BYTES)));
    assert!(!valid_asset_id(&"x".repeat(MAX_ASSET_ID_BYTES + 1)));
    for bad in ["", ".", ".."] {
        assert!(!valid_asset_id(bad));
    }
    assert!(valid_asset_id("..."));
    assert!(valid_asset_id("caf\u{e9}") && valid_asset_id("\u{c5}X") && valid_asset_id("\u{1ea1}\u{307}z"));
    for decomposed in ["cafe\u{301}", "\u{212b}X", "a\u{307}\u{323}z", "\u{212a}1"] {
        assert!(!valid_asset_id(decomposed), "{decomposed:?}");
    }
    for right_to_left in [
        "serial_number:\u{5d0}12",
        "serial_number:12\u{5d0}",
        "serial_number:\u{5d0}-1",
        "serial_number:1-\u{5d0}",
        "x\u{627}\u{661}",
        "x\u{661}",
    ] {
        assert!(!valid_asset_id(right_to_left), "{right_to_left:?}");
    }
    assert!(valid_asset_cursor(&"a".repeat(MAX_ASSET_CURSOR_CHARS)));
    for bad in ["", "a b", "a/b", &"a".repeat(MAX_ASSET_CURSOR_CHARS + 1)] {
        assert!(!valid_asset_cursor(bad));
    }
    assert_eq!(encode_asset_id("a-b.c*_"), "a-b.c*_");
    assert_eq!(encode_asset_id("a b+c~"), "a%20b%2Bc%7E");
    assert_eq!(assets_path(None, None), "assets?");
    assert_eq!(assets_path(Some("a=b"), Some(LIMIT)), "assets?cursor=a%3Db&limit=7");
    Ok(())
}


const PAGE_ITEMS: usize = 101;


fn summary_json() -> serde_json::Value {
    serde_json::json!({"id": "a", "kind": "k", "lifecycle": "l", "version": 1, "counts": {"keys": 0, "attributes": 0, "open_conflicts": 0}})
}


fn asset_with(keys: usize, attributes: usize, id: &str) -> Result<AssetDetailView, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
        "id": id, "kind": "k", "lifecycle": "l", "version": 1, "counts": {"keys": 0, "attributes": 0, "open_conflicts": 0},
        "keys": vec![serde_json::json!({"key": "k", "value": "v"}); keys],
        "attributes": vec![serde_json::json!({"name": "n", "value": "v", "source": "s"}); attributes],
        "truncated": false
    }))
}


fn page_with(items: usize, cursor: Option<&str>) -> Result<AssetPageView, serde_json::Error> {
    serde_json::from_value(serde_json::json!({"items": vec![summary_json(); items], "next_cursor": cursor}))
}


#[test]
fn asset_answers_are_bounded() -> TestResult {
    assert!(check_asset_detail(&asset_with(MAX_ASSET_KEYS, MAX_ASSET_ATTRIBUTES, "a")?, "a").is_ok());
    assert!(check_asset_detail(&asset_with(MAX_ASSET_KEYS + 1, 0, "a")?, "a").is_err());
    assert!(check_asset_detail(&asset_with(0, MAX_ASSET_ATTRIBUTES + 1, "a")?, "a").is_err());
    assert!(check_asset_detail(&asset_with(0, 0, "a")?, "b").is_err());
    assert!(check_asset_page(&page_with(1, Some("abc"))?).is_ok());
    assert!(check_asset_page(&page_with(1, None)?).is_ok());
    assert!(check_asset_page(&page_with(PAGE_ITEMS, None)?).is_err());
    assert!(check_asset_page(&page_with(1, Some("a b"))?).is_err());
    Ok(())
}


const CERT_EPOCH_FLOOR: i64 = 1_700_000_000;


const CERT_START: i64 = 10;


const CERT_MONTH: i64 = 2_592_000;


#[test]
fn certificate_helpers_accept_only_their_grammar() -> TestResult {
    let fingerprint = "a".repeat(CERT_FINGERPRINT_CHARS);
    assert!(valid_cert_cursor(&format!("-12:{fingerprint}")) && valid_cert_cursor(&format!("1800000000:{fingerprint}")));
    for bad in [
        "",
        ":",
        "12",
        "x:",
        &format!(":{fingerprint}"),
        &format!("-:{fingerprint}"),
        &format!("1:{}", "A".repeat(CERT_FINGERPRINT_CHARS)),
    ] {
        assert!(!valid_cert_cursor(bad), "{bad}");
    }
    assert!(!valid_cert_cursor(&format!("{}:{fingerprint}", "1".repeat(CERT_LONG_TIME))));
    assert_eq!(cert_filter("30"), Some("30"));
    assert_eq!(cert_filter("31"), None);
    assert_eq!(certs_path(None, None), "certificates?limit=100");
    assert_eq!(
        certs_path(Some("1:x"), Some(CERT_START)),
        "certificates?limit=100&expiring_before=10&cursor=1%3Ax"
    );
    assert_eq!(expiring_before(CERT_START, "all"), None);
    assert_eq!(expiring_before(CERT_START, "30"), Some(CERT_START + CERT_MONTH));
    assert_eq!(expiring_before(i64::MAX, "90"), Some(i64::MAX));
    assert!(wall_seconds() > CERT_EPOCH_FLOOR);
    Ok(())
}


const CERT_FINGERPRINT_CHARS: usize = 64;


const CERT_LONG_TIME: usize = 21;


#[test]
fn hunt_helpers_accept_only_their_grammar() -> TestResult {
    for good in ["a", "0", "a-b_c.d", &"a".repeat(MAX_PACK_ID_CHARS)] {
        assert!(valid_pack_id(good), "{good}");
    }
    for bad in [
        "",
        "-a",
        "_a",
        ".a",
        "A",
        "a b",
        "a\u{3164}",
        "a\u{1b}",
        &"a".repeat(MAX_PACK_ID_CHARS + 1),
        "é",
    ] {
        assert!(!valid_pack_id(bad), "{bad}");
    }
    for good in ["MTgwMDAwMDAwMDpwYWNrLWM", "QQ", &"A".repeat(MAX_HUNT_CURSOR_CHARS)] {
        assert!(valid_hunt_cursor(good), "{good}");
    }
    for bad in [
        "",
        "A",
        "QQ==",
        "a b",
        "a+b/",
        &"A".repeat(MAX_HUNT_CURSOR_CHARS + 1),
        "MTgwMDAwMDAwMDpwYWNrLWM\n",
    ] {
        assert!(!valid_hunt_cursor(bad), "{bad}");
    }
    assert_eq!(hunts_path(None), "hunts/findings?limit=100");
    assert_eq!(hunts_path(Some("QQ")), "hunts/findings?limit=100&cursor=QQ");
    assert_eq!(window_time("2026-03-02T01:00:00+01:00").as_deref(), Some("2026-03-02T00:00:00Z"));
    assert_eq!(window_time("0000-01-01T00:00:00Z").as_deref(), Some("0000-01-01T00:00:00Z"));
    assert_eq!(window_time("9999-12-31T23:59:59Z").as_deref(), Some("9999-12-31T23:59:59Z"));
    for bad in [
        "",
        "yesterday",
        "2026-03-02",
        "0000-01-01T00:00:00+02:00",
        "9999-12-31T23:00:00-02:00",
        "2026-13-01T00:00:00Z",
        "2026-03-02T00:00:00Z\u{1b}",
    ] {
        assert!(window_time(bad).is_none(), "{bad}");
    }
    Ok(())
}


#[test]
fn vulnerability_helpers_accept_only_the_stores_grammar() -> TestResult {
    for (text, max, accepted) in [
        ("7.5", VULN_CVSS_MAX, true),
        ("0", VULN_CVSS_MAX, true),
        ("10", VULN_CVSS_MAX, true),
        ("11", VULN_CVSS_MAX, false),
        ("-0.1", VULN_CVSS_MAX, false),
        ("-0", VULN_CVSS_MAX, false),
        ("-0.0", VULN_EPSS_MAX, false),
        ("1", VULN_EPSS_MAX, true),
        ("2", VULN_EPSS_MAX, false),
        ("1e999", VULN_CVSS_MAX, false),
        ("null", VULN_CVSS_MAX, false),
        ("\"NaN\"", VULN_CVSS_MAX, false),
        ("[1]", VULN_CVSS_MAX, false),
    ] {
        let raw = serde_json::value::RawValue::from_string(text.to_owned())?;
        let expected = accepted.then(|| text.parse::<f64>()).transpose()?;
        assert_eq!(vuln_score(&raw, max), expected, "{text}");
    }
    assert!(valid_vuln_field("a") && valid_vuln_field(&"a".repeat(MAX_VULN_FIELD_BYTES)));
    for bad in ["", "-a", "a b", "a\u{3164}", "a\u{1b}", &"a".repeat(MAX_VULN_FIELD_BYTES + 1)] {
        assert!(!valid_vuln_field(bad), "{bad}");
    }
    assert!(valid_vuln_asset("a.b") && !valid_vuln_asset(".") && !valid_vuln_asset("..") && !valid_vuln_asset("-a"));
    assert!(valid_vuln_cursor("0 a b c d") && valid_vuln_cursor("4294967295 a b c d"));
    for bad in [
        "",
        "1 a b c",
        "1 a b c d e",
        "01 a b c d",
        "-1 a b c d",
        "4294967296 a b c d",
        "1 -a b c d",
        "1  b c d",
    ] {
        assert!(!valid_vuln_cursor(bad), "{bad}");
    }
    let oversized = format!("1 a b c {}", "d".repeat(MAX_VULN_CURSOR_BYTES));
    assert!(oversized.len() > MAX_VULN_CURSOR_BYTES && !valid_vuln_cursor(&oversized));
    let at_cap = format!(
        "{} {} {} {} {}",
        u32::MAX,
        "a".repeat(MAX_VULN_FIELD_BYTES),
        "b".repeat(MAX_VULN_FIELD_BYTES),
        "c".repeat(MAX_VULN_FIELD_BYTES),
        "d".repeat(MAX_VULN_FIELD_BYTES)
    );
    assert_eq!(at_cap.len(), MAX_VULN_CURSOR_BYTES);
    assert!(valid_vuln_cursor(&at_cap));
    assert_eq!(vulns_path(None), "vulnerabilities/findings?limit=100");
    assert_eq!(vulns_path(Some("1 a b c d")), "vulnerabilities/findings?limit=100&cursor=1+a+b+c+d");
    Ok(())
}


#[test]
fn compliance_helpers_accept_only_the_modules_grammar() -> TestResult {
    for good in ["a", "0", "a._-b", &"a".repeat(MAX_STATE_ID_CHARS)] {
        assert!(valid_state_id(good), "{good}");
    }
    for bad in [
        "",
        "-a",
        "_a",
        ".a",
        "a b",
        "a+b",
        "a/b",
        "a\u{3164}",
        "a\u{1b}",
        "é",
        "a\n",
        &"a".repeat(MAX_STATE_ID_CHARS + 1),
    ] {
        assert!(!valid_state_id(bad), "{bad}");
    }
    for good in ["a", "web-01.corp", "a/b+c:d@e~f^g_h", &"a".repeat(MAX_STATE_ASSET_CHARS)] {
        assert!(valid_state_asset(good), "{good}");
    }
    for bad in [
        "",
        "-a",
        "/a",
        ".a",
        "a b",
        "a%2e",
        "a\u{3164}",
        "é",
        "a\0",
        &"a".repeat(MAX_STATE_ASSET_CHARS + 1),
    ] {
        assert!(!valid_state_asset(bad), "{bad}");
    }
    assert!(valid_state_cursor("626173650063746c00686f73742d31"));
    for bad in [
        "",
        "6",
        "zz",
        "626173650063746c00686f73742d3",
        "626173650063746c00686f73742D31",
        "61",
        "61006200630064",
        "61002d780063",
        "610062002d78",
        &"a".repeat(MAX_STATE_CURSOR_HEX + 1),
    ] {
        assert!(!valid_state_cursor(bad), "{bad}");
    }
    for good in ["fail", "error", "excepted", "pass", "all"] {
        assert_eq!(verdict_filter(good), Some(good));
    }
    for bad in ["", "Fail", "fail ", "none"] {
        assert!(verdict_filter(bad).is_none(), "{bad}");
    }
    assert_eq!(states_path("fail", None, None), "compliance/state?verdict=fail&limit=100");
    assert_eq!(
        states_path("all", Some("b"), Some("61")),
        "compliance/state?verdict=all&limit=100&baseline=b&cursor=61"
    );
    Ok(())
}


#[test]
fn oncall_helpers_accept_only_the_apis_rules() -> TestResult {
    assert_eq!(parse_oncall_id("0"), Some(0));
    assert_eq!(parse_oncall_id(SAMPLE_ONCALL_ID.to_string().as_str()), Some(SAMPLE_ONCALL_ID));
    for bad in ["", "-1", "+1", "1e3", " 1", "99999999999999999999", "\u{661}"] {
        assert!(parse_oncall_id(bad).is_none(), "{bad}");
    }
    for good in ["a", "fp one", "a-b.c:1", &"a".repeat(MAX_ONCALL_FINGERPRINT_BYTES)] {
        assert!(valid_oncall_text(good, MAX_ONCALL_FINGERPRINT_BYTES), "{good}");
    }
    for bad in [
        "",
        " a",
        "a ",
        "a  b",
        "a\tb",
        "a\u{1b}",
        "\u{e9}",
        "a\u{3164}",
        &"a".repeat(MAX_ONCALL_FINGERPRINT_BYTES + 1),
    ] {
        assert!(!valid_oncall_text(bad, MAX_ONCALL_FINGERPRINT_BYTES), "{bad}");
    }
    assert_eq!(oncall_path(), "oncall/alerts?limit=1000");
    ONCALL_STATES
        .iter()
        .try_for_each(|state| oncall_state_key(state).map(|_| ()).ok_or("unmapped state"))?;
    assert!(oncall_state_key("bogus").is_none());
    Ok(())
}


const SAMPLE_ONCALL_ID: i64 = 42;


#[test]
fn a_dot_asset_vulnerability_row_has_no_link_and_a_negative_zero_score_is_unreadable() -> TestResult {
    let row = |asset: &str, cvss: &str| -> Result<VulnView, serde_json::Error> {
        serde_json::from_value(serde_json::json!({
            "asset": asset, "ecosystem": "npm", "package": "p", "record_id": "CVE-1", "installed_version": "1", "fixed_version": null,
            "cvss": serde_json::from_str::<serde_json::Value>(cvss)?, "epss": 1, "kev": false, "priority": 1,
            "first_seen": "2026-03-01T00:00:00Z", "last_seen": "2026-03-02T00:00:00Z"
        }))
    };
    assert!(readable_vuln(&row("web01", "1.0")?).is_some());
    for refused in [row(".", "1.0")?, row("..", "1.0")?, row("web01", "-0.0")?] {
        assert!(readable_vuln(&refused).is_none());
        let shown = vuln_row(Language::English, &refused, None).0;
        assert!(shown.contains("Unreadable row.") && !shown.contains("action="), "{shown}");
    }
    Ok(())
}


#[test]
fn dhcp_grammar_copies_accept_only_the_apis_shapes() -> TestResult {
    let label = "a".repeat(MAX_DHCP_LABEL_CHARS);
    let too_long = "a".repeat(MAX_DHCP_LABEL_CHARS + 1);
    for good in ["a", "host-1.example.com", "a_b", "a.b.c", label.as_str()] {
        assert!(valid_dhcp_hostname(good), "{good}");
    }
    let long_name = format!("{label}.{label}.{label}.{label}");
    for bad in [
        "",
        "-a",
        "a-",
        "a..b",
        ".a",
        "a.",
        "a b",
        "a\u{3164}",
        "a\u{1b}",
        too_long.as_str(),
        long_name.as_str(),
    ] {
        assert!(!valid_dhcp_hostname(bad), "{bad}");
    }
    assert_eq!(parse_dhcp_mac(Some("aa-bb-cc-dd-ee-0f")).as_deref(), Some("AA-BB-CC-DD-EE-0F"));
    assert_eq!(parse_dhcp_mac(None), None);
    assert_eq!(parse_dhcp_mac(Some("a:bb:cc:dd:ee:ff")), None);
    assert_eq!(parse_dhcp_time(Some("0")), Some(0));
    assert_eq!(parse_dhcp_time(None), None);
    assert_eq!(parse_dhcp_window(Some("1"), Some("1")), Some((1, 1)));
    assert_eq!(parse_dhcp_window(Some("1"), None), None);
    assert_eq!(parse_dhcp_address(None), None);
    assert!(parse_dhcp_address(Some("::1")).is_some());
    Ok(())
}


#[test]
fn register_grammar_copies_accept_only_the_apis_shapes() -> TestResult {
    let reference = "a".repeat(MAX_SHELL_REFERENCE_BYTES);
    let subject = "a".repeat(MAX_SHELL_SUBJECT_BYTES);
    for good in ["a", "A1", "s-1", "a/b:c", "a_b.c", "host/1", reference.as_str()] {
        assert!(valid_shell_reference(good), "{good}");
    }
    for bad in [
        "",
        "-a",
        "_a",
        ".a",
        "a b",
        "a\u{3164}",
        "a\u{1b}",
        "a\u{0}",
        "a+b",
        "a|b",
        "é",
        &format!("{reference}a"),
    ] {
        assert!(!valid_shell_reference(bad), "{bad}");
    }
    for good in ["a", "auth0|a+b/c=d", "a@b.c", "-x", subject.as_str()] {
        assert!(valid_shell_subject(good), "{good}");
    }
    for bad in ["", "a b", "a\u{3164}", "a\u{202e}", "a\u{1b}", "é", &format!("{subject}a")] {
        assert!(!valid_shell_subject(bad), "{bad}");
    }
    assert!(valid_shell_filter_requester("auth0|a") && !valid_shell_filter_requester("-x") && !valid_shell_filter_requester(""));
    for good in ["1.s", "-1.s", "0.s-1", "9223372036854775807.a.b", "-9223372036854775808.s"] {
        assert!(valid_shell_cursor(good), "{good}");
    }
    let long = format!("1.{reference}");
    let longer = format!("1.{reference}a");
    assert!(valid_shell_cursor(&long) && !valid_shell_cursor(&longer));
    for bad in [
        "",
        "1",
        "1.",
        ".s",
        "01.s",
        "+1.s",
        "-0.s",
        "9223372036854775808.s",
        "1.-x",
        "x.s",
        "1.s b",
        "1,s",
    ] {
        assert!(!valid_shell_cursor(bad), "{bad}");
    }
    let widest = format!("{}.{reference}", "1".repeat(MAX_SHELL_I64_CHARS));
    assert!(widest.len() == MAX_SHELL_CURSOR_BYTES && !valid_shell_cursor(&widest));
    assert_eq!(shell_open_filter(""), Some(None));
    assert_eq!(shell_open_filter("true"), Some(Some("true")));
    assert_eq!(shell_open_filter("false"), Some(Some("false")));
    for bad in ["True", "yes", " true", "true\u{0}"] {
        assert_eq!(shell_open_filter(bad), None, "{bad}");
    }
    let hash = "0123456789abcdef".repeat(HASH_REPEATS);
    assert!(valid_shell_hash(&hash));
    for bad in [
        "",
        "abc",
        &hash.to_ascii_uppercase(),
        &format!("{hash}0"),
        &format!("g{}", hash.get(1..).unwrap_or("")),
    ] {
        assert!(!valid_shell_hash(bad), "{bad}");
    }
    Ok(())
}


#[test]
fn the_register_path_is_built_from_checked_values_and_encodes_the_special_characters() -> TestResult {
    let query = ShellQuery {
        asset: Some("a/b".to_owned()),
        requester: Some("auth0|a+b/c=d".to_owned()),
        open: Some("true"),
        cursor: Some("1.s:1".to_owned()),
    };
    assert_eq!(
        shell_list_path(&query),
        "remote-shell/sessions?limit=100&asset=a%2Fb&requester=auth0%7Ca%2Bb%2Fc%3Dd&open=true&cursor=1.s%3A1"
    );
    assert_eq!(shell_list_path(&ShellQuery::default()), "remote-shell/sessions?limit=100");
    Ok(())
}


#[test]
fn the_interval_scan_refuses_more_than_the_api_cap_before_decoding() -> TestResult {
    let items = |count: usize| format!("{{\"intervals\":[{}]}}", vec!["null"; count].join(","));
    assert!(scan_dhcp_intervals(items(DHCP_LIMIT).as_bytes()).is_ok());
    assert!(scan_dhcp_intervals(items(DHCP_LIMIT + 1).as_bytes()).is_err());
    assert!(scan_dhcp_intervals(b"{\"items\":[]}").is_err());
    Ok(())
}


const POSTURE_IDENTITY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";


#[test]
fn the_posture_account_grammar_copy_accepts_only_the_crates_shapes() -> TestResult {
    let longest = "a".repeat(MAX_POSTURE_ACCOUNT_BYTES);
    let overlong = "a".repeat(MAX_POSTURE_ACCOUNT_BYTES + 1);
    for good in ["acct", "123456789012", "arn:aws:iam::1:root", "a/b#c", "k8s_(x)$*,+=@", longest.as_str()] {
        assert!(valid_posture_account(good), "{good}");
    }
    for bad in [
        "",
        "-x",
        ".",
        "..",
        "../",
        "../x",
        "a/..",
        "a/./b",
        "/..",
        "a b",
        "a\u{0}",
        "a\u{1b}",
        "\u{3164}",
        "caf\u{e9}",
        "a\\b",
        "<s>",
        "a%",
        overlong.as_str(),
    ] {
        assert!(!valid_posture_account(bad), "{bad}");
    }
    assert!(valid_posture_account("a.b") && valid_posture_account("..a") && valid_posture_account("a/b..") && valid_posture_account("a//b"));
    Ok(())
}


#[test]
fn the_posture_cursor_grammar_copy_accepts_only_the_stores_shape() -> TestResult {
    let run = "r".repeat(MAX_POSTURE_RUN_ID_BYTES);
    let long_run = "r".repeat(MAX_POSTURE_RUN_ID_BYTES + 1);
    for good in [
        format!("run1 0 0 {POSTURE_IDENTITY}"),
        format!("{run} 1772000000000000 32767 {POSTURE_IDENTITY}"),
        format!("run1 1 -1 {POSTURE_IDENTITY}"),
    ] {
        assert!(valid_posture_cursor(&good), "{good}");
    }
    for bad in [
        String::new(),
        "run1".to_owned(),
        format!("{long_run} 1 1 {POSTURE_IDENTITY}"),
        format!("-x 1 1 {POSTURE_IDENTITY}"),
        format!("run1 -1 1 {POSTURE_IDENTITY}"),
        format!("run1 01 1 {POSTURE_IDENTITY}"),
        format!("run1 +1 1 {POSTURE_IDENTITY}"),
        format!("run1 1 01 {POSTURE_IDENTITY}"),
        format!("run1 1 32768 {POSTURE_IDENTITY}"),
        format!("run1 1 1 {}", POSTURE_IDENTITY.to_uppercase()),
        format!("run1 1 1 {}", POSTURE_IDENTITY.trim_end_matches('f')),
        format!("run1 1 1 {POSTURE_IDENTITY} x"),
        format!("run1 1 1 {}g", POSTURE_IDENTITY.trim_end_matches('f')),
        format!("{} 1 1 {POSTURE_IDENTITY}", "r".repeat(MAX_POSTURE_CURSOR_BYTES)),
    ] {
        assert!(!valid_posture_cursor(&bad), "{bad}");
    }
    Ok(())
}


#[test]
fn the_posture_path_and_item_scan_follow_the_apis_limit() -> TestResult {
    assert_eq!(posture_path("a/b#c", None), "posture/accounts/a%2Fb%23c/findings?limit=33");
    assert_eq!(
        posture_path("acct", Some("run1 1 1 x")),
        "posture/accounts/acct/findings?limit=33&cursor=run1+1+1+x"
    );
    let items = |count: usize| format!("{{\"items\":[{}]}}", vec!["null"; count].join(","));
    assert!(scan_state_items(items(POSTURE_LIMIT).as_bytes(), POSTURE_LIMIT).is_ok());
    assert!(scan_state_items(items(POSTURE_LIMIT + 1).as_bytes(), POSTURE_LIMIT).is_err());
    Ok(())
}
