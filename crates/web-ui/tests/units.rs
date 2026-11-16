#[path = "support/types.rs"]
mod types;


use axum::http::{HeaderMap, HeaderValue, StatusCode};
use types::TestResult;
use web_ui::api::{
    alerts_path, assets_path, cases_path, check_asset_detail, check_asset_page, classify, conflict_failure, encode_asset_id, get_alert, get_case,
    valid_asset_cursor, valid_asset_id, valid_cursor, valid_id, valid_token, MAX_ASSET_ATTRIBUTES, MAX_ASSET_CURSOR_CHARS, MAX_ASSET_ID_BYTES,
    MAX_ASSET_KEYS, MAX_COMMENT_CHARS, MAX_CURSOR_CHARS, MAX_TOKEN_BYTES,
};
use web_ui::client::build_client;
use web_ui::config::DEFAULT_LIMITS;
use web_ui::error::{ApiFailure, SessionError};
use web_ui::model::{ApiSection, WebLimits};
use web_ui::model::{AssetDetailView, AssetPageView};
use web_ui::routes::{comment_limits, comment_shaped, COMMENT_FORM_BYTES};
use web_ui::session::{clear_cookie, cookie_value, csrf_matches, new_secret, session_key, set_cookie};


const CONFLICT: u16 = 409;


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
