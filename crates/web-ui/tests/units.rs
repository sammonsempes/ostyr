#[path = "support/types.rs"]
mod types;


use axum::http::{HeaderMap, HeaderValue, StatusCode};
use types::TestResult;
use web_ui::api::{alerts_path, classify, get_alert, valid_cursor, valid_id, valid_token, MAX_CURSOR_CHARS, MAX_TOKEN_BYTES};
use web_ui::client::build_client;
use web_ui::error::{ApiFailure, SessionError};
use web_ui::model::ApiSection;
use web_ui::session::{clear_cookie, cookie_value, csrf_matches, new_secret, session_key, set_cookie};


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
    })?;
    let token = secrecy::SecretString::from("t".to_owned());
    assert!(matches!(get_alert(&client, &token, "short").await, Err(ApiFailure::NotFound)));
    assert!(matches!(
        get_alert(&client, &token, &"a".repeat(ID_LENGTH)).await,
        Err(ApiFailure::Unavailable(_))
    ));
    Ok(())
}
