use crate::harness::{call, get_status, header_of, published_state, request, snapshot, state_with, text_of, PEER, TENANT};
use crate::types::TestResult;
use axum::http::StatusCode;
use status_page::error::StatusPageError;
use status_page::model::{PageSettings, Snapshot};
use status_page::server::{status_router, tag_matches, BODY_REFUSED_BODY, NOT_ALLOWED_BODY, NOT_FOUND_BODY, NO_PEER_BODY, UNAVAILABLE_BODY};
use status_page::snapshot::publish;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const OTHER_TENANT: &str = "globex";


#[tokio::test]
async fn both_routes_serve_with_security_headers() -> TestResult {
    let (state, _clock) = published_state(PageSettings::default(), "one")?;
    let router = status_router(state);
    let html = call(&router, request("GET", "/", Some(PEER), &[])?).await?;
    assert_eq!(html.status(), StatusCode::OK);
    assert_eq!(header_of(&html, "content-type"), Some("text/html; charset=utf-8"));
    assert_eq!(header_of(&html, "content-security-policy"), Some("default-src 'none'"));
    assert_eq!(header_of(&html, "x-content-type-options"), Some("nosniff"));
    assert_eq!(header_of(&html, "referrer-policy"), Some("no-referrer"));
    assert_eq!(header_of(&html, "cache-control"), Some("public, max-age=15"));
    assert_eq!(text_of(html).await?, "<html>one</html>");
    let json = call(&router, request("GET", "/status.json", Some(PEER), &[])?).await?;
    assert_eq!(header_of(&json, "content-type"), Some("application/json"));
    assert_eq!(text_of(json).await?, "{\"label\":\"one\"}");
    Ok(())
}


#[tokio::test]
async fn other_paths_and_methods_get_fixed_bodies() -> TestResult {
    let (state, _clock) = published_state(PageSettings::default(), "one")?;
    let router = status_router(state);
    let missing = call(&router, request("GET", "/etc/passwd", Some(PEER), &[])?).await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(header_of(&missing, "cache-control"), Some("no-store"));
    assert_eq!(header_of(&missing, "x-content-type-options"), Some("nosniff"));
    assert_eq!(text_of(missing).await?, NOT_FOUND_BODY);
    let post = call(&router, request("POST", "/", Some(PEER), &[])?).await?;
    assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(text_of(post).await?, NOT_ALLOWED_BODY);
    let delete = call(&router, request("DELETE", "/status.json", Some(PEER), &[])?).await?;
    assert_eq!(delete.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(text_of(delete).await?, NOT_ALLOWED_BODY);
    Ok(())
}


#[tokio::test]
async fn unpublished_page_answers_503_then_serves() -> TestResult {
    let (state, _clock) = state_with(PageSettings::default());
    let router = status_router(state.clone());
    let before = call(&router, request("GET", "/", Some(PEER), &[])?).await?;
    assert_eq!(before.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(text_of(before).await?, UNAVAILABLE_BODY);
    assert_eq!(get_status(&router, "/status.json", PEER).await?, StatusCode::SERVICE_UNAVAILABLE);
    publish(&state, snapshot(TENANT, "late"))?;
    assert_eq!(get_status(&router, "/", PEER).await?, StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn swap_between_two_requests_changes_the_bytes() -> TestResult {
    let (state, _clock) = published_state(PageSettings::default(), "first")?;
    let router = status_router(state.clone());
    assert_eq!(
        text_of(call(&router, request("GET", "/", Some(PEER), &[])?).await?).await?,
        "<html>first</html>"
    );
    publish(&state, snapshot(TENANT, "second"))?;
    assert_eq!(
        text_of(call(&router, request("GET", "/", Some(PEER), &[])?).await?).await?,
        "<html>second</html>"
    );
    Ok(())
}


#[tokio::test]
async fn publish_refuses_another_tenant_and_keeps_the_old_page() -> TestResult {
    let (state, _clock) = published_state(PageSettings::default(), "mine")?;
    let refused = publish(&state, snapshot(OTHER_TENANT, "theirs"));
    assert!(matches!(refused, Err(StatusPageError::SnapshotTenant { .. })));
    assert!(refused
        .map_err(|error| error.to_string())
        .err()
        .is_some_and(|text| text.contains(OTHER_TENANT)));
    let router = status_router(state);
    assert_eq!(
        text_of(call(&router, request("GET", "/", Some(PEER), &[])?).await?).await?,
        "<html>mine</html>"
    );
    Ok(())
}


#[tokio::test]
async fn etag_gives_304_on_a_match() -> TestResult {
    let (state, _clock) = published_state(PageSettings::default(), "one")?;
    let tag = snapshot(TENANT, "one").etag;
    let router = status_router(state.clone());
    let first = call(&router, request("GET", "/", Some(PEER), &[])?).await?;
    assert_eq!(header_of(&first, "etag"), Some(tag.as_str()));
    let same = call(&router, request("GET", "/", Some(PEER), &[("if-none-match", &tag)])?).await?;
    assert_eq!(same.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(header_of(&same, "etag"), Some(tag.as_str()));
    assert_eq!(header_of(&same, "cache-control"), Some("public, max-age=15"));
    assert_eq!(text_of(same).await?, "");
    let listed = format!("\"other\", W/{tag}");
    let weak = call(&router, request("GET", "/status.json", Some(PEER), &[("if-none-match", &listed)])?).await?;
    assert_eq!(weak.status(), StatusCode::NOT_MODIFIED);
    let star = call(&router, request("GET", "/", Some(PEER), &[("if-none-match", "*")])?).await?;
    assert_eq!(star.status(), StatusCode::NOT_MODIFIED);
    let stale = call(&router, request("GET", "/", Some(PEER), &[("if-none-match", "\"old\"")])?).await?;
    assert_eq!(stale.status(), StatusCode::OK);
    publish(&state, snapshot(TENANT, "two"))?;
    let changed = call(&router, request("GET", "/", Some(PEER), &[("if-none-match", &tag)])?).await?;
    assert_eq!(changed.status(), StatusCode::OK);
    Ok(())
}


#[test]
fn tag_matching_ignores_unreadable_values() -> TestResult {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("if-none-match", axum::http::HeaderValue::from_bytes(&INVALID_UTF8)?);
    assert!(!tag_matches(&headers, "\"x\""));
    Ok(())
}


#[tokio::test]
async fn a_tag_that_is_not_a_header_value_is_a_500() -> TestResult {
    let (state, _clock) = state_with(PageSettings::default());
    publish(
        &state,
        Snapshot {
            etag: "bad\ntag".to_owned(),
            ..snapshot(TENANT, "x")
        },
    )?;
    let router = status_router(state);
    assert_eq!(get_status(&router, "/", PEER).await?, StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}


#[tokio::test]
async fn a_request_body_is_refused() -> TestResult {
    let (state, _clock) = published_state(PageSettings::default(), "one")?;
    let router = status_router(state);
    let sized = call(&router, request("GET", "/", Some(PEER), &[("content-length", "5")])?).await?;
    assert_eq!(sized.status(), StatusCode::BAD_REQUEST);
    assert_eq!(text_of(sized).await?, BODY_REFUSED_BODY);
    let chunked = call(&router, request("GET", "/", Some(PEER), &[("transfer-encoding", "chunked")])?).await?;
    assert_eq!(chunked.status(), StatusCode::BAD_REQUEST);
    let garbled = call(&router, request("GET", "/", Some(PEER), &[("content-length", "abc")])?).await?;
    assert_eq!(garbled.status(), StatusCode::BAD_REQUEST);
    let empty = call(&router, request("GET", "/", Some(PEER), &[("content-length", "0")])?).await?;
    assert_eq!(empty.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn a_request_without_a_peer_is_refused() -> TestResult {
    let (state, _clock) = published_state(PageSettings::default(), "one")?;
    let router = status_router(state);
    let response = call(&router, request("GET", "/", None, &[])?).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(text_of(response).await?, NO_PEER_BODY);
    Ok(())
}
