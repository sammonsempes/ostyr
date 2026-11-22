use super::{csrf_of, requests_of, set_conflict, set_mode, write_form, writes_of, SESSION_COOKIE};
use crate::harness::{fire, get_with, harness, location_of, post_form, sign_in, Harness, Req};
use crate::stub::{id_of, link_item, Mode, ReadFault, LEAK, TOKEN};
use crate::types::{TestError, TestResult};
use axum::http::StatusCode;
use secrecy::SecretString;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr};
use web_ui::api::{list_case_links, post_case_link};
use web_ui::error::ApiFailure;


const CASE_PATH: &str = "/cases/case-1";


const LINK_PATH: &str = "/cases/case-1/alerts";


const MANY_LINKS: usize = 10_000;


const SHORT_ID: usize = 63;


const LONG_ID: usize = 65;


const BAD_CASE_IDS: usize = 3;


const PAIR: usize = 2;


fn set_links(rig: &Harness, reply: Option<Value>) -> TestResult {
    *rig.stub.state.links_reply.lock().map_err(|_| "poisoned")? = reply;
    Ok(())
}


fn set_links_fault(rig: &Harness, status: Option<StatusCode>) -> TestResult {
    *rig.stub.state.links_fault.lock().map_err(|_| "poisoned")? = status;
    Ok(())
}


fn link_paths(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.link_paths.lock().map_err(|_| "poisoned")?.clone())
}


fn open_form(alert: &str) -> String {
    format!("action=\"/alerts/{alert}\"")
}


#[tokio::test]
async fn the_case_page_lists_the_linked_alerts_and_offers_the_form() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let empty = fire(&rig, get_with(CASE_PATH, &session)).await?;
    assert_eq!(empty.status, StatusCode::OK);
    assert!(empty.body.contains("Linked alerts") && empty.body.contains("No alert is linked to this case."));
    assert!(empty.body.contains(&format!("action=\"{LINK_PATH}\"")) && empty.body.contains("name=\"alert_id\""));
    let first = write_form(&rig, &session, LINK_PATH, &[("alert_id", &id_of('a'))]).await?;
    assert_eq!(first.status, StatusCode::OK);
    assert!(first.body.contains(&open_form(&id_of('a'))) && !first.body.contains("No alert is linked"));
    let again = write_form(&rig, &session, LINK_PATH, &[("alert_id", &id_of('a'))]).await?;
    assert_eq!(again.status, StatusCode::OK);
    assert!(again.body.contains(&open_form(&id_of('a'))));
    let other = write_form(&rig, &session, LINK_PATH, &[("alert_id", &id_of('b'))]).await?;
    assert!(other.body.contains(&open_form(&id_of('a'))) && other.body.contains(&open_form(&id_of('b'))));
    let body = json!({"alert_id": id_of('a')}).to_string();
    assert_eq!(
        writes_of(&rig)?,
        vec![
            format!("{LINK_PATH} {body}"),
            format!("{LINK_PATH} {body}"),
            format!("{LINK_PATH} {}", json!({"alert_id": id_of('b')})),
        ]
    );
    assert_eq!(rig.stub.state.linked.lock().map_err(|_| "poisoned")?.len(), PAIR);
    Ok(())
}


#[tokio::test]
async fn a_french_page_shows_the_panel_in_french() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let reply = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..get_with(CASE_PATH, &session)
        },
    )
    .await?;
    assert!(reply.body.contains("Alertes liées") && reply.body.contains("est liée à ce dossier"));
    Ok(())
}


#[tokio::test]
async fn an_alert_id_outside_the_grammar_is_refused_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let before = requests_of(&rig);
    let good = id_of('a');
    let upper = good.to_uppercase();
    let short = "a".repeat(SHORT_ID);
    let long = "a".repeat(LONG_ID);
    let newline = format!("{good}\n");
    let bad = [upper.as_str(), short.as_str(), long.as_str(), newline.as_str(), "", "../x", " ", "g"];
    for alert in bad {
        let reply = write_form(&rig, &session, LINK_PATH, &[("alert_id", alert)]).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{alert:?}");
    }
    let missing = write_form(&rig, &session, LINK_PATH, &[]).await?;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    assert!(writes_of(&rig)?.is_empty());
    assert_eq!(requests_of(&rig) - before, bad.len() + 1);
    Ok(())
}


#[tokio::test]
async fn a_write_without_the_session_token_is_refused_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let other = sign_in(&rig).await?;
    let foreign = csrf_of(&rig, &other).await?;
    let before = requests_of(&rig);
    let cookie = vec![format!("{SESSION_COOKIE}={session}")];
    let fields = format!("alert_id={}", id_of('a'));
    for body in [
        fields.clone(),
        format!("csrf=&{fields}"),
        format!("csrf=wrong&{fields}"),
        format!("csrf={foreign}&{fields}"),
    ] {
        let reply = fire(&rig, post_form(LINK_PATH, cookie.clone(), &body)).await?;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{body}");
    }
    let anonymous = fire(&rig, post_form(LINK_PATH, vec![], &format!("csrf={foreign}&{fields}"))).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    assert!(writes_of(&rig)?.is_empty());
    assert_eq!(requests_of(&rig) - before, 0);
    Ok(())
}


#[tokio::test]
async fn an_invalid_case_id_is_not_found_without_a_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let before = requests_of(&rig);
    for bad in ["-x", "..%2Fx", ".x"] {
        let reply = write_form(&rig, &session, &format!("/cases/{bad}/alerts"), &[("alert_id", &id_of('a'))]).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{bad}");
    }
    assert!(writes_of(&rig)?.is_empty());
    assert_eq!(requests_of(&rig) - before, BAD_CASE_IDS);
    Ok(())
}


#[tokio::test]
async fn api_failures_on_a_link_render_our_own_pages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for (mode, status) in [
        (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
        (Mode::Status(StatusCode::NOT_FOUND), StatusCode::NOT_FOUND),
        (Mode::Status(StatusCode::BAD_REQUEST), StatusCode::BAD_REQUEST),
        (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
    ] {
        let token = csrf_of(&rig, &session).await?;
        set_mode(&rig, mode)?;
        let body = format!("csrf={token}&alert_id={}", id_of('a'));
        let reply = fire(&rig, post_form(LINK_PATH, vec![format!("{SESSION_COOKIE}={session}")], &body)).await?;
        assert_eq!(reply.status, status);
        assert!(!reply.body.contains(LEAK));
        set_mode(&rig, Mode::Normal)?;
    }
    assert!(rig.stub.state.linked.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_full_case_and_an_unknown_conflict_have_fixed_pages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    set_conflict(&rig, Some("alerts_full"))?;
    let full = write_form(&rig, &session, LINK_PATH, &[("alert_id", &id_of('a'))]).await?;
    assert_eq!(full.status, StatusCode::CONFLICT);
    assert!(full.body.contains("maximum number of alerts") && !full.body.contains(LEAK) && !full.body.contains("alerts_full"));
    set_conflict(&rig, Some("something_new"))?;
    let unknown = write_form(&rig, &session, LINK_PATH, &[("alert_id", &id_of('a'))]).await?;
    assert_eq!(unknown.status, StatusCode::BAD_GATEWAY);
    assert!(!unknown.body.contains(LEAK) && !unknown.body.contains("something_new"));
    assert!(rig.stub.state.linked.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_401_on_the_write_or_on_the_reread_ends_the_session() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let token = csrf_of(&rig, &session).await?;
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let body = format!("csrf={token}&alert_id={}", id_of('a'));
    let ended = fire(&rig, post_form(LINK_PATH, vec![format!("{SESSION_COOKIE}={session}")], &body)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    set_mode(&rig, Mode::Normal)?;
    let second = sign_in(&rig).await?;
    let second_token = csrf_of(&rig, &second).await?;
    *rig.stub.state.read_fault.lock().map_err(|_| "poisoned")? = Some(ReadFault::Status(StatusCode::UNAUTHORIZED));
    let second_body = format!("csrf={second_token}&alert_id={}", id_of('a'));
    let reread = fire(&rig, post_form(LINK_PATH, vec![format!("{SESSION_COOKIE}={second}")], &second_body)).await?;
    assert_eq!(location_of(&reread).as_deref(), Some("/login"));
    assert_eq!(writes_of(&rig)?.len(), PAIR);
    Ok(())
}


#[tokio::test]
async fn a_failing_link_read_leaves_the_case_page_with_our_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for status in [StatusCode::INTERNAL_SERVER_ERROR, StatusCode::FORBIDDEN, StatusCode::NOT_FOUND] {
        set_links_fault(&rig, Some(status))?;
        let reply = fire(&rig, get_with(CASE_PATH, &session)).await?;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body.contains("The linked alerts cannot be shown.") && !reply.body.contains(LEAK));
        assert!(reply.body.contains("Phishing wave"));
        let written = write_form(&rig, &session, LINK_PATH, &[("alert_id", &id_of('c'))]).await?;
        assert_eq!(written.status, StatusCode::OK);
        assert!(written.body.contains("The linked alerts cannot be shown."));
    }
    set_links_fault(&rig, Some(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with(CASE_PATH, &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    Ok(())
}


#[tokio::test]
async fn a_hostile_link_list_makes_the_panel_unavailable() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let good = id_of('a');
    let many: Vec<Value> = (0..MANY_LINKS).map(|_| link_item(&good)).collect();
    let hostile = [
        json!({"items": [link_item("short")], "next_cursor": null}),
        json!({"items": [link_item(&"A".repeat(SHORT_ID + 1))], "next_cursor": null}),
        json!({"items": [link_item("<script>x</script>")], "next_cursor": null}),
        json!({"items": [link_item(&good)], "next_cursor": "a b"}),
        json!({"items": [link_item(&good)], "next_cursor": "<script>"}),
        json!({"items": many, "next_cursor": null}),
        json!({"items": "wrong", "next_cursor": null}),
    ];
    for reply in hostile {
        set_links(&rig, Some(reply))?;
        let page = fire(&rig, get_with(CASE_PATH, &session)).await?;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page.body.contains("The linked alerts cannot be shown.") && !page.body.contains("<script>x"));
        assert!(!page.body.contains("action=\"/alerts/"));
    }
    Ok(())
}


#[tokio::test]
async fn the_next_page_of_links_carries_the_checked_cursor() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    set_links(&rig, Some(json!({"items": [link_item(&id_of('a'))], "next_cursor": "YWJj_-"})))?;
    let first = fire(&rig, get_with(CASE_PATH, &session)).await?;
    assert!(first.body.contains("name=\"links_cursor\" value=\"YWJj_-\"") && first.body.contains("More linked alerts"));
    let second = fire(&rig, get_with(&format!("{CASE_PATH}?links_cursor=YWJj_-"), &session)).await?;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(
        link_paths(&rig)?,
        vec![
            "/cases/case-1/alerts?limit=50".to_owned(),
            "/cases/case-1/alerts?limit=50&cursor=YWJj_-".to_owned()
        ]
    );
    let before = requests_of(&rig);
    for bad in ["a%20b", "", "%3Cscript%3E", "a%0A"] {
        let reply = fire(&rig, get_with(&format!("{CASE_PATH}?links_cursor={bad}"), &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(requests_of(&rig), before);
    Ok(())
}


#[tokio::test]
async fn the_link_calls_check_the_ids_first() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let client = rig.state.api.load_full();
    let token = SecretString::from(TOKEN.to_owned());
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let before = requests_of(&rig);
    assert!(matches!(
        list_case_links(&client, source, &token, "-x", None).await,
        Err(ApiFailure::NotFound)
    ));
    assert!(matches!(
        post_case_link(&client, source, &token, "-x", &id_of('a')).await,
        Err(ApiFailure::NotFound)
    ));
    assert!(matches!(
        post_case_link(&client, source, &token, "case-1", "short").await,
        Err(ApiFailure::NotFound)
    ));
    assert_eq!(requests_of(&rig), before);
    Ok(())
}
