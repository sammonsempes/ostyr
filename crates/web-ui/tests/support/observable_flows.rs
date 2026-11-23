use super::{csrf_of, requests_of, set_conflict, set_mode, write_form, writes_of, SESSION_COOKIE};
use crate::harness::{fire, get_with, harness, location_of, post_form, sign_in, Harness, Req};
use crate::stub::{Mode, ReadFault, LEAK, TOKEN};
use crate::types::TestResult;
use axum::http::StatusCode;
use secrecy::SecretString;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr};
use web_ui::api::{list_case_observables, post_case_observable};
use web_ui::error::ApiFailure;
use web_ui::model::Language;
use web_ui::model::{NewObservable, ObservableListView, ObservableView, ObservablesPanel};
use web_ui::pages::observables_panel;


const CASE_PATH: &str = "/cases/case-1";


const OBSERVABLES_PATH: &str = "/cases/case-1/observables";


const MANY_OBSERVABLES: usize = 501;


const OVER_SEEN_IN: usize = 21;


const VALUE_CAP: usize = 2_048;


const SOURCE_CAP: usize = 256;


const TEN_KB: usize = 10_240;


const HUGE: usize = 200_000;


const BAD_CASE_IDS: usize = 3;


const WRITES: usize = 2;


const MIN_UNKNOWNS: usize = 4;


const KINDS: [(&str, &str); 7] = [
    ("ip", "203.0.113.7"),
    ("domain", "evil.example.com"),
    ("url", "http://evil.example.com/a"),
    ("hash", "d41d8cd98f00b204e9800998ecf8427e"),
    ("email", "bad@example.com"),
    ("filename", "payload.exe"),
    ("other", "free text"),
];


fn stored(kind: &str, value: &str) -> Value {
    json!({"kind": kind, "value": value, "tlp": "amber", "pap": "amber", "ioc": "suspected", "source": "edr"})
}


fn set_list(rig: &Harness, reply: Option<Value>) -> TestResult {
    *rig.stub.state.observables_reply.lock().map_err(|_| "poisoned")? = reply;
    Ok(())
}


fn set_list_fault(rig: &Harness, status: Option<StatusCode>) -> TestResult {
    *rig.stub.state.observables_fault.lock().map_err(|_| "poisoned")? = status;
    Ok(())
}


fn good_fields<'form>(kind: &'form str, value: &'form str) -> Vec<(&'form str, &'form str)> {
    vec![
        ("kind", kind),
        ("value", value),
        ("tlp", "amber_strict"),
        ("pap", "red"),
        ("ioc", "confirmed"),
        ("source", "edr"),
    ]
}


#[tokio::test]
async fn every_kind_is_posted_as_the_exact_json_and_listed() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let empty = fire(&rig, get_with(CASE_PATH, &session)).await?;
    assert!(empty.body.contains("Observables") && empty.body.contains("No observable is recorded on this case."));
    assert!(empty.body.contains(&format!("action=\"{OBSERVABLES_PATH}\"")) && empty.body.contains("name=\"kind\""));
    for (kind, value) in KINDS {
        let reply = write_form(&rig, &session, OBSERVABLES_PATH, &good_fields(kind, value)).await?;
        assert_eq!(reply.status, StatusCode::OK, "{kind}");
        assert!(reply.body.contains(value) && !reply.body.contains("already held"), "{kind}");
    }
    let expected: Vec<String> = KINDS
        .iter()
        .map(|(kind, value)| {
            let body = json!({"kind": kind, "value": value, "tlp": "amber_strict", "pap": "red", "ioc": "confirmed", "source": "edr"});
            format!("{OBSERVABLES_PATH} {body}")
        })
        .collect();
    assert_eq!(writes_of(&rig)?, expected);
    let page = fire(&rig, get_with(CASE_PATH, &session)).await?;
    assert!(page.body.contains("TLP:AMBER") && page.body.contains("PAP:AMBER") && page.body.contains("Suspected IOC"));
    assert!(page.body.contains("IP address") && page.body.contains("File name"));
    assert!(page.body.contains("action=\"/cases/case-2\""));
    Ok(())
}


#[tokio::test]
async fn the_same_observable_again_shows_the_fixed_note() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let first = write_form(&rig, &session, OBSERVABLES_PATH, &good_fields("ip", "203.0.113.7")).await?;
    assert!(!first.body.contains("already held"));
    let again = write_form(&rig, &session, OBSERVABLES_PATH, &good_fields("ip", "203.0.113.7")).await?;
    assert_eq!(again.status, StatusCode::OK);
    assert!(again.body.contains("The case already held this observable."));
    assert_eq!(rig.stub.state.observables.lock().map_err(|_| "poisoned")?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_french_page_shows_the_panel_and_form_in_french() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    write_form(&rig, &session, OBSERVABLES_PATH, &good_fields("domain", "evil.example.com")).await?;
    let reply = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..get_with(CASE_PATH, &session)
        },
    )
    .await?;
    assert!(
        reply.body.contains("Domaine") && reply.body.contains("Statut IOC") && reply.body.contains("Ajouter l'observable"),
        "{}",
        reply.body
    );
    assert!(!reply.body.contains("missing text"));
    Ok(())
}


#[tokio::test]
async fn forged_selects_and_texts_are_refused_before_any_call() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let before = requests_of(&rig);
    let long_value = "a".repeat(VALUE_CAP + 1);
    let ten_kb = "a".repeat(TEN_KB);
    let long_source = "s".repeat(SOURCE_CAP + 1);
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("kind", vec![("kind", "IP")]),
        ("kind empty", vec![("kind", "")]),
        ("kind padded", vec![("kind", "ip ")]),
        ("kind injected", vec![("kind", "ip\",\"x\":\"y")]),
        ("tlp", vec![("tlp", "white")]),
        ("tlp case", vec![("tlp", "AMBER")]),
        ("pap", vec![("pap", "amber_strict")]),
        ("ioc", vec![("ioc", "yes")]),
        ("value long", vec![("value", &long_value)]),
        ("value 10 KB", vec![("value", &ten_kb)]),
        ("value empty", vec![("value", "")]),
        ("value blank", vec![("value", "   ")]),
        ("value bidi", vec![("value", "evil\u{202e}moc.example")]),
        ("value escape", vec![("value", "a\u{1b}[31mb")]),
        ("value newline", vec![("value", "a\nb")]),
        ("value filler", vec![("value", "x\u{3164}")]),
        ("source long", vec![("source", &long_source)]),
        ("source empty", vec![("source", "")]),
        ("source bidi", vec![("source", "edr\u{2066}")]),
    ];
    for (name, change) in &cases {
        let mut fields = good_fields("ip", "203.0.113.7");
        change
            .iter()
            .for_each(|(key, value)| fields.iter_mut().filter(|(held, _)| held == key).for_each(|entry| entry.1 = value));
        let reply = write_form(&rig, &session, OBSERVABLES_PATH, &fields).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{name}");
        assert!(reply.body.contains("name=\"csrf\""), "{name}");
    }
    let missing = write_form(&rig, &session, OBSERVABLES_PATH, &[]).await?;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    assert!(writes_of(&rig)?.is_empty());
    assert_eq!(requests_of(&rig) - before, cases.len() + 1);
    Ok(())
}


#[tokio::test]
async fn a_value_at_the_cap_is_posted_and_a_huge_form_is_too_large() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let exact = "a".repeat(VALUE_CAP);
    let reply = write_form(&rig, &session, OBSERVABLES_PATH, &good_fields("other", &exact)).await?;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(writes_of(&rig)?.len(), 1);
    let huge = "a".repeat(HUGE);
    let refused = write_form(&rig, &session, OBSERVABLES_PATH, &good_fields("other", &huge)).await?;
    assert_eq!(refused.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(writes_of(&rig)?.len(), 1);
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
    let fields = "kind=ip&value=203.0.113.7&tlp=amber&pap=amber&ioc=suspected&source=edr";
    for body in [
        fields.to_owned(),
        format!("csrf=&{fields}"),
        format!("csrf=wrong&{fields}"),
        format!("csrf={foreign}&{fields}"),
    ] {
        let reply = fire(&rig, post_form(OBSERVABLES_PATH, cookie.clone(), &body)).await?;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{body}");
    }
    let anonymous = fire(&rig, post_form(OBSERVABLES_PATH, vec![], &format!("csrf={foreign}&{fields}"))).await?;
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
        let reply = write_form(&rig, &session, &format!("/cases/{bad}/observables"), &good_fields("ip", "203.0.113.7")).await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{bad}");
    }
    assert!(writes_of(&rig)?.is_empty());
    assert_eq!(requests_of(&rig) - before, BAD_CASE_IDS);
    Ok(())
}


#[tokio::test]
async fn api_failures_render_our_own_pages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for (mode, status) in [
        (Mode::Status(StatusCode::FORBIDDEN), StatusCode::FORBIDDEN),
        (Mode::Status(StatusCode::NOT_FOUND), StatusCode::NOT_FOUND),
        (Mode::Status(StatusCode::BAD_REQUEST), StatusCode::BAD_REQUEST),
        (Mode::Status(StatusCode::INTERNAL_SERVER_ERROR), StatusCode::BAD_GATEWAY),
    ] {
        set_mode(&rig, mode)?;
        let reply = write_form(&rig, &session, OBSERVABLES_PATH, &good_fields("ip", "203.0.113.7")).await?;
        assert_eq!(reply.status, status);
        assert!(!reply.body.contains(LEAK));
        set_mode(&rig, Mode::Normal)?;
    }
    assert!(rig.stub.state.observables.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_full_case_and_an_unknown_conflict_have_fixed_pages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    set_conflict(&rig, Some("full"))?;
    let full = write_form(&rig, &session, OBSERVABLES_PATH, &good_fields("ip", "203.0.113.7")).await?;
    assert_eq!(full.status, StatusCode::CONFLICT);
    assert!(full.body.contains("maximum number of observables") && !full.body.contains("comments") && !full.body.contains(LEAK));
    set_conflict(&rig, Some("something_new"))?;
    let unknown = write_form(&rig, &session, OBSERVABLES_PATH, &good_fields("ip", "203.0.113.7")).await?;
    assert_eq!(unknown.status, StatusCode::BAD_GATEWAY);
    assert!(!unknown.body.contains("something_new") && !unknown.body.contains(LEAK));
    assert!(rig.stub.state.observables.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_401_on_the_write_on_the_reread_or_on_the_list_ends_the_session() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let token = csrf_of(&rig, &session).await?;
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let body = format!("csrf={token}&kind=ip&value=203.0.113.7&tlp=amber&pap=amber&ioc=suspected&source=edr");
    let ended = fire(&rig, post_form(OBSERVABLES_PATH, vec![format!("{SESSION_COOKIE}={session}")], &body)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    set_mode(&rig, Mode::Normal)?;
    let second = sign_in(&rig).await?;
    let second_token = csrf_of(&rig, &second).await?;
    *rig.stub.state.read_fault.lock().map_err(|_| "poisoned")? = Some(ReadFault::Status(StatusCode::UNAUTHORIZED));
    let second_body = body.replace(&token, &second_token);
    let reread = fire(
        &rig,
        post_form(OBSERVABLES_PATH, vec![format!("{SESSION_COOKIE}={second}")], &second_body),
    )
    .await?;
    assert_eq!(location_of(&reread).as_deref(), Some("/login"));
    *rig.stub.state.read_fault.lock().map_err(|_| "poisoned")? = None;
    let third = sign_in(&rig).await?;
    set_list_fault(&rig, Some(StatusCode::UNAUTHORIZED))?;
    let listed = fire(&rig, get_with(CASE_PATH, &third)).await?;
    assert_eq!(location_of(&listed).as_deref(), Some("/login"));
    assert_eq!(writes_of(&rig)?.len(), WRITES);
    Ok(())
}


#[tokio::test]
async fn a_failing_list_read_leaves_the_case_page_with_our_text() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for status in [StatusCode::INTERNAL_SERVER_ERROR, StatusCode::FORBIDDEN, StatusCode::NOT_FOUND] {
        set_list_fault(&rig, Some(status))?;
        let reply = fire(&rig, get_with(CASE_PATH, &session)).await?;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body.contains("The observables cannot be shown.") && !reply.body.contains(LEAK));
        assert!(reply.body.contains("Phishing wave"));
        let written = write_form(&rig, &session, OBSERVABLES_PATH, &good_fields("ip", "203.0.113.7")).await?;
        assert_eq!(written.status, StatusCode::OK);
        assert!(written.body.contains("The observables cannot be shown."));
    }
    Ok(())
}


fn raw_item(kind: &str, seen_in: Value) -> Value {
    json!({"kind": kind, "value": "v", "tlp": "red", "pap": "red", "ioc": "confirmed", "source": "s", "seen_in": seen_in, "seen_in_truncated": false})
}


#[tokio::test]
async fn a_hostile_list_makes_the_panel_unavailable() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let many: Vec<Value> = (0..MANY_OBSERVABLES).map(|_| raw_item("ip", json!([]))).collect();
    let crowd: Vec<Value> = (0..OVER_SEEN_IN).map(|_| json!("case-2")).collect();
    let hostile = [
        json!({"items": [raw_item("<script>x</script>", json!([]))]}),
        json!({"items": [raw_item("IP", json!([]))]}),
        json!({"items": [{"kind": "ip", "value": "v", "tlp": "white", "pap": "red", "ioc": "confirmed", "seen_in": [], "seen_in_truncated": false}]}),
        json!({"items": [{"kind": "ip", "value": "v", "tlp": "red", "pap": "x", "ioc": "confirmed", "seen_in": [], "seen_in_truncated": false}]}),
        json!({"items": [{"kind": "ip", "value": "v", "tlp": "red", "pap": "red", "ioc": "x", "seen_in": [], "seen_in_truncated": false}]}),
        json!({"items": [raw_item("ip", json!(["<script>x</script>"]))]}),
        json!({"items": [raw_item("ip", json!(["../x"]))]}),
        json!({"items": [raw_item("ip", json!(crowd))]}),
        json!({"items": many}),
        json!({"items": "wrong"}),
        json!({"items": [{"kind": "ip"}]}),
    ];
    for reply in hostile {
        set_list(&rig, Some(reply))?;
        let page = fire(&rig, get_with(CASE_PATH, &session)).await?;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page.body.contains("The observables cannot be shown.") && !page.body.contains("<script>x"));
        assert!(!page.body.contains("<th>Value</th>"));
    }
    Ok(())
}


#[tokio::test]
async fn hostile_values_and_a_truncated_seen_in_render_escaped() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let value = format!("<script>x</script>\u{202e}\u{1b}{}", "z".repeat(VALUE_CAP));
    let item = json!({
        "kind": "other", "value": value, "tlp": "red", "pap": "green", "ioc": "not_ioc", "source": "s",
        "seen_in": ["case-2", "-x"], "seen_in_truncated": true
    });
    set_list(&rig, Some(json!({"items": [item]})))?;
    let bad = fire(&rig, get_with(CASE_PATH, &session)).await?;
    assert!(bad.body.contains("The observables cannot be shown."));
    let ok = json!({
        "kind": "other", "value": value, "tlp": "red", "pap": "green", "ioc": "not_ioc", "source": "s",
        "seen_in": ["case-2"], "seen_in_truncated": true
    });
    set_list(&rig, Some(json!({"items": [ok]})))?;
    let page = fire(&rig, get_with(CASE_PATH, &session)).await?;
    assert_eq!(page.status, StatusCode::OK);
    assert!(!page.body.contains("<script>x") && !page.body.contains('\u{202e}') && !page.body.contains('\u{1b}'));
    assert!(page.body.contains("&lt;script&gt;x") && page.body.contains("more cases not shown") && page.body.contains("TLP:RED"));
    assert!(page.body.contains("PAP:GREEN") && page.body.contains("Not an IOC") && page.body.contains("action=\"/cases/case-2\""));
    Ok(())
}


#[tokio::test]
async fn the_observable_calls_check_the_case_id_first() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let client = rig.state.api.load_full();
    let token = SecretString::from(TOKEN.to_owned());
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let new = NewObservable {
        kind: "ip",
        value: "203.0.113.7",
        tlp: "amber",
        pap: "amber",
        ioc: "suspected",
        source: "edr",
    };
    let before = requests_of(&rig);
    assert!(matches!(
        list_case_observables(&client, source, &token, "-x").await,
        Err(ApiFailure::NotFound)
    ));
    assert!(matches!(
        post_case_observable(&client, source, &token, "-x", &new).await,
        Err(ApiFailure::NotFound)
    ));
    assert_eq!(requests_of(&rig), before);
    assert!(post_case_observable(&client, source, &token, "case-1", &new).await?.eq(&false));
    assert!(post_case_observable(&client, source, &token, "case-1", &new).await?);
    let list = list_case_observables(&client, source, &token, "case-1").await?;
    assert_eq!(list.items.len(), 1);
    assert_eq!(stored("ip", "203.0.113.7").get("kind"), Some(&json!("ip")));
    Ok(())
}


#[test]
fn the_panel_shows_the_unknown_text_for_a_name_outside_the_tables() -> TestResult {
    let item = ObservableView {
        kind: "x".to_owned(),
        value: "v".to_owned(),
        tlp: "x".to_owned(),
        pap: "x".to_owned(),
        ioc: "x".to_owned(),
        seen_in: vec![],
        seen_in_truncated: false,
    };
    let shown = observables_panel(Language::English, &ObservablesPanel::Shown(ObservableListView { items: vec![item] })).into_string();
    assert!(shown.matches("unknown").count() >= MIN_UNKNOWNS, "{shown}");
    let absent = observables_panel(Language::English, &ObservablesPanel::Absent).into_string();
    assert!(absent.is_empty());
    Ok(())
}
