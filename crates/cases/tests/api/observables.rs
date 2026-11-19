use crate::fixture::{
    case, executor, fixture, fixture_with, memory_backend, store, Fixture, ANALYST, AUDITOR, BASE_TIME, OTHER_TENANT, READER, TENANT,
};
use crate::http::{body_json, call, get, login};
use crate::memory::{lock, Db};
use crate::types::{TestError, TestResult};
use alerts::error::StoreError;
use axum::body::Body;
use axum::http::StatusCode;
use cases::api::cases_document;
use cases::api_model::{CasesBackend, ObservableRequest};
use cases::error::CaseStoreError;
use cases::grammar::MAX_LABEL_CHARS;
use cases::model::{IocStatus, Observable, ObservableKind, Pap, Tlp};
use cases::observables_api::{checked_request, held_or, observable_flow, observables_flow, OBSERVABLES_PATH, OBSERVABLE_BODY_LIMIT};
use cases::store::{add_observable, MAX_NAME_CHARS, MAX_OBSERVABLES, MAX_OBSERVABLE_CHARS, SEEN_IN_LIMIT};
use cases::stored::SeenObservable;
use core_api::model::{ApiError, ApiIdentity};
use core_pg::scope::tenant_scope;
use serde_json::{json, Value};
use std::sync::Arc;


const THREE: usize = 3;


const SHORT_HASH: usize = 63;


const KINDS: [(&str, &str); 7] = [
    ("ip", "10.0.0.1"),
    ("domain", "example.com"),
    ("url", "https://example.com/a"),
    ("hash", "d41d8cd98f00b204e9800998ecf8427e"),
    ("email", "alice@example.com"),
    ("filename", "report.pdf"),
    ("other", "free text"),
];


async fn post(fx: &Fixture, path: &str, token: Option<&str>, body: &Value) -> Result<(StatusCode, Value), TestError> {
    let response = call(&fx.router, "POST", path, token, Body::from(body.to_string())).await?;
    let status = response.status();
    Ok((status, body_json(response).await?))
}


async fn read(fx: &Fixture, path: &str, token: &str) -> Result<(StatusCode, Value), TestError> {
    let response = get(&fx.router, path, Some(token)).await?;
    let status = response.status();
    Ok((status, body_json(response).await?))
}


fn body_of(kind: &str, value: &str) -> Value {
    json!({"kind": kind, "value": value, "tlp": "amber", "pap": "green", "ioc": "suspected", "source": "analyst"})
}


fn with_field(mut body: Value, key: &str, value: Value) -> Value {
    if let Some(object) = body.as_object_mut() {
        object.insert(key.to_owned(), value);
    }
    body
}


async fn seeded() -> Result<(Fixture, String), TestError> {
    let fx = fixture()?;
    let cases = [
        case(TENANT, "c1", BASE_TIME),
        case(TENANT, "c2", BASE_TIME),
        case(TENANT, "c3", BASE_TIME),
        case(OTHER_TENANT, "foreign", BASE_TIME),
    ];
    store(&fx.db, &cases).await?;
    let token = login(&fx.router, ANALYST).await?;
    Ok((fx, token))
}


fn count_of(db: &Db, tenant: &str, id: &str) -> usize {
    lock(&db.tenants)
        .get(tenant)
        .and_then(|table| table.get(id))
        .map_or(0, |entry| entry.case.observables.len())
}


#[tokio::test]
async fn every_kind_is_added_with_a_201_and_the_stored_form() -> TestResult {
    let (fx, token) = seeded().await?;
    for (kind, value) in KINDS {
        let (status, reply) = post(&fx, "/cases/c1/observables", Some(&token), &body_of(kind, value)).await?;
        assert_eq!(status, StatusCode::CREATED, "{kind}");
        assert_eq!(reply.get("kind"), Some(&json!(kind)));
        assert_eq!(reply.get("value"), Some(&json!(value)));
        assert_eq!(reply.get("already_present"), Some(&json!(false)));
        assert_eq!(reply.get("tlp"), Some(&json!("amber")));
    }
    assert_eq!(count_of(&fx.db, TENANT, "c1"), KINDS.len());
    Ok(())
}


#[tokio::test]
async fn another_spelling_of_the_same_value_is_a_200_already_present() -> TestResult {
    let (fx, token) = seeded().await?;
    let first = post(&fx, "/cases/c1/observables", Some(&token), &body_of("domain", "example.com")).await?;
    assert_eq!(first.0, StatusCode::CREATED);
    let second = with_field(
        with_field(body_of("domain", "Example.COM."), "tlp", json!("red")),
        "source",
        json!("someone else"),
    );
    let (status, reply) = post(&fx, "/cases/c1/observables", Some(&token), &second).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply.get("already_present"), Some(&json!(true)));
    assert_eq!(reply.get("value"), Some(&json!("example.com")));
    assert_eq!(reply.get("tlp"), Some(&json!("amber")));
    assert_eq!(reply.get("source"), Some(&json!("analyst")));
    assert_eq!(count_of(&fx.db, TENANT, "c1"), 1);
    Ok(())
}


#[tokio::test]
async fn a_duplicate_whose_readback_fails_is_a_fixed_500_and_a_missing_readback_keeps_the_submitted_form() -> TestResult {
    let fx = fixture_with(|_db| CasesBackend {
        observable: Arc::new(|_scope, _id, _observable| Box::pin(async { Ok(false) })),
        observables: Arc::new(|_scope, _id| Box::pin(async { Err(CaseStoreError::BadRow { column: 0 }) })),
        ..memory_backend(&Arc::new(Db::default()))
    })?;
    let token = login(&fx.router, ANALYST).await?;
    let (status, reply) = post(&fx, "/cases/c1/observables", Some(&token), &body_of("ip", "10.0.0.1")).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!reply.to_string().contains("10.0.0.1"));
    let submitted = Observable {
        kind: ObservableKind::Ip,
        value: "10.0.0.1".to_owned(),
        tlp: Tlp::Red,
        pap: Pap::Red,
        ioc: IocStatus::NotIoc,
        source: "s".to_owned(),
    };
    assert_eq!(held_or(&[], submitted.clone()), submitted);
    let listed = |kind: ObservableKind, value: &str, source: &str| SeenObservable {
        observable: Observable {
            kind,
            value: value.to_owned(),
            source: source.to_owned(),
            ..submitted.clone()
        },
        seen_in: Vec::new(),
        seen_in_truncated: false,
    };
    let items = [
        listed(ObservableKind::Domain, "10.0.0.1", "other kind"),
        listed(ObservableKind::Ip, "10.0.0.2", "other value"),
        listed(ObservableKind::Ip, "10.0.0.1", "stored"),
    ];
    assert_eq!(held_or(&items, submitted).source, "stored");
    Ok(())
}


#[tokio::test]
async fn the_case_stops_at_the_cap_with_a_fixed_409() -> TestResult {
    let (fx, token) = seeded().await?;
    for index in 0..MAX_OBSERVABLES {
        let (status, _reply) = post(&fx, "/cases/c1/observables", Some(&token), &body_of("other", &format!("v{index}"))).await?;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (status, reply) = post(&fx, "/cases/c1/observables", Some(&token), &body_of("other", "extra")).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reply.pointer("/error/code"), Some(&json!("full")));
    assert!(!reply.to_string().contains("extra"));
    assert_eq!(count_of(&fx.db, TENANT, "c1"), MAX_OBSERVABLES);
    Ok(())
}


#[tokio::test]
async fn each_grammar_refusal_is_a_400_naming_the_field_without_the_value() -> TestResult {
    let (fx, token) = seeded().await?;
    let before = lock(&fx.db.statements).len();
    let refused = [
        ("ip", "fe80::1%eth0".to_owned()),
        ("domain", format!("{}.com", "a".repeat(MAX_LABEL_CHARS + 1))),
        ("hash", "a".repeat(SHORT_HASH)),
        ("email", "alice smith@example.com".to_owned()),
        ("url", "javascript:alert(1)".to_owned()),
        ("filename", "evil\u{202e}gpj.exe".to_owned()),
        ("other", "esc\u{1b}[31m".to_owned()),
        ("other", "a\nb".to_owned()),
        ("other", "x".repeat(MAX_OBSERVABLE_CHARS + 1)),
        ("other", "   ".to_owned()),
    ];
    for (kind, value) in refused {
        let (status, reply) = post(&fx, "/cases/c1/observables", Some(&token), &body_of(kind, &value)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{kind} {value:?}");
        assert_eq!(reply.pointer("/error/code"), Some(&json!("bad_request")));
        let text = reply.to_string();
        assert!(
            text.contains("`value`") && (value.trim().is_empty() || !text.contains(value.trim())),
            "{text}"
        );
    }
    let bad_source = with_field(body_of("ip", "10.0.0.1"), "source", json!("s\u{1b}"));
    let (status, reply) = post(&fx, "/cases/c1/observables", Some(&token), &bad_source).await?;
    assert_eq!((status, reply.to_string().contains("`source`")), (StatusCode::BAD_REQUEST, true));
    let long_source = with_field(body_of("ip", "10.0.0.1"), "source", json!("s".repeat(MAX_NAME_CHARS + 1)));
    assert_eq!(
        post(&fx, "/cases/c1/observables", Some(&token), &long_source).await?.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(lock(&fx.db.statements).len(), before);
    assert_eq!(count_of(&fx.db, TENANT, "c1"), 0);
    Ok(())
}


#[tokio::test]
async fn a_malformed_body_is_a_fixed_400_and_nothing_is_echoed() -> TestResult {
    let (fx, token) = seeded().await?;
    let unknown = with_field(body_of("ip", "10.0.0.1"), "tenant", json!(OTHER_TENANT));
    let with_actor = with_field(body_of("ip", "10.0.0.1"), "actor", json!("root"));
    let bodies = [
        unknown,
        with_actor,
        body_of("IP", "10.0.0.1"),
        json!({"kind": "ip"}),
        body_of("ip", "10.0.0.1"),
    ];
    let mut statuses = Vec::new();
    for body in &bodies {
        statuses.push(post(&fx, "/cases/c1/observables", Some(&token), body).await?.0);
    }
    assert_eq!(
        statuses,
        [
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            StatusCode::CREATED
        ]
    );
    let duplicate = "{\"kind\":\"ip\",\"kind\":\"ip\",\"value\":\"10.0.0.2\",\"tlp\":\"red\",\"pap\":\"red\",\"ioc\":\"not_ioc\",\"source\":\"s\"}";
    let response = call(&fx.router, "POST", "/cases/c1/observables", Some(&token), Body::from(duplicate)).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(count_of(&fx.db, TENANT, "c1"), 1);
    let huge = Body::from(format!("{{\"value\":\"{}\"}}", "x".repeat(OBSERVABLE_BODY_LIMIT * THREE)));
    let big = call(&fx.router, "POST", "/cases/c1/observables", Some(&token), huge).await?;
    assert_eq!(big.status(), StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}


#[tokio::test]
async fn another_tenants_case_is_the_same_404_as_an_unknown_one() -> TestResult {
    let (fx, token) = seeded().await?;
    let body = body_of("ip", "10.0.0.1");
    let foreign = post(&fx, "/cases/foreign/observables", Some(&token), &body).await?;
    let unknown = post(&fx, "/cases/none/observables", Some(&token), &body).await?;
    assert_eq!(foreign.0, StatusCode::NOT_FOUND);
    assert_eq!(foreign, unknown);
    let listed = read(&fx, "/cases/foreign/observables", &token).await?;
    let missing = read(&fx, "/cases/none/observables", &token).await?;
    assert_eq!(listed.0, StatusCode::NOT_FOUND);
    assert_eq!(listed, missing);
    assert_eq!(count_of(&fx.db, OTHER_TENANT, "foreign"), 0);
    let before = lock(&fx.db.statements).len();
    assert_eq!(post(&fx, "/cases/%00/observables", Some(&token), &body).await?.0, StatusCode::NOT_FOUND);
    assert_eq!(read(&fx, "/cases/%ff/observables", &token).await?.0, StatusCode::NOT_FOUND);
    assert_eq!(lock(&fx.db.statements).len(), before);
    Ok(())
}


#[tokio::test]
async fn permissions_follow_the_cases_roles() -> TestResult {
    let (fx, _analyst) = seeded().await?;
    let body = body_of("ip", "10.0.0.1");
    let reader = login(&fx.router, READER).await?;
    assert_eq!(post(&fx, "/cases/c1/observables", Some(&reader), &body).await?.0, StatusCode::FORBIDDEN);
    assert_eq!(read(&fx, "/cases/c1/observables", &reader).await?.0, StatusCode::FORBIDDEN);
    let auditor = login(&fx.router, AUDITOR).await?;
    assert_eq!(post(&fx, "/cases/c1/observables", Some(&auditor), &body).await?.0, StatusCode::FORBIDDEN);
    assert_eq!(read(&fx, "/cases/c1/observables", &auditor).await?.0, StatusCode::OK);
    assert_eq!(post(&fx, "/cases/c1/observables", None, &body).await?.0, StatusCode::UNAUTHORIZED);
    assert_eq!(count_of(&fx.db, TENANT, "c1"), 0);
    Ok(())
}


#[tokio::test]
async fn the_list_shows_seen_in_across_the_cases_of_one_tenant_only() -> TestResult {
    let (fx, token) = seeded().await?;
    for id in ["c1", "c2", "c3"] {
        post(&fx, &format!("/cases/{id}/observables"), Some(&token), &body_of("domain", "example.com")).await?;
    }
    post(&fx, "/cases/c1/observables", Some(&token), &body_of("ip", "10.0.0.9")).await?;
    let hostile = Observable {
        kind: ObservableKind::Domain,
        value: "example.com".to_owned(),
        tlp: Tlp::Red,
        pap: Pap::Red,
        ioc: IocStatus::Confirmed,
        source: "other tenant".to_owned(),
    };
    add_observable(&executor(&fx.db), &tenant_scope(OTHER_TENANT)?, "foreign", &hostile).await?;
    let (status, listed) = read(&fx, "/cases/c1/observables", &token).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed.pointer("/items/0/seen_in"), Some(&json!(["c2", "c3"])));
    assert_eq!(listed.pointer("/items/0/seen_in_truncated"), Some(&json!(false)));
    assert_eq!(listed.pointer("/items/1/value"), Some(&json!("10.0.0.9")));
    assert_eq!(listed.pointer("/items/1/seen_in"), Some(&json!([])));
    assert!(!listed.to_string().contains("foreign"));
    let query = read(&fx, "/cases/c1/observables?tenant=globex", &token).await?;
    assert_eq!(query.0, StatusCode::BAD_REQUEST);
    Ok(())
}


#[tokio::test]
async fn twenty_one_cases_holding_a_value_list_twenty_and_truncate() -> TestResult {
    let fx = fixture()?;
    let cases: Vec<_> = (0..=SEEN_IN_LIMIT + 1)
        .map(|index| case(TENANT, &format!("c{index:03}"), BASE_TIME))
        .collect();
    store(&fx.db, &cases).await?;
    let token = login(&fx.router, ANALYST).await?;
    for stored in &cases {
        let path = format!("/cases/{}/observables", stored.id);
        assert_eq!(
            post(&fx, &path, Some(&token), &body_of("domain", "example.com")).await?.0,
            StatusCode::CREATED
        );
    }
    let (_status, listed) = read(&fx, "/cases/c000/observables", &token).await?;
    let seen = listed.pointer("/items/0/seen_in").and_then(Value::as_array).ok_or("no list")?;
    assert_eq!(seen.len(), SEEN_IN_LIMIT);
    assert_eq!(listed.pointer("/items/0/seen_in_truncated"), Some(&json!(true)));
    Ok(())
}


#[tokio::test]
async fn markup_in_a_value_is_stored_as_data_and_returned_escaped() -> TestResult {
    let (fx, token) = seeded().await?;
    for value in ["<script>alert(1)</script>", "line\u{2028}separator"] {
        assert_eq!(
            post(&fx, "/cases/c1/observables", Some(&token), &body_of("other", value)).await?.0,
            StatusCode::CREATED
        );
    }
    let response = get(&fx.router, "/cases/c1/observables", Some(&token)).await?;
    let parsed = body_json(response).await?;
    assert_eq!(parsed.pointer("/items/0/value"), Some(&json!("<script>alert(1)</script>")));
    assert_eq!(parsed.pointer("/items/1/value"), Some(&json!("line\u{2028}separator")));
    Ok(())
}


#[tokio::test]
async fn store_failures_are_fixed_replies_and_busy_is_a_429() -> TestResult {
    let fx = fixture_with(|_db| CasesBackend {
        observable: Arc::new(|_scope, _id, _observable| Box::pin(async { Err(CaseStoreError::Lease(StoreError::Busy)) })),
        observables: Arc::new(|_scope, _id| Box::pin(async { Err(CaseStoreError::BadRow { column: 0 }) })),
        ..memory_backend(&Arc::new(Db::default()))
    })?;
    let token = login(&fx.router, ANALYST).await?;
    let body = body_of("ip", "10.0.0.1");
    assert_eq!(
        post(&fx, "/cases/c1/observables", Some(&token), &body).await?.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let (status, reply) = read(&fx, "/cases/c1/observables", &token).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!reply.to_string().contains("column"));
    let document = serde_json::to_value(cases_document())?;
    let path = document.pointer("/paths/~1cases~1{id}~1observables").ok_or("route missing")?;
    assert!(path.get("get").is_some() && path.get("post").is_some());
    assert_eq!(OBSERVABLES_PATH, "/cases/{id}/observables");
    Ok(())
}


#[test]
fn the_request_check_normalises_and_names_the_refused_field() -> TestResult {
    let request = |kind: ObservableKind, value: &str, source: &str| ObservableRequest {
        kind,
        value: value.to_owned(),
        tlp: Tlp::Red,
        pap: Pap::Red,
        ioc: IocStatus::Confirmed,
        source: source.to_owned(),
    };
    let stored = checked_request(request(ObservableKind::Domain, " Example.COM. ", "s")).map_err(|field| field.to_owned())?;
    assert_eq!(stored.value, "example.com");
    assert_eq!(checked_request(request(ObservableKind::Ip, "nope", "s")).err(), Some("value"));
    assert_eq!(checked_request(request(ObservableKind::Ip, "10.0.0.1", "")).err(), Some("source"));
    assert_eq!(checked_request(request(ObservableKind::Ip, "nope", "")).err(), Some("value"));
    Ok(())
}


#[tokio::test]
async fn the_flows_refuse_a_missing_session_an_unusable_tenant_and_a_refused_body() -> TestResult {
    let fx = fixture()?;
    let backend = memory_backend(&fx.db);
    let identity = ApiIdentity {
        module: "cases".to_owned(),
        tenant: TENANT.to_owned(),
        generation: 0,
    };
    let unusable = ApiIdentity {
        module: "cases".to_owned(),
        tenant: "bad tenant".to_owned(),
        generation: 0,
    };
    let request = || ObservableRequest {
        kind: ObservableKind::Ip,
        value: "10.0.0.1".to_owned(),
        tlp: Tlp::Red,
        pap: Pap::Red,
        ioc: IocStatus::NotIoc,
        source: "s".to_owned(),
    };
    assert_eq!(
        observable_flow(&identity, None, &backend, Ok("c1".to_owned()), Ok(request())).await.err(),
        Some(ApiError::Internal)
    );
    assert_eq!(
        observable_flow(&unusable, None, &backend, Ok("c1".to_owned()), Ok(request())).await.err(),
        Some(ApiError::Internal)
    );
    assert_eq!(
        observable_flow(&identity, None, &backend, Ok("c1".to_owned()), Err(ApiError::BadRequest))
            .await
            .err(),
        Some(ApiError::BadRequest)
    );
    assert_eq!(
        observables_flow(&unusable, &backend, Ok("c1".to_owned())).await.err(),
        Some(ApiError::Internal)
    );
    assert!(lock(&fx.db.statements).is_empty());
    Ok(())
}
