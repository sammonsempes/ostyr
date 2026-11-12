use crate::fixture::{case, fixture, fixture_with, memory_backend, store, Fixture, ANALYST, AUDITOR, BASE_TIME, NOW, OTHER_TENANT, READER, TENANT};
use crate::http::{body_json, call, get, login};
use crate::memory::{lock, Db};
use crate::types::{TestError, TestResult};
use alerts::error::StoreError;
use axum::body::Body;
use axum::http::StatusCode;
use cases::api::cases_document;
use cases::api_model::{CasesBackend, LinkRequest, ListQuery};
use cases::error::CaseStoreError;
use cases::links_api::{decode_link_cursor, encode_link_cursor, link_failure, link_flow, links_flow, ALERTS_PATH, LINK_BODY_LIMIT};
use cases::model::CaseEventKind;
use cases::store::MAX_ALERTS_PER_CASE;
use core_api::model::{ApiError, ApiIdentity};
use serde_json::{json, Value};
use std::sync::Arc;


const ALERT: &str = "2d6c7e2fdf972aab0077338ff3c04044ccb108f41661aa365bea425f0b894fee";


const FOREIGN_ALERT: &str = "3d6c7e2fdf972aab0077338ff3c04044ccb108f41661aa365bea425f0b894fee";


const TOTAL: usize = 120;


const PAGE: usize = 50;


const OVER_CURSOR: usize = 2_000;


const SOME_LIMIT: usize = 3;


const LAST_PAGE: usize = TOTAL - 2 * PAGE;


fn alert_number(index: usize) -> String {
    format!("{index:064x}")
}


fn know(db: &Db, tenant: &str, id: &str) {
    lock(&db.known_alerts).entry(tenant.to_owned()).or_default().insert(id.to_owned());
}


fn linked(db: &Db, tenant: &str, id: &str) -> Result<usize, TestError> {
    let tenants = lock(&db.tenants);
    Ok(tenants.get(tenant).and_then(|table| table.get(id)).ok_or("no such case")?.alerts.len())
}


fn statements(db: &Db) -> usize {
    lock(&db.statements).len()
}


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


async fn seeded() -> Result<(Fixture, String), TestError> {
    let fx = fixture()?;
    store(&fx.db, &[case(TENANT, "c1", BASE_TIME), case(OTHER_TENANT, "foreign", BASE_TIME)]).await?;
    know(&fx.db, TENANT, ALERT);
    know(&fx.db, OTHER_TENANT, FOREIGN_ALERT);
    let token = login(&fx.router, ANALYST).await?;
    Ok((fx, token))
}


fn code_of(reply: &Value) -> Option<&str> {
    reply.pointer("/error/code").and_then(Value::as_str)
}


#[tokio::test]
async fn a_link_is_201_then_200_with_one_row_and_one_history_event() -> TestResult {
    let (fx, token) = seeded().await?;
    let body = json!({"alert_id": ALERT});
    let (created, reply) = post(&fx, "/cases/c1/alerts", Some(&token), &body).await?;
    assert_eq!((created, reply), (StatusCode::CREATED, json!({"alert_id": ALERT})));
    let (replayed, again) = post(&fx, "/cases/c1/alerts", Some(&token), &body).await?;
    assert_eq!((replayed, again), (StatusCode::OK, json!({"alert_id": ALERT})));
    assert_eq!(linked(&fx.db, TENANT, "c1")?, 1);
    let tenants = lock(&fx.db.tenants);
    let history = &tenants.get(TENANT).and_then(|table| table.get("c1")).ok_or("missing")?.case.history;
    assert_eq!(history.len(), 1);
    let event = history.first().ok_or("no event")?;
    assert_eq!((event.kind, event.actor.as_str(), event.at), (CaseEventKind::AlertLinked, ANALYST, NOW));
    assert_eq!(event.alert_id.as_deref(), Some(ALERT));
    Ok(())
}


#[tokio::test]
async fn a_foreign_case_or_alert_is_a_404_and_writes_nothing() -> TestResult {
    let (fx, token) = seeded().await?;
    let foreign_case = post(&fx, "/cases/foreign/alerts", Some(&token), &json!({"alert_id": FOREIGN_ALERT})).await?;
    assert_eq!((foreign_case.0, code_of(&foreign_case.1)), (StatusCode::NOT_FOUND, Some("not_found")));
    let missing = post(&fx, "/cases/none/alerts", Some(&token), &json!({"alert_id": ALERT})).await?;
    assert_eq!((missing.0, code_of(&missing.1)), (StatusCode::NOT_FOUND, Some("not_found")));
    assert_eq!(foreign_case.1, missing.1);
    let foreign_alert = post(&fx, "/cases/c1/alerts", Some(&token), &json!({"alert_id": FOREIGN_ALERT})).await?;
    assert_eq!(
        (foreign_alert.0, code_of(&foreign_alert.1)),
        (StatusCode::NOT_FOUND, Some("alert_not_found"))
    );
    assert_eq!(linked(&fx.db, TENANT, "c1")?, 0);
    assert_eq!(linked(&fx.db, OTHER_TENANT, "foreign")?, 0);
    let listed = read(&fx, "/cases/foreign/alerts", &token).await?;
    assert_eq!((listed.0, code_of(&listed.1)), (StatusCode::NOT_FOUND, Some("not_found")));
    Ok(())
}


#[tokio::test]
async fn bad_bodies_and_ids_never_reach_the_store() -> TestResult {
    let (fx, token) = seeded().await?;
    let before = statements(&fx.db);
    let bad_alerts = [
        json!({"alert_id": "xyz"}),
        json!({"alert_id": ALERT.to_uppercase()}),
        json!({"alert_id": ""}),
    ];
    for body in bad_alerts {
        let (code, reply) = post(&fx, "/cases/c1/alerts", Some(&token), &body).await?;
        assert_eq!((code, code_of(&reply)), (StatusCode::BAD_REQUEST, Some("bad_request")));
        assert!(reply.to_string().contains("alert_id"));
    }
    let forged = [
        json!({"alert_id": ALERT, "tenant": OTHER_TENANT}),
        json!({"alert_id": ALERT, "actor": "root"}),
        json!({}),
        json!({"alert_id": true}),
    ];
    for body in forged {
        assert_eq!(post(&fx, "/cases/c1/alerts", Some(&token), &body).await?.0, StatusCode::BAD_REQUEST);
    }
    let malformed_id = post(&fx, "/cases/%00/alerts", Some(&token), &json!({"alert_id": ALERT})).await?;
    assert_eq!(malformed_id.0, StatusCode::NOT_FOUND);
    let non_utf8 = post(&fx, "/cases/%ff/alerts", Some(&token), &json!({"alert_id": ALERT})).await?;
    assert_eq!(non_utf8.0, StatusCode::NOT_FOUND);
    assert_eq!(statements(&fx.db), before);
    let query = call(
        &fx.router,
        "POST",
        "/cases/c1/alerts?tenant=globex",
        Some(&token),
        Body::from(json!({"alert_id": ALERT}).to_string()),
    )
    .await?;
    assert_eq!(query.status(), StatusCode::CREATED);
    assert_eq!(linked(&fx.db, TENANT, "c1")?, 1);
    let tenant_query = read(&fx, "/cases/c1/alerts?tenant=globex", &token).await?;
    assert_eq!(tenant_query.0, StatusCode::BAD_REQUEST);
    Ok(())
}


#[tokio::test]
async fn a_body_over_the_limit_is_a_413() -> TestResult {
    let (fx, token) = seeded().await?;
    let big = json!({"alert_id": ALERT, "pad": "x".repeat(LINK_BODY_LIMIT)});
    assert_eq!(post(&fx, "/cases/c1/alerts", Some(&token), &big).await?.0, StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}


#[tokio::test]
async fn permissions_follow_the_cases_roles() -> TestResult {
    let (fx, _analyst) = seeded().await?;
    let body = json!({"alert_id": ALERT});
    let reader = login(&fx.router, READER).await?;
    assert_eq!(post(&fx, "/cases/c1/alerts", Some(&reader), &body).await?.0, StatusCode::FORBIDDEN);
    assert_eq!(read(&fx, "/cases/c1/alerts", &reader).await?.0, StatusCode::FORBIDDEN);
    let auditor = login(&fx.router, AUDITOR).await?;
    assert_eq!(post(&fx, "/cases/c1/alerts", Some(&auditor), &body).await?.0, StatusCode::FORBIDDEN);
    assert_eq!(read(&fx, "/cases/c1/alerts", &auditor).await?.0, StatusCode::OK);
    assert_eq!(post(&fx, "/cases/c1/alerts", None, &body).await?.0, StatusCode::UNAUTHORIZED);
    assert_eq!(linked(&fx.db, TENANT, "c1")?, 0);
    Ok(())
}


#[tokio::test]
async fn the_cap_is_a_409_alerts_full() -> TestResult {
    let (fx, token) = seeded().await?;
    for index in 0..=MAX_ALERTS_PER_CASE {
        know(&fx.db, TENANT, &alert_number(index));
    }
    {
        let mut tenants = lock(&fx.db.tenants);
        let entry = tenants.get_mut(TENANT).and_then(|table| table.get_mut("c1")).ok_or("missing")?;
        entry.alerts = (0..MAX_ALERTS_PER_CASE).map(alert_number).collect();
    }
    let over = post(
        &fx,
        "/cases/c1/alerts",
        Some(&token),
        &json!({"alert_id": alert_number(MAX_ALERTS_PER_CASE)}),
    )
    .await?;
    assert_eq!((over.0, code_of(&over.1)), (StatusCode::CONFLICT, Some("alerts_full")));
    assert_eq!(linked(&fx.db, TENANT, "c1")?, MAX_ALERTS_PER_CASE);
    let replay = post(&fx, "/cases/c1/alerts", Some(&token), &json!({"alert_id": alert_number(0)})).await?;
    assert_eq!(replay.0, StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn links_page_by_cursor_in_ascending_order() -> TestResult {
    let (fx, token) = seeded().await?;
    {
        let mut tenants = lock(&fx.db.tenants);
        let entry = tenants.get_mut(TENANT).and_then(|table| table.get_mut("c1")).ok_or("missing")?;
        entry.alerts = (0..TOTAL).map(alert_number).collect();
    }
    let first = read(&fx, &format!("/cases/c1/alerts?limit={PAGE}"), &token).await?;
    let cursor_one = first.1.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let second = read(&fx, &format!("/cases/c1/alerts?limit={PAGE}&cursor={cursor_one}"), &token).await?;
    let cursor_two = second.1.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let third = read(&fx, &format!("/cases/c1/alerts?limit={PAGE}&cursor={cursor_two}"), &token).await?;
    assert_eq!(third.1.get("next_cursor"), Some(&Value::Null));
    let items = |page: &(StatusCode, Value)| page.1.get("items").and_then(Value::as_array).map_or(0, Vec::len);
    assert_eq!((items(&first), items(&second), items(&third)), (PAGE, PAGE, LAST_PAGE));
    let ids: Vec<&str> = [&first, &second, &third]
        .into_iter()
        .flat_map(|page| page.1.get("items").and_then(Value::as_array).into_iter().flatten())
        .filter_map(|item| item.get("alert_id").and_then(Value::as_str))
        .collect();
    assert_eq!(
        ids,
        (0..TOTAL)
            .map(alert_number)
            .collect::<Vec<String>>()
            .iter()
            .map(String::as_str)
            .collect::<Vec<&str>>()
    );
    let default = read(&fx, "/cases/c1/alerts", &token).await?;
    assert_eq!(items(&default), PAGE);
    Ok(())
}


#[tokio::test]
async fn an_empty_case_lists_an_empty_page() -> TestResult {
    let (fx, token) = seeded().await?;
    let page = read(&fx, "/cases/c1/alerts", &token).await?;
    assert_eq!(page, (StatusCode::OK, json!({"items": [], "next_cursor": null})));
    Ok(())
}


#[tokio::test]
async fn a_bad_cursor_limit_or_id_on_the_list_makes_zero_store_calls() -> TestResult {
    let (fx, token) = seeded().await?;
    let before = statements(&fx.db);
    let forged_text = encode_link_cursor("not an alert id");
    let forged_upper = encode_link_cursor(&ALERT.to_uppercase());
    let paths = [
        "/cases/c1/alerts?cursor=!!!".to_owned(),
        format!("/cases/c1/alerts?cursor={forged_text}"),
        format!("/cases/c1/alerts?cursor={forged_upper}"),
        format!("/cases/c1/alerts?cursor={}", "A".repeat(OVER_CURSOR)),
        "/cases/c1/alerts?limit=0".to_owned(),
        "/cases/c1/alerts?limit=101".to_owned(),
        "/cases/c1/alerts?limit=1e1".to_owned(),
    ];
    for path in paths {
        assert_eq!(read(&fx, &path, &token).await?.0, StatusCode::BAD_REQUEST, "{path}");
    }
    assert_eq!(read(&fx, "/cases/%00/alerts", &token).await?.0, StatusCode::NOT_FOUND);
    assert_eq!(statements(&fx.db), before);
    Ok(())
}


#[test]
fn the_link_cursor_round_trips_and_refuses_anything_else() -> TestResult {
    assert_eq!(decode_link_cursor(&encode_link_cursor(ALERT))?, ALERT);
    assert!(matches!(decode_link_cursor("%%"), Err(CaseStoreError::BadCursor)));
    assert!(matches!(decode_link_cursor("/w"), Err(CaseStoreError::BadCursor)));
    assert!(matches!(decode_link_cursor(&encode_link_cursor("abc")), Err(CaseStoreError::BadCursor)));
    Ok(())
}


#[test]
fn link_failures_map_to_stable_replies() -> TestResult {
    let full = link_failure(&CaseStoreError::Full {
        what: "alerts",
        limit: SOME_LIMIT,
    })
    .map_err(|_refused| "refused")?;
    assert_eq!(full.status(), StatusCode::CONFLICT);
    let history = link_failure(&CaseStoreError::Full {
        what: "history",
        limit: SOME_LIMIT,
    })
    .map_err(|_refused| "refused")?;
    assert_eq!(history.status(), StatusCode::CONFLICT);
    assert_eq!(
        link_failure(&CaseStoreError::AlertNotFound).map_err(|_refused| "refused")?.status(),
        StatusCode::NOT_FOUND
    );
    assert!(link_failure(&CaseStoreError::BadAlertId).is_err());
    assert_eq!(ALERTS_PATH, "/cases/{id}/alerts");
    Ok(())
}


#[tokio::test]
async fn a_busy_store_is_a_429_and_the_document_lists_both_routes() -> TestResult {
    let fx = fixture_with(|_db| CasesBackend {
        link: Arc::new(|_scope, _id, _alert, _actor, _now| Box::pin(async { Err(CaseStoreError::Lease(StoreError::Busy)) })),
        links: Arc::new(|_scope, _id, _page| Box::pin(async { Err(CaseStoreError::Lease(StoreError::Busy)) })),
        ..memory_backend(&Arc::new(Db::default()))
    })?;
    let token = login(&fx.router, ANALYST).await?;
    assert_eq!(
        post(&fx, "/cases/c1/alerts", Some(&token), &json!({"alert_id": ALERT})).await?.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(read(&fx, "/cases/c1/alerts", &token).await?.0, StatusCode::TOO_MANY_REQUESTS);
    let document = serde_json::to_value(cases_document())?;
    let path = document.pointer("/paths/~1cases~1{id}~1alerts").ok_or("route missing")?;
    assert!(path.get("get").is_some() && path.get("post").is_some());
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
    let request = || LinkRequest { alert_id: ALERT.to_owned() };
    let query = || ListQuery { cursor: None, limit: None };
    assert_eq!(
        link_flow(&identity, None, &backend, Ok("c1".to_owned()), Ok(request())).await.err(),
        Some(ApiError::Internal)
    );
    assert_eq!(
        link_flow(&unusable, None, &backend, Ok("c1".to_owned()), Ok(request())).await.err(),
        Some(ApiError::Internal)
    );
    assert_eq!(
        link_flow(&identity, None, &backend, Ok("c1".to_owned()), Err(ApiError::BadRequest))
            .await
            .err(),
        Some(ApiError::BadRequest)
    );
    assert_eq!(
        links_flow(&unusable, &backend, Ok("c1".to_owned()), Ok(query())).await.err(),
        Some(ApiError::Internal)
    );
    assert_eq!(
        links_flow(&identity, &backend, Ok("c1".to_owned()), Err(ApiError::BadRequest))
            .await
            .err(),
        Some(ApiError::BadRequest)
    );
    assert!(lock(&fx.db.statements).is_empty());
    Ok(())
}
