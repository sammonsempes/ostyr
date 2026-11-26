use crate::fixture::{
    fixture, fixture_over, memory_backend, seed, ADMINISTRATOR, ANALYST, AUDITOR, EMPTY_TRACE, OTHER_TENANT, READER, RESPONDER, TENANT,
};
use crate::http::{body_json, get, login, source};
use crate::memory::{lock, run_id, Db};
use crate::types::{Calls, TestResult};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use core_api::model::{ApiError, ApiIdentity, Requirement};
use core_api::routes::route_key;
use core_auth::rbac::{builtin_catalog, is_allowed, PERMISSION_PLAYBOOKS_READ};
use core_auth::types::RoleSet;
use core_pg::error::PgError;
use response_playbooks::api::{page_of, playbooks_access, playbooks_document, read_reply, scope_of, DEFAULT_LIMIT, GET_PATH, LIST_PATH};
use response_playbooks::api_model::{ListQuery, RunsBackend};
use response_playbooks::error::ReadError;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;


const MARKER: &str = "SECRETVALUE-91c2";


const SEEDED: i64 = 3;


const TENANT_HEADERS: [&str; 4] = ["x-tenant", "x-tenant-id", "x-ostyr-tenant", "tenant"];


const SEQ_2: i64 = 2;


const SEQ_3: i64 = 3;


const CASE_COUNT: usize = 6;


const CURSOR_SEVEN: i64 = 7;


const ROUTE_COUNT: usize = 2;


const SOURCE_RUN: i64 = 2;


const PERMITTED_CALLS: usize = 4;


fn tenant_db() -> Arc<Db> {
    let db = Arc::new(Db::default());
    (1..=SEEDED).for_each(|seq| seed(&db, TENANT, 'a', seq, EMPTY_TRACE));
    (1..=SEEDED).for_each(|seq| seed(&db, OTHER_TENANT, 'b', seq + SEEDED, EMPTY_TRACE));
    db
}


fn calls_of(calls: &Calls) -> Vec<String> {
    lock(calls).clone()
}


fn failing(error: fn() -> ReadError) -> impl FnOnce(&Arc<Db>, &Calls) -> RunsBackend {
    move |_db, _calls| RunsBackend {
        list: Arc::new(move |_scope, _page| Box::pin(async move { Err(error()) })),
        get: Arc::new(move |_scope, _id| Box::pin(async move { Err(error()) })),
    }
}


fn identity(tenant: &str) -> ApiIdentity {
    ApiIdentity {
        module: "playbooks".to_owned(),
        tenant: tenant.to_owned(),
        generation: 0,
    }
}


#[tokio::test]
async fn an_analyst_lists_only_the_identity_tenants_runs_page_by_page() -> TestResult {
    let fx = fixture_over(tenant_db(), memory_backend)?;
    let token = login(&fx.router, ANALYST).await?;
    let first = body_json(get(&fx.router, &format!("{LIST_PATH}?limit=2"), Some(&token)).await?).await?;
    let ids = |value: &serde_json::Value| -> Vec<String> {
        value
            .get("items")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("id").and_then(|id| id.as_str()).map(str::to_owned))
            .collect()
    };
    assert_eq!(ids(&first), vec![run_id('a', SEQ_3), run_id('a', SEQ_2)]);
    assert_eq!(first.get("next_cursor"), Some(&json!("2")));
    let second = body_json(get(&fx.router, &format!("{LIST_PATH}?limit=2&cursor=2"), Some(&token)).await?).await?;
    assert_eq!(ids(&second), vec![run_id('a', 1)]);
    assert_eq!(second.get("next_cursor"), Some(&json!(null)));
    assert!(calls_of(&fx.calls).iter().all(|call| call.contains(TENANT)));
    Ok(())
}


#[tokio::test]
async fn the_default_page_size_is_used_without_a_limit() -> TestResult {
    let fx = fixture_over(tenant_db(), memory_backend)?;
    let token = login(&fx.router, ANALYST).await?;
    get(&fx.router, LIST_PATH, Some(&token)).await?;
    assert_eq!(calls_of(&fx.calls), vec![format!("list {TENANT} None {DEFAULT_LIMIT}")]);
    Ok(())
}


#[tokio::test]
async fn the_tenant_comes_from_the_identity_never_from_the_request() -> TestResult {
    let fx = fixture_over(tenant_db(), memory_backend)?;
    let token = login(&fx.router, ANALYST).await?;
    let query = get(&fx.router, &format!("{LIST_PATH}?tenant={OTHER_TENANT}"), Some(&token)).await?;
    assert_eq!(query.status(), StatusCode::BAD_REQUEST);
    let detail_query = get(
        &fx.router,
        &format!("{GET_PATH}?tenant={OTHER_TENANT}").replace("{id}", &run_id('a', 1)),
        Some(&token),
    )
    .await?;
    assert_eq!(detail_query.status(), StatusCode::BAD_REQUEST);
    assert!(calls_of(&fx.calls).is_empty());
    let other = get(&fx.router, &GET_PATH.replace("{id}", &run_id('b', SEEDED + 1)), Some(&token)).await?;
    assert_eq!(other.status(), StatusCode::NOT_FOUND);
    let own = get(&fx.router, &GET_PATH.replace("{id}", &run_id('a', 1)), Some(&token)).await?;
    assert_eq!(own.status(), StatusCode::OK);
    assert!(calls_of(&fx.calls).iter().all(|call| call.contains(TENANT)));
    Ok(())
}


#[tokio::test]
async fn a_forged_cursor_is_a_400_or_stays_in_the_tenant() -> TestResult {
    let fx = fixture_over(tenant_db(), memory_backend)?;
    let token = login(&fx.router, ANALYST).await?;
    for cursor in ["abc", "-1", "1%20OR%201", "99999999999999999999", ""] {
        let response = get(&fx.router, &format!("{LIST_PATH}?cursor={cursor}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{cursor}");
    }
    let huge = body_json(get(&fx.router, &format!("{LIST_PATH}?cursor={}", i64::MAX), Some(&token)).await?).await?;
    assert!(!huge.to_string().contains(&run_id('b', SEEDED + 1)));
    for limit in ["0", "101", "x", "-3"] {
        let response = get(&fx.router, &format!("{LIST_PATH}?limit={limit}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{limit}");
    }
    Ok(())
}


#[tokio::test]
async fn a_tenant_header_is_ignored() -> TestResult {
    let fx = fixture_over(tenant_db(), memory_backend)?;
    let token = login(&fx.router, ANALYST).await?;
    for name in TENANT_HEADERS {
        let mut request = Request::builder()
            .method("GET")
            .uri(LIST_PATH)
            .header("authorization", format!("Bearer {token}"))
            .header(name, OTHER_TENANT)
            .body(Body::empty())?;
        request.extensions_mut().insert(ConnectInfo(source()));
        let response = fx.router.clone().oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::OK, "{name}");
        let text = body_json(response).await?.to_string();
        assert!(!text.contains(&run_id('b', SEEDED + 1)), "{name}");
    }
    assert_eq!(calls_of(&fx.calls).len(), TENANT_HEADERS.len());
    assert!(calls_of(&fx.calls)
        .iter()
        .all(|call| call.contains(TENANT) && !call.contains(OTHER_TENANT)));
    Ok(())
}


#[tokio::test]
async fn the_roles_with_the_permission_read_and_the_others_are_refused() -> TestResult {
    let fx = fixture()?;
    let path = GET_PATH.replace("{id}", &run_id('a', 1));
    for role in [ANALYST, AUDITOR] {
        let token = login(&fx.router, role).await?;
        assert_eq!(get(&fx.router, LIST_PATH, Some(&token)).await?.status(), StatusCode::OK, "{role}");
        assert_eq!(get(&fx.router, &path, Some(&token)).await?.status(), StatusCode::NOT_FOUND, "{role}");
    }
    for role in [READER, RESPONDER] {
        let token = login(&fx.router, role).await?;
        assert_eq!(get(&fx.router, LIST_PATH, Some(&token)).await?.status(), StatusCode::FORBIDDEN, "{role}");
        assert_eq!(get(&fx.router, &path, Some(&token)).await?.status(), StatusCode::FORBIDDEN, "{role}");
    }
    assert_eq!(get(&fx.router, LIST_PATH, None).await?.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(calls_of(&fx.calls).len(), PERMITTED_CALLS);
    let catalog = builtin_catalog();
    let administrators: RoleSet = [ADMINISTRATOR.to_owned()].into();
    assert!(is_allowed(&catalog, &administrators, PERMISSION_PLAYBOOKS_READ));
    Ok(())
}


#[tokio::test]
async fn a_parameter_value_never_leaves_the_detail_reply() -> TestResult {
    let db = Arc::new(Db::default());
    let trace = json!([{"kind": "action", "action": "block_ip", "params": {"ip": MARKER, "note": "string"}, "reason": MARKER}]).to_string();
    seed(&db, TENANT, 'a', SOURCE_RUN, &trace);
    let fx = fixture_over(db, memory_backend)?;
    let token = login(&fx.router, ANALYST).await?;
    let response = get(&fx.router, &GET_PATH.replace("{id}", &run_id('a', SOURCE_RUN)), Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await?;
    assert!(!body.to_string().contains(MARKER), "{body}");
    assert_eq!(body.pointer("/trace/0/params/note"), Some(&json!("string")));
    assert_eq!(body.pointer("/trace/0/params/ip"), Some(&json!("unknown")));
    assert_eq!(body.get("playbook"), Some(&json!("isolate")));
    let listed = body_json(get(&fx.router, LIST_PATH, Some(&token)).await?).await?;
    assert!(!listed.to_string().contains(MARKER));
    assert!(listed.pointer("/items/0/trace").is_none());
    Ok(())
}


#[tokio::test]
async fn a_malformed_or_undecodable_id_is_the_fixed_404_without_a_store_call() -> TestResult {
    let fx = fixture_over(tenant_db(), memory_backend)?;
    let token = login(&fx.router, ANALYST).await?;
    for id in ["zz", "%FF", "1", "..%2F..%2Fx"] {
        let response = get(&fx.router, &format!("/playbooks/runs/{id}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{id}");
    }
    let found = body_json(get(&fx.router, "/playbooks/runs/zz", Some(&token)).await?).await?;
    assert_eq!(found.pointer("/error/code"), Some(&json!("not_found")));
    assert_eq!(found.pointer("/error/message"), Some(&json!("no such playbook run")));
    Ok(())
}


#[tokio::test]
async fn each_read_failure_has_its_fixed_status() -> TestResult {
    let cases: [(fn() -> ReadError, StatusCode); CASE_COUNT] = [
        (|| ReadError::Busy, StatusCode::TOO_MANY_REQUESTS),
        (|| ReadError::Pg(PgError::ConnectTimeout { seconds: 1 }), StatusCode::SERVICE_UNAVAILABLE),
        (|| ReadError::BadRow, StatusCode::INTERNAL_SERVER_ERROR),
        (|| ReadError::TaskFailed, StatusCode::INTERNAL_SERVER_ERROR),
        (|| ReadError::BadCursor, StatusCode::BAD_REQUEST),
        (|| ReadError::BadLimit { limit: 1 }, StatusCode::BAD_REQUEST),
    ];
    for (error, status) in cases {
        let fx = fixture_over(Arc::default(), failing(error))?;
        let token = login(&fx.router, ANALYST).await?;
        assert_eq!(get(&fx.router, LIST_PATH, Some(&token)).await?.status(), status);
        assert_eq!(
            get(&fx.router, &GET_PATH.replace("{id}", &run_id('a', 1)), Some(&token)).await?.status(),
            status
        );
    }
    Ok(())
}


#[test]
fn the_parsers_and_replies_follow_their_rules() -> TestResult {
    let query = |cursor: Option<&str>, limit: Option<&str>| ListQuery {
        cursor: cursor.map(str::to_owned),
        limit: limit.map(str::to_owned),
    };
    assert_eq!(page_of(&query(None, None))?.size, DEFAULT_LIMIT);
    assert_eq!(page_of(&query(Some("7"), Some("3")))?.after, Some(CURSOR_SEVEN));
    assert!(matches!(page_of(&query(Some("x"), None)), Err(ReadError::BadCursor)));
    assert!(matches!(page_of(&query(None, Some("0"))), Err(ReadError::BadLimit { .. })));
    assert_eq!(scope_of(&identity("-x")).err(), Some(ApiError::Internal));
    assert!(scope_of(&identity(TENANT)).is_ok());
    assert!(read_reply(&ReadError::Busy).is_err());
    Ok(())
}


#[test]
fn the_access_table_and_document_name_both_paths() -> TestResult {
    let table = playbooks_access();
    assert_eq!(table.len(), ROUTE_COUNT);
    [LIST_PATH, GET_PATH].into_iter().for_each(|path| {
        let rule = table.get(&route_key("GET", path));
        assert_eq!(
            rule.map(|found| (&found.requirement, found.sensitive)),
            Some((&Requirement::Permission(PERMISSION_PLAYBOOKS_READ.to_owned()), false))
        );
    });
    let document = serde_json::to_value(playbooks_document())?;
    assert!(document.pointer("/paths/~1playbooks~1runs").is_some());
    assert!(document.pointer("/paths/~1playbooks~1runs~1{id}").is_some());
    Ok(())
}
