use crate::fixture::{
    case, config_in, fixture, fixture_rated, fixture_with, memory_backend, seed_accounts, store, Fixture, ANALYST, AUDITOR, BASE_TIME, NOW,
    OPEN_RATE, OTHER_TENANT, READER, TENANT,
};
use crate::http::{body_json, call, get, login};
use crate::memory::{handle, lock, Db, Forced};
use crate::swap::swap_after_admission;
use crate::types::{TestError, TestResult};
use alerts::error::StoreError;
use alerts::types::RowFuture;
use axum::body::Body;
use axum::http::StatusCode;
use axum::middleware::from_fn_with_state;
use axum::Router;
use cases::api::{cases_access, cases_document, cases_router};
use cases::api_model::{ActionName, ActionRequest, CasesBackend};
use cases::backend::unix_now;
use cases::error::{CaseStoreError, TransitionError};
use cases::model::{Case, CaseEventKind, CaseStatus, Resolution};
use cases::store::{APPLY_SQL, MAX_COMMENTS, MAX_COMMENT_CHARS, MAX_ID_CHARS};
use cases::write::act_on_case;
use cases::write_api::{action_flow, actor_of, case_action, comment_flow, write_failure, ACTION_BODY_LIMIT, COMMENT_BODY_LIMIT};
use core_api::model::{ApiError, ApiIdentity};
use core_api::routes::build_router;
use core_api::state::{build_state_from_files, RATE_MAX_REQUESTS};
use core_api::types::SharedState;
use core_pg::scope::TenantScope;
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Barrier;
use tokio::task::JoinSet;


const HISTORY_AFTER_THREE_ACTIONS: usize = 3;


const NOT_TEXT: u32 = 5;


const OVERSIZE_FACTOR: usize = 3;


const SOME_PARALLEL: usize = 8;


async fn post(fx: &Fixture, path: &str, token: Option<&str>, body: &Value) -> Result<(StatusCode, Value), TestError> {
    let response = call(&fx.router, "POST", path, token, Body::from(body.to_string())).await?;
    let status = response.status();
    Ok((status, body_json(response).await?))
}


fn stored(db: &Db, tenant: &str, id: &str) -> Result<(Case, i64), TestError> {
    let tenants = lock(&db.tenants);
    let entry = tenants.get(tenant).and_then(|table| table.get(id)).ok_or("no such case")?;
    Ok((entry.case.clone(), entry.version))
}


fn set_status(db: &Db, id: &str, status: CaseStatus) -> Result<(), TestError> {
    let mut tenants = lock(&db.tenants);
    let entry = tenants.get_mut(TENANT).and_then(|table| table.get_mut(id)).ok_or("no such case")?;
    entry.case.status = status;
    Ok(())
}


async fn seeded() -> Result<(Fixture, String), TestError> {
    let fx = fixture()?;
    store(&fx.db, &[case(TENANT, "c1", BASE_TIME), case(OTHER_TENANT, "foreign", BASE_TIME)]).await?;
    let token = login(&fx.router, ANALYST).await?;
    Ok((fx, token))
}


fn statements(db: &Db) -> usize {
    lock(&db.statements).len()
}


#[tokio::test]
async fn each_action_from_each_status_is_allowed_or_a_409_that_changes_nothing() -> TestResult {
    let matrix = [
        (CaseStatus::New, "start", None, true),
        (CaseStatus::New, "close", Some("benign"), true),
        (CaseStatus::New, "close", None, false),
        (CaseStatus::New, "reopen", None, false),
        (CaseStatus::InProgress, "start", None, false),
        (CaseStatus::InProgress, "close", Some("true_positive"), true),
        (CaseStatus::InProgress, "close", None, false),
        (CaseStatus::InProgress, "reopen", None, false),
        (CaseStatus::Closed, "start", None, false),
        (CaseStatus::Closed, "close", Some("other"), false),
        (CaseStatus::Closed, "reopen", None, true),
    ];
    for (status, action, resolution, allowed) in matrix {
        let (fx, token) = seeded().await?;
        set_status(&fx.db, "c1", status)?;
        let (before, version) = stored(&fx.db, TENANT, "c1")?;
        let body = resolution.map_or_else(|| json!({"action": action}), |value| json!({"action": action, "resolution": value}));
        let (code, reply) = post(&fx, "/cases/c1/actions", Some(&token), &body).await?;
        let (after, after_version) = stored(&fx.db, TENANT, "c1")?;
        if allowed {
            assert_eq!(code, StatusCode::OK, "{status:?} {action}");
            assert_eq!(after.history.len(), 1);
            let event = after.history.first().ok_or("no event")?;
            assert_eq!(event.actor, ANALYST);
            assert_eq!(event.at, NOW);
            assert_eq!(after_version, version + 1);
            assert_eq!(reply.get("version"), Some(&json!(version + 1)));
            assert_eq!(
                reply.get("status").and_then(Value::as_str),
                Some(serde_json::to_value(after.status)?.as_str().ok_or("status")?)
            );
        } else {
            assert_eq!(code, StatusCode::CONFLICT, "{status:?} {action}");
            assert_eq!((after, after_version), (before, version));
            assert!(reply.pointer("/error/code").and_then(Value::as_str).is_some());
        }
    }
    Ok(())
}


#[tokio::test]
async fn start_close_reopen_records_reopened_and_clears_the_resolution() -> TestResult {
    let (fx, token) = seeded().await?;
    post(&fx, "/cases/c1/actions", Some(&token), &json!({"action": "start"})).await?;
    post(
        &fx,
        "/cases/c1/actions",
        Some(&token),
        &json!({"action": "close", "resolution": "duplicate"}),
    )
    .await?;
    let (closed, _closed_version) = stored(&fx.db, TENANT, "c1")?;
    assert_eq!(closed.resolution, Some(Resolution::Duplicate));
    let (code, reply) = post(&fx, "/cases/c1/actions", Some(&token), &json!({"action": "reopen"})).await?;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(reply.get("resolution"), Some(&Value::Null));
    let (reopened, _reopened_version) = stored(&fx.db, TENANT, "c1")?;
    let kinds: Vec<CaseEventKind> = reopened.history.iter().map(|event| event.kind).collect();
    assert_eq!(kinds, [CaseEventKind::Started, CaseEventKind::Closed, CaseEventKind::Reopened]);
    let read = body_json(get(&fx.router, "/cases/c1", Some(&token)).await?).await?;
    assert_eq!(read.pointer("/counts/history"), Some(&json!(HISTORY_AFTER_THREE_ACTIONS)));
    Ok(())
}


#[tokio::test]
async fn forged_or_malformed_bodies_are_a_400_without_a_store_call() -> TestResult {
    let (fx, token) = seeded().await?;
    let before = statements(&fx.db);
    let bodies = [
        json!({"action": "start", "actor": "root"}),
        json!({"action": "start", "tenant": OTHER_TENANT}),
        json!({"action": "explode"}),
        json!({"action": "close", "resolution": "nonsense"}),
        json!({"action": "start", "resolution": "benign"}),
        json!({"action": "reopen", "resolution": "benign"}),
        json!({}),
        json!([]),
    ];
    for body in bodies {
        let (code, reply) = post(&fx, "/cases/c1/actions", Some(&token), &body).await?;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.pointer("/error/code"), Some(&json!("bad_request")));
    }
    let comments = [
        json!({"text": "x", "author": "root"}),
        json!({"text": ""}),
        json!({"text": "a\u{0}b"}),
        json!({"text": "x".repeat(MAX_COMMENT_CHARS + 1)}),
        json!({"text": NOT_TEXT}),
        json!({}),
    ];
    for body in comments {
        let (code, reply) = post(&fx, "/cases/c1/comments", Some(&token), &body).await?;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{body}");
        let message = reply.pointer("/error/message").and_then(Value::as_str).ok_or("no message")?;
        assert!(!message.contains("xxxx") && !message.contains("root"));
    }
    let text_error = post(&fx, "/cases/c1/comments", Some(&token), &json!({"text": ""})).await?.1;
    assert!(text_error.to_string().contains("`text`"));
    let resolution_error = post(
        &fx,
        "/cases/c1/actions",
        Some(&token),
        &json!({"action": "start", "resolution": "benign"}),
    )
    .await?
    .1;
    assert!(resolution_error.to_string().contains("`resolution`"));
    let raw = call(&fx.router, "POST", "/cases/c1/actions", Some(&token), Body::from("{not json")).await?;
    assert_eq!(raw.status(), StatusCode::BAD_REQUEST);
    assert_eq!(statements(&fx.db), before);
    assert!(stored(&fx.db, TENANT, "c1")?.0.history.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_comment_of_exactly_the_cap_is_stored_with_the_session_user() -> TestResult {
    let (fx, token) = seeded().await?;
    let text = "e".repeat(MAX_COMMENT_CHARS);
    let (code, reply) = post(&fx, "/cases/c1/comments", Some(&token), &json!({"text": text})).await?;
    assert_eq!(code, StatusCode::CREATED);
    assert_eq!(reply.get("author"), Some(&json!(ANALYST)));
    assert_eq!(reply.get("at"), Some(&json!(NOW)));
    let (after, version) = stored(&fx.db, TENANT, "c1")?;
    assert_eq!(after.comments.len(), 1);
    assert_eq!(version, 1);
    Ok(())
}


#[tokio::test]
async fn bodies_over_the_route_limits_are_refused_before_any_store_call() -> TestResult {
    let (fx, token) = seeded().await?;
    let before = statements(&fx.db);
    let padding = "x".repeat(ACTION_BODY_LIMIT);
    let big_action = json!({"action": "start", "resolution": padding}).to_string();
    let action_response = call(&fx.router, "POST", "/cases/c1/actions", Some(&token), Body::from(big_action)).await?;
    assert_eq!(action_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let big_comment = json!({"text": "x".repeat(COMMENT_BODY_LIMIT)}).to_string();
    let comment_response = call(&fx.router, "POST", "/cases/c1/comments", Some(&token), Body::from(big_comment)).await?;
    assert_eq!(comment_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let huge = "x".repeat(COMMENT_BODY_LIMIT * OVERSIZE_FACTOR);
    let huge_response = call(&fx.router, "POST", "/cases/c1/comments", Some(&token), Body::from(huge)).await?;
    assert_eq!(huge_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(statements(&fx.db), before);
    Ok(())
}


#[tokio::test]
async fn roles_without_cases_write_and_missing_tokens_never_reach_the_store() -> TestResult {
    let (fx, _analyst) = seeded().await?;
    let reader = login(&fx.router, READER).await?;
    let auditor = login(&fx.router, AUDITOR).await?;
    let before = statements(&fx.db);
    let bodies = [
        ("/cases/c1/actions", json!({"action": "start"})),
        ("/cases/c1/comments", json!({"text": "hi"})),
    ];
    for (path, body) in bodies {
        assert_eq!(post(&fx, path, Some(&reader), &body).await?.0, StatusCode::FORBIDDEN);
        assert_eq!(post(&fx, path, Some(&auditor), &body).await?.0, StatusCode::FORBIDDEN);
        assert_eq!(post(&fx, path, None, &body).await?.0, StatusCode::UNAUTHORIZED);
        assert_eq!(post(&fx, path, Some("bogus"), &body).await?.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(statements(&fx.db), before);
    assert!(stored(&fx.db, TENANT, "c1")?.0.history.is_empty());
    Ok(())
}


#[tokio::test]
async fn another_tenants_case_a_missing_one_and_malformed_ids_are_the_same_404() -> TestResult {
    let (fx, token) = seeded().await?;
    let (foreign_before, version) = stored(&fx.db, OTHER_TENANT, "foreign")?;
    let missing = post(&fx, "/cases/nothing/actions", Some(&token), &json!({"action": "start"})).await?;
    assert_eq!(missing.0, StatusCode::NOT_FOUND);
    let foreign = post(&fx, "/cases/foreign/actions", Some(&token), &json!({"action": "start"})).await?;
    assert_eq!(foreign, missing);
    let comment = post(&fx, "/cases/foreign/comments", Some(&token), &json!({"text": "hi"})).await?;
    assert_eq!(comment, missing);
    let missing_comment = post(&fx, "/cases/nothing/comments", Some(&token), &json!({"text": "hi"})).await?;
    assert_eq!(missing_comment, missing);
    assert_eq!(stored(&fx.db, OTHER_TENANT, "foreign")?, (foreign_before, version));
    let before = statements(&fx.db);
    let long = "x".repeat(MAX_ID_CHARS + 1);
    for id in ["%00", "%ff", &long] {
        for (suffix, body) in [("actions", json!({"action": "start"})), ("comments", json!({"text": "hi"}))] {
            let reply = post(&fx, &format!("/cases/{id}/{suffix}"), Some(&token), &body).await?;
            assert_eq!(reply, missing, "{id} {suffix}");
        }
    }
    assert_eq!(statements(&fx.db), before);
    assert!(lock(&fx.db.statements)
        .iter()
        .all(|(tenant, _sql)| tenant == TENANT || tenant == OTHER_TENANT));
    Ok(())
}


#[tokio::test]
async fn an_identity_swap_after_admission_writes_in_the_admitting_tenant() -> TestResult {
    let dir = tempdir()?;
    let config = config_in(&dir, RATE_MAX_REQUESTS)?;
    seed_accounts(&config)?;
    let db = Arc::new(Db::default());
    let state: SharedState = Arc::new(build_state_from_files(&config, cases_access(), vec![cases_document()])?);
    let swapping = cases_router(memory_backend(&db)).layer(from_fn_with_state(state.clone(), swap_after_admission));
    let router = build_router(state.clone(), swapping);
    store(&db, &[case(TENANT, "same", BASE_TIME), case(OTHER_TENANT, "same", BASE_TIME)]).await?;
    let token = login(&router, ANALYST).await?;
    let response = call(
        &router,
        "POST",
        "/cases/same/actions",
        Some(&token),
        Body::from(json!({"action": "start"}).to_string()),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(state.identity.load().tenant, OTHER_TENANT);
    assert_eq!(stored(&db, OTHER_TENANT, "same")?.0.history.len(), 0);
    assert_eq!(stored(&db, TENANT, "same")?.0.history.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_comment_at_the_cap_is_a_409_and_adds_nothing() -> TestResult {
    let (fx, token) = seeded().await?;
    for _ in 0..MAX_COMMENTS {
        assert_eq!(
            post(&fx, "/cases/c1/comments", Some(&token), &json!({"text": "hi"})).await?.0,
            StatusCode::CREATED
        );
    }
    let (code, reply) = post(&fx, "/cases/c1/comments", Some(&token), &json!({"text": "one more"})).await?;
    assert_eq!(code, StatusCode::CONFLICT);
    assert_eq!(reply.pointer("/error/code"), Some(&json!("full")));
    assert!(reply.to_string().contains(&MAX_COMMENTS.to_string()));
    assert_eq!(stored(&fx.db, TENANT, "c1")?.0.comments.len(), MAX_COMMENTS);
    Ok(())
}


fn gated_backend(db: &Arc<Db>, gate: &Arc<Barrier>) -> CasesBackend {
    let held_db = Arc::clone(db);
    let held_gate = Arc::clone(gate);
    CasesBackend {
        act: Arc::new(move |scope, id, action, actor, now| {
            let inner = Arc::clone(&held_db);
            let barrier = Arc::clone(&held_gate);
            Box::pin(async move {
                let gated = |tenant: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> {
                    let waiting = Arc::clone(&barrier);
                    let store = Arc::clone(&inner);
                    Box::pin(async move {
                        if sql == APPLY_SQL {
                            waiting.wait().await;
                        }
                        handle(&store, &tenant, sql, &params)
                    })
                };
                act_on_case(&gated, &scope, &id, action, &actor, now).await
            })
        }),
        ..memory_backend(db)
    }
}


async fn close_once(router: Router, token: String) -> Result<(StatusCode, Value), String> {
    close_request(&router, &token).await.map_err(|failure| failure.to_string())
}


async fn close_request(router: &Router, token: &str) -> Result<(StatusCode, Value), TestError> {
    let body = json!({"action": "close", "resolution": "benign"});
    let response = call(router, "POST", "/cases/c1/actions", Some(token), Body::from(body.to_string())).await?;
    let status = response.status();
    Ok((status, body_json(response).await?))
}


#[tokio::test]
async fn parallel_closes_leave_one_closed_event() -> TestResult {
    let gate = Arc::new(Barrier::new(SOME_PARALLEL));
    let fx = fixture_rated(OPEN_RATE, |db| gated_backend(db, &gate))?;
    store(&fx.db, &[case(TENANT, "c1", BASE_TIME)]).await?;
    let token = login(&fx.router, ANALYST).await?;
    let mut tasks = JoinSet::new();
    (0..SOME_PARALLEL).for_each(|_| {
        tasks.spawn(close_once(fx.router.clone(), token.clone()));
    });
    let mut replies = Vec::new();
    for _ in 0..SOME_PARALLEL {
        replies.push(tasks.join_next().await.ok_or("a request task is missing")???);
    }
    let conflicts: Vec<_> = replies.iter().filter(|(code, _)| *code == StatusCode::CONFLICT).collect();
    assert_eq!(replies.iter().filter(|(code, _)| *code == StatusCode::OK).count(), 1);
    assert_eq!(conflicts.len(), SOME_PARALLEL - 1);
    assert!(conflicts
        .iter()
        .all(|(_, reply)| reply.pointer("/error/code") == Some(&json!("case_changed"))));
    let (closed, _) = stored(&fx.db, TENANT, "c1")?;
    assert_eq!(closed.history.len(), 1);
    assert_eq!(closed.status, CaseStatus::Closed);
    Ok(())
}


#[tokio::test]
async fn store_failures_map_to_stable_statuses() -> TestResult {
    let (fx, token) = seeded().await?;
    lock(&fx.db.forced).push_back(Forced::Fail);
    let (code, reply) = post(&fx, "/cases/c1/actions", Some(&token), &json!({"action": "start"})).await?;
    assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reply.pointer("/error/code"), Some(&json!("internal_error")));
    let conflicting = fixture_with(|_db| CasesBackend {
        act: Arc::new(|_scope, _id, _action, _actor, _now| Box::pin(async { Err(CaseStoreError::Conflict) })),
        comment: Arc::new(|_scope, _id, _comment| Box::pin(async { Err(CaseStoreError::Lease(StoreError::Busy)) })),
        ..memory_backend(&Arc::new(Db::default()))
    })?;
    let analyst = login(&conflicting.router, ANALYST).await?;
    let (conflict_code, conflict_reply) = post(&conflicting, "/cases/c1/actions", Some(&analyst), &json!({"action": "start"})).await?;
    assert_eq!(conflict_code, StatusCode::CONFLICT);
    assert_eq!(conflict_reply.pointer("/error/code"), Some(&json!("case_changed")));
    let busy = post(&conflicting, "/cases/c1/comments", Some(&analyst), &json!({"text": "hi"})).await?;
    assert_eq!(busy.0, StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}


#[tokio::test]
async fn a_request_without_a_session_is_a_generic_500_and_never_written() -> TestResult {
    let fx = fixture()?;
    let backend = memory_backend(&fx.db);
    let identity = ApiIdentity {
        module: "cases".to_owned(),
        tenant: TENANT.to_owned(),
        generation: 0,
    };
    let request = ActionRequest {
        action: ActionName::Start,
        resolution: None,
    };
    assert_eq!(
        action_flow(&identity, None, &backend, Ok("c1".to_owned()), Ok(request)).await.err(),
        Some(ApiError::Internal)
    );
    let text = cases::api_model::CommentRequest { text: "hi".to_owned() };
    assert_eq!(
        comment_flow(&identity, None, &backend, Ok("c1".to_owned()), Ok(text)).await.err(),
        Some(ApiError::Internal)
    );
    assert_eq!(actor_of(None), Err(ApiError::Internal));
    let unusable = ApiIdentity {
        module: "cases".to_owned(),
        tenant: "bad tenant".to_owned(),
        generation: 0,
    };
    let again = ActionRequest {
        action: ActionName::Start,
        resolution: None,
    };
    assert_eq!(
        action_flow(&unusable, None, &backend, Ok("c1".to_owned()), Ok(again)).await.err(),
        Some(ApiError::Internal)
    );
    let more = cases::api_model::CommentRequest { text: "hi".to_owned() };
    assert_eq!(
        comment_flow(&unusable, None, &backend, Ok("c1".to_owned()), Ok(more)).await.err(),
        Some(ApiError::Internal)
    );
    assert!(lock(&fx.db.statements).is_empty());
    Ok(())
}


#[test]
fn pure_helpers_map_inputs_to_actions_and_failures() -> TestResult {
    let close = ActionRequest {
        action: ActionName::Close,
        resolution: None,
    };
    assert_eq!(case_action(&close).map(|action| format!("{action:?}")), Some("Close(None)".to_owned()));
    assert!(write_failure(&CaseStoreError::NotFound).is_ok());
    assert!(write_failure(&CaseStoreError::Transition(TransitionError::ResolutionRequired)).is_ok());
    assert_eq!(write_failure(&CaseStoreError::TenantMismatch).err(), Some(ApiError::Internal));
    assert!(unix_now() > BASE_TIME);
    Ok(())
}


#[tokio::test]
async fn a_wrong_content_type_is_a_400_and_the_openapi_lists_both_writes() -> TestResult {
    let (fx, token) = seeded().await?;
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/cases/c1/actions")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "text/plain")
        .body(Body::from("{}"))?;
    request.extensions_mut().insert(axum::extract::ConnectInfo(crate::http::source()));
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let document = body_json(get(&fx.router, "/openapi.json", None).await?).await?;
    let paths = document.get("paths").ok_or("no paths")?;
    for path in ["/cases/{id}/actions", "/cases/{id}/comments"] {
        let responses = paths.pointer(&format!("/{}/post/responses", path.replace('/', "~1"))).ok_or("no post")?;
        assert!(["200", "201", "400", "404", "409", "413"]
            .iter()
            .any(|code| responses.get(*code).is_some()));
    }
    Ok(())
}
