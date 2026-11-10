use crate::fixture::{case, config_in, memory_backend, seed_accounts, store, ANALYST, BASE_TIME, OTHER_TENANT, TENANT};
use crate::http::{body_json, get, login};
use crate::memory::Db;
use crate::types::TestResult;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::Response;
use cases::api::{cases_access, cases_document, cases_router};
use core_api::model::ApiIdentity;
use core_api::routes::build_router;
use core_api::state::{build_state_from_files, RATE_MAX_REQUESTS};
use core_api::types::SharedState;
use serde_json::Value;
use std::sync::Arc;
use tempfile::tempdir;


pub async fn swap_after_admission(State(app): State<SharedState>, request: Request, next: Next) -> Response {
    let current = app.identity.load_full();
    app.identity.store(Arc::new(ApiIdentity {
        module: current.module.clone(),
        tenant: OTHER_TENANT.to_owned(),
        generation: current.generation + 1,
    }));
    next.run(request).await
}


#[tokio::test]
async fn an_identity_swap_after_admission_never_serves_the_new_tenant() -> TestResult {
    let dir = tempdir()?;
    let config = config_in(&dir, RATE_MAX_REQUESTS)?;
    seed_accounts(&config)?;
    let db = Arc::new(Db::default());
    let state: SharedState = Arc::new(build_state_from_files(&config, cases_access(), vec![cases_document()])?);
    let swapping = cases_router(memory_backend(&db)).layer(from_fn_with_state(state.clone(), swap_after_admission));
    let router = build_router(state.clone(), swapping);
    store(&db, &[case(TENANT, "own", BASE_TIME), case(OTHER_TENANT, "foreign", BASE_TIME)]).await?;
    let token = login(&router, ANALYST).await?;
    let response = get(&router, "/cases", Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await?;
    let ids: Vec<&str> = json
        .get("items")
        .and_then(Value::as_array)
        .ok_or("no items")?
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str))
        .collect();
    assert_eq!(ids, ["own"]);
    assert_eq!(state.identity.load().tenant, OTHER_TENANT);
    Ok(())
}
