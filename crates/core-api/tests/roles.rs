#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/http.rs"]
mod http;
#[path = "support/types.rs"]
mod types;


use axum::body::Body;
use axum::http::StatusCode;
use core_api::error::StartupError;
use core_api::middleware::authenticate_under;
use core_api::model::Requirement;
use core_api::state::{auth_context, auth_inputs, read_catalog_digested};
use core_auth::error::{AuthError, RolesError};
use core_auth::limiter::ACCOUNT_MAX_FAILURES;
use core_auth::model::Account;
use core_auth::password::hash_password;
use core_auth::random::os_random;
use core_auth::rbac::{builtin_catalog, load_catalog, MAX_ROLES_FILE_BYTES};
use core_auth::store::update_store_file;
use fixture::{fixture, Fixture, PASSWORD, READER};
use http::{audit_lines, body_json, call, login_body, login_token, request, send};
use serde_json::{json, Value};
use std::sync::Arc;
use time::OffsetDateTime;
use types::{TestError, TestResult};


const CUSTOM_ROLES: &str = r#"[
    {"name":"breakglass","permissions":["policy.webauthn_required","events.read"]},
    {"name":"viewer","permissions":["events.read"]}
]"#;


const OVER_THE_CAP: usize = 2;


const CUSTOM_USER: &str = "carol";


const WRONG_PASSWORD: &str = "not the password at all";


fn add_account(fx: &Fixture, name: &str, roles: &[&str]) -> TestResult {
    let account = Account {
        username: name.to_owned(),
        password_hash: hash_password(PASSWORD, os_random)?,
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        totp: None,
        sessions_valid_after: None,
    };
    update_store_file(&fx.config.accounts_store, os_random, |accounts, _| {
        accounts.insert(name.to_owned(), account);
        Ok(())
    })?
    .saved?;
    Ok(())
}


fn use_custom_catalog(fx: &Fixture) -> TestResult {
    fx.state.catalog.store(Arc::new(load_catalog(CUSTOM_ROLES.as_bytes())?));
    Ok(())
}


async fn login_as(fx: &Fixture, name: &str, password: &str) -> Result<(StatusCode, Value), TestError> {
    let response = send(&fx.router, request("POST", "/auth/login", None, login_body(name, password))?).await?;
    let status = response.status();
    Ok((status, body_json(response).await?))
}


fn reasons(fx: &Fixture, action: &str) -> Result<Vec<String>, TestError> {
    Ok(audit_lines(fx)?
        .iter()
        .filter(|line| line.get("action").and_then(Value::as_str) == Some(action))
        .filter_map(|line| line.pointer("/parameters/reason").and_then(Value::as_str).map(str::to_owned))
        .collect())
}


fn token_of(body: &Value) -> Result<String, TestError> {
    Ok(body.get("token").and_then(Value::as_str).ok_or("no token")?.to_owned())
}


#[tokio::test]
async fn a_custom_webauthn_role_refuses_a_password_only_login() -> TestResult {
    let fx = fixture()?;
    use_custom_catalog(&fx)?;
    add_account(&fx, CUSTOM_USER, &["reader", "breakglass"])?;
    let (status, body) = login_as(&fx, CUSTOM_USER, PASSWORD).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.pointer("/error/code"), Some(&json!("invalid_credentials")));
    assert!(body.get("token").is_none());
    assert_eq!(reasons(&fx, "auth.login")?, ["webauthn_required"]);
    Ok(())
}


#[tokio::test]
async fn a_login_holding_an_unknown_role_is_refused_like_a_wrong_password() -> TestResult {
    let fx = fixture()?;
    add_account(&fx, CUSTOM_USER, &["viewer"])?;
    let unknown = login_as(&fx, CUSTOM_USER, PASSWORD).await?;
    let wrong = login_as(&fx, READER, WRONG_PASSWORD).await?;
    assert_eq!(unknown, wrong);
    assert_eq!(unknown.0, StatusCode::UNAUTHORIZED);
    assert_eq!(reasons(&fx, "auth.login")?, ["unknown_role", "bad_password"]);
    Ok(())
}


#[tokio::test]
async fn an_unknown_role_failure_counts_towards_the_lockout() -> TestResult {
    let fx = fixture()?;
    add_account(&fx, CUSTOM_USER, &["viewer"])?;
    for _ in 0..ACCOUNT_MAX_FAILURES {
        assert_eq!(login_as(&fx, CUSTOM_USER, PASSWORD).await?.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(login_as(&fx, CUSTOM_USER, PASSWORD).await?.0, StatusCode::UNAUTHORIZED);
    let recorded = reasons(&fx, "auth.login")?;
    assert_eq!(recorded.iter().filter(|reason| *reason == "unknown_role").count(), ACCOUNT_MAX_FAILURES);
    assert_eq!(recorded.last().map(String::as_str), Some("locked"));
    Ok(())
}


#[tokio::test]
async fn an_open_session_is_refused_once_its_role_leaves_the_catalog_and_never_served_again() -> TestResult {
    let fx = fixture()?;
    use_custom_catalog(&fx)?;
    add_account(&fx, CUSTOM_USER, &["viewer"])?;
    let (status, body) = login_as(&fx, CUSTOM_USER, PASSWORD).await?;
    assert_eq!(status, StatusCode::OK);
    let token = token_of(&body)?;
    assert_eq!(call(&fx.router, "GET", "/example/ping", Some(&token)).await?.status(), StatusCode::OK);
    fx.state.catalog.store(Arc::new(builtin_catalog()));
    assert_eq!(
        call(&fx.router, "GET", "/example/ping", Some(&token)).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&fx.router, "GET", "/auth/me", Some(&token)).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    let refusals: Vec<Value> = audit_lines(&fx)?
        .into_iter()
        .filter(|line| line.pointer("/parameters/reason") == Some(&json!("unknown_role")))
        .collect();
    assert_eq!(refusals.len(), 1);
    assert!(refusals.iter().all(|line| line.get("action") == Some(&json!("api.request"))));
    assert!(refusals.iter().all(|line| line.get("actor_id") == Some(&json!(CUSTOM_USER))));
    use_custom_catalog(&fx)?;
    assert_eq!(
        call(&fx.router, "POST", "/auth/logout", Some(&token)).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&fx.router, "GET", "/example/ping", Some(&token)).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&fx.router, "GET", "/auth/me", Some(&token)).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    let (relogin_status, _) = login_as(&fx, CUSTOM_USER, PASSWORD).await?;
    assert_eq!(relogin_status, StatusCode::OK);
    Ok(())
}


#[test]
fn an_oversize_roles_file_is_reported_with_the_cli_limit() -> TestResult {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("roles.json");
    std::fs::write(&file, vec![b' '; usize::try_from(MAX_ROLES_FILE_BYTES)? + OVER_THE_CAP])?;
    let refused = read_catalog_digested(Some(&file)).err().ok_or("accepted")?;
    assert_eq!(
        refused.to_string(),
        StartupError::from(AuthError::Roles(RolesError::TooLarge { max: MAX_ROLES_FILE_BYTES })).to_string()
    );
    std::fs::write(&file, "[]")?;
    assert!(read_catalog_digested(Some(&file)).is_ok());
    assert!(read_catalog_digested(Some(&dir.path().join("missing.json"))).is_err());
    Ok(())
}


#[test]
fn an_escaped_roles_file_is_refused_by_the_reader() -> TestResult {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("roles.json");
    let escaped = br#"[{"name":"viewer","permissions":["events\u002eread"]}]"#;
    std::fs::write(&file, escaped)?;
    assert!(read_catalog_digested(Some(&file)).is_err());
    Ok(())
}


#[tokio::test]
async fn a_session_of_a_built_in_role_is_untouched() -> TestResult {
    let fx = fixture()?;
    use_custom_catalog(&fx)?;
    assert!(fx.dir.path().exists());
    let token = login_token(&fx.router).await?;
    assert_eq!(call(&fx.router, "GET", "/example/ping", Some(&token)).await?.status(), StatusCode::OK);
    assert_eq!(
        send(&fx.router, request("GET", "/example/ping", None, Body::empty())?).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}


#[tokio::test]
async fn a_session_is_judged_under_the_snapshot_it_is_given_for_both_checks() -> TestResult {
    let fx = fixture()?;
    use_custom_catalog(&fx)?;
    add_account(&fx, CUSTOM_USER, &["viewer"])?;
    let token = token_of(&login_as(&fx, CUSTOM_USER, PASSWORD).await?.1)?;
    let custom = load_catalog(CUSTOM_ROLES.as_bytes())?;
    let permission = Requirement::Permission("events.read".to_owned());
    let now = OffsetDateTime::now_utc();
    fx.state.catalog.store(Arc::new(builtin_catalog()));
    let served = authenticate_under(&fx.state, &custom, Some(&permission), token.clone(), now);
    assert!(served.error.is_none() && served.session.is_some());
    fx.state.catalog.store(Arc::new(custom));
    let refused = authenticate_under(&fx.state, &builtin_catalog(), Some(&permission), token, now);
    assert_eq!(refused.reason, Some("unknown_role"));
    assert!(refused.session.is_none());
    Ok(())
}


#[tokio::test]
async fn a_login_context_uses_the_snapshot_of_its_inputs_not_the_live_catalog() -> TestResult {
    let fx = fixture()?;
    use_custom_catalog(&fx)?;
    let inputs = auth_inputs(&fx.state);
    fx.state.catalog.store(Arc::new(builtin_catalog()));
    let context = auth_context(&fx.state, "request-1", &fx.state.verify, &inputs);
    assert!(context.catalog.contains_key("viewer"));
    assert!(!fx.state.catalog.load().contains_key("viewer"));
    Ok(())
}
