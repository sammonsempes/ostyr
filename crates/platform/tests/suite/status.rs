use crate::fixture::{body_json, call, fixture, fixture_with_permits, login, unweighted_parts, ANALYST, PAGE_TEXT, READER, RESPONDER};
use crate::types::TestResult;
use axum::body::Body;
use axum::http::StatusCode;
use core_config::types::SettingsMap;
use platform::error::PlatformError;
use platform::merge::{load_page_services, page_failure, page_file_of, page_services_of, SETTING_PAGE_FILE};
use platform::model::Module;
use status_page::config::load_config;
use status_page::error::StatusPageError;
use status_page::model::DEFAULT_LIMITS;
use std::cell::Cell;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Semaphore;


const MODULES: &str = "alerts,status";


const CREATE: &str = "/status/incidents";


const UPDATE: &str = "/status/incidents/7/updates";


const RESOLVE: &str = "/status/incidents/7/resolve";


const STARTED_AT: i64 = 1_700_000_000;


const MARKER: &str = "SECRET-PAGE-MARKER";


fn create_body(extra: Option<(&str, &str)>) -> Body {
    let mut body = serde_json::json!({ "service": "web", "title": "Slow", "published": false, "started_at": STARTED_AT });
    if let (Some((key, value)), Some(map)) = (extra, body.as_object_mut()) {
        map.insert(key.to_owned(), serde_json::Value::String(value.to_owned()));
    }
    Body::from(body.to_string())
}


async fn post(router: &axum::Router, path: &str, token: Option<&str>, body: Body) -> Result<StatusCode, crate::types::TestError> {
    Ok(call(router, "POST", path, token, body).await?.status())
}


fn denied(code: StatusCode) -> bool {
    code == StatusCode::UNAUTHORIZED || code == StatusCode::FORBIDDEN
}


#[test]
fn the_page_file_is_required_only_with_status() -> TestResult {
    let mut settings = SettingsMap::new();
    assert_eq!(page_file_of(&settings, &[Module::Alerts])?, None);
    assert_eq!(
        page_file_of(&settings, &[Module::Status, Module::Alerts]),
        Err(PlatformError::MissingPageFile)
    );
    assert!(PlatformError::MissingPageFile.to_string().contains(SETTING_PAGE_FILE));
    settings.insert(SETTING_PAGE_FILE.to_owned(), "/etc/page.yaml".to_owned());
    assert_eq!(page_file_of(&settings, &[Module::Status])?, Some(PathBuf::from("/etc/page.yaml")));
    assert_eq!(page_file_of(&settings, &[Module::Cmdb])?, None);
    Ok(())
}


#[test]
fn status_without_a_page_is_a_build_error() -> TestResult {
    assert_eq!(unweighted_parts(MODULES)?.err().ok_or("built")?, PlatformError::MissingPageFile);
    Ok(())
}


#[test]
fn the_page_file_is_read_once_and_gives_the_page_tenant_and_services() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("page.yaml");
    fs::write(&file, PAGE_TEXT)?;
    let reads = Cell::new(0);
    let page = page_services_of(&file, &|path| {
        reads.set(reads.get() + 1);
        load_config(path, &DEFAULT_LIMITS)
    })?;
    assert_eq!(reads.get(), 1);
    assert_eq!(page.tenant, "acme");
    assert_eq!(page.services.iter().map(String::as_str).collect::<Vec<_>>(), ["web"]);
    assert_eq!(load_page_services(&file)?, page);
    Ok(())
}


fn refusal(error: &PlatformError, reason: &str) -> bool {
    matches!(error, PlatformError::PageFile { reason: found } if *found == reason) && !error.to_string().contains(MARKER)
}


#[test]
fn a_missing_a_directory_an_invalid_and_a_duplicate_page_file_are_refused_with_no_file_text() -> TestResult {
    let dir = tempdir()?;
    let missing = dir.path().join("absent.yaml");
    assert!(refusal(&load_page_services(&missing).err().ok_or("loaded")?, "cannot be read"));
    assert!(refusal(&load_page_services(dir.path()).err().ok_or("loaded")?, "cannot be read"));
    let invalid = dir.path().join("invalid.yaml");
    fs::write(&invalid, format!("id: {MARKER}\ntenant: [\n"))?;
    assert!(refusal(&load_page_services(&invalid).err().ok_or("loaded")?, "is invalid"));
    let duplicate = dir.path().join("duplicate.yaml");
    fs::write(
        &duplicate,
        format!("id: main\ntenant: acme\ntitle: {MARKER}\ncomponents:\n  - name: A\n    service: web\n  - name: B\n    service: web\n"),
    )?;
    assert!(refusal(&load_page_services(&duplicate).err().ok_or("loaded")?, "is invalid"));
    assert_eq!(
        page_failure(&StatusPageError::TenantMismatch),
        PlatformError::PageFile { reason: "is invalid" }
    );
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_fifo_page_file_is_refused_without_blocking() -> TestResult {
    let dir = tempdir()?;
    let fifo = dir.path().join("page.yaml");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status()?.success());
    assert!(refusal(&load_page_services(&fifo).err().ok_or("loaded")?, "cannot be read"));
    Ok(())
}


#[tokio::test]
async fn the_write_routes_need_status_write_and_reach_the_backend() -> TestResult {
    let fx = fixture(MODULES)?;
    for path in [CREATE, UPDATE, RESOLVE] {
        assert_eq!(post(&fx.router, path, None, Body::empty()).await?, StatusCode::UNAUTHORIZED, "{path}");
    }
    for user in [READER, ANALYST] {
        let token = login(&fx.router, user).await?;
        for path in [CREATE, UPDATE, RESOLVE] {
            assert_eq!(
                post(&fx.router, path, Some(&token), create_body(None)).await?,
                StatusCode::FORBIDDEN,
                "{user} {path}"
            );
        }
    }
    let responder = login(&fx.router, RESPONDER).await?;
    let code = post(&fx.router, CREATE, Some(&responder), create_body(None)).await?;
    assert!(
        !denied(code) && code != StatusCode::NOT_FOUND && code != StatusCode::BAD_REQUEST,
        "{code}"
    );
    for (key, value) in [("tenant", "other"), ("actor", "mallory")] {
        let refused = post(&fx.router, CREATE, Some(&responder), create_body(Some((key, value)))).await?;
        assert_eq!(refused, StatusCode::BAD_REQUEST, "{key}");
    }
    let undeclared = Body::from(r#"{"service":"nowhere","title":"t","published":false,"started_at":1700000000}"#);
    assert_eq!(post(&fx.router, CREATE, Some(&responder), undeclared).await?, StatusCode::BAD_REQUEST);
    for method in ["GET", "HEAD", "PUT", "DELETE"] {
        assert!(
            denied(call(&fx.router, method, CREATE, Some(&responder), Body::empty()).await?.status()),
            "{method}"
        );
    }
    Ok(())
}


#[tokio::test]
async fn the_write_routes_share_the_semaphore_and_answer_429_when_it_is_empty() -> TestResult {
    let permits = Arc::new(Semaphore::new(0));
    let limited = fixture_with_permits(MODULES, &permits)?;
    let token = login(&limited.router, RESPONDER).await?;
    assert_eq!(
        post(&limited.router, CREATE, Some(&token), create_body(None)).await?,
        StatusCode::TOO_MANY_REQUESTS
    );
    Ok(())
}


#[tokio::test]
async fn a_deployment_without_status_denies_the_write_routes_by_default() -> TestResult {
    let fx = fixture("alerts")?;
    let responder = login(&fx.router, RESPONDER).await?;
    for path in [CREATE, UPDATE, RESOLVE] {
        assert_eq!(post(&fx.router, path, None, Body::empty()).await?, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(
            post(&fx.router, path, Some(&responder), create_body(None)).await?,
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    let document = body_json(call(&fx.router, "GET", "/openapi.json", None, Body::empty()).await?).await?;
    assert!(document.get("paths").and_then(|paths| paths.get(CREATE)).is_none());
    Ok(())
}


#[tokio::test]
async fn the_document_lists_the_write_paths_when_status_is_selected() -> TestResult {
    let fx = fixture(MODULES)?;
    let document = body_json(call(&fx.router, "GET", "/openapi.json", None, Body::empty()).await?).await?;
    let paths = document.get("paths").ok_or("no paths")?;
    assert!(paths.get(CREATE).is_some());
    assert!(paths.get("/status/incidents/{id}/updates").is_some());
    assert!(paths.get("/status/incidents/{id}/resolve").is_some());
    Ok(())
}
