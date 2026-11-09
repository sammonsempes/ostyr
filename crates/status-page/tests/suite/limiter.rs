use crate::harness::{call, get_status, header_of, peer, request, small_settings, snapshot, state_with, PEER, TENANT};
use crate::types::TestResult;
use axum::http::StatusCode;
use core_audit::log::{append, open_file_log};
use core_config::reload::{reload, ReloadContext, ReloadOutcome};
use status_page::limiter::{new_state, source_key, system_millis};
use status_page::model::PageSettings;
use status_page::server::status_router;
use status_page::settings::{open_settings_engine, settings_state, validate_settings};
use status_page::snapshot::publish;
use std::fs;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tempfile::tempdir;


const OTHER_PEER: &str = "192.0.2.11";


const THIRD_PEER: &str = "192.0.2.12";


const BURST: u32 = 2;


const SOURCES: usize = 2;


const SECOND_MILLIS: u64 = 1000;


const RAISED_BURST: u32 = 5;


const SOURCE_FLOOD: u8 = 50;


const FIELD_COUNT: usize = 9;


#[tokio::test]
async fn a_source_over_its_burst_gets_429_and_recovers_with_the_clock() -> TestResult {
    let (state, clock) = state_with(small_settings(1, BURST, SOURCES));
    publish(&state, snapshot(TENANT, "one"))?;
    let router = status_router(state);
    assert_eq!(get_status(&router, "/", PEER).await?, StatusCode::OK);
    assert_eq!(get_status(&router, "/", PEER).await?, StatusCode::OK);
    let limited = call(&router, request("GET", "/", Some(PEER), &[])?).await?;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(header_of(&limited, "retry-after"), Some("1"));
    assert_eq!(header_of(&limited, "cache-control"), Some("no-store"));
    assert_eq!(get_status(&router, "/", OTHER_PEER).await?, StatusCode::OK);
    clock.fetch_add(SECOND_MILLIS, Ordering::SeqCst);
    assert_eq!(get_status(&router, "/", PEER).await?, StatusCode::OK);
    assert_eq!(get_status(&router, "/", PEER).await?, StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}


#[tokio::test]
async fn a_limited_request_never_reaches_the_body_check_or_the_page() -> TestResult {
    let (state, _clock) = state_with(small_settings(1, 1, SOURCES));
    let router = status_router(state);
    assert_eq!(get_status(&router, "/", PEER).await?, StatusCode::SERVICE_UNAVAILABLE);
    let limited = call(&router, request("GET", "/", Some(PEER), &[("content-length", "9")])?).await?;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}


#[tokio::test]
async fn the_key_table_is_capped_and_the_oldest_source_leaves() -> TestResult {
    let (state, _clock) = state_with(small_settings(1, 1, SOURCES));
    let router = status_router(state.clone());
    assert_eq!(get_status(&router, "/", PEER).await?, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(get_status(&router, "/", OTHER_PEER).await?, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(get_status(&router, "/", THIRD_PEER).await?, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(state.buckets.lock().map_err(|error| error.to_string())?.len(), SOURCES);
    assert_eq!(get_status(&router, "/", PEER).await?, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(state.buckets.lock().map_err(|error| error.to_string())?.len(), SOURCES);
    Ok(())
}


#[tokio::test]
async fn many_sources_never_grow_the_table_past_the_cap() -> TestResult {
    let (state, _clock) = state_with(small_settings(1, 1, SOURCES));
    let router = status_router(state.clone());
    for last in 1..=SOURCE_FLOOD {
        get_status(&router, "/", &format!("198.51.100.{last}")).await?;
    }
    assert_eq!(state.buckets.lock().map_err(|error| error.to_string())?.len(), SOURCES);
    Ok(())
}


#[tokio::test]
async fn ipv6_sources_share_a_bucket_per_slash_64() -> TestResult {
    let (state, _clock) = state_with(small_settings(1, 1, SOURCES));
    let router = status_router(state);
    assert_eq!(get_status(&router, "/", "2001:db8:0:1::1").await?, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(get_status(&router, "/", "2001:db8:0:1:ffff::2").await?, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(get_status(&router, "/", "2001:db8:0:2::1").await?, StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}


#[test]
fn source_keys_fold_ipv6_and_unmap_ipv4() -> TestResult {
    assert_eq!(source_key(peer("2001:db8:0:1:aaaa:bbbb:cccc:dddd")?), peer("2001:db8:0:1::")?);
    assert_eq!(source_key(peer("::ffff:192.0.2.1")?), peer("192.0.2.1")?);
    assert_eq!(source_key(peer("192.0.2.1")?), peer("192.0.2.1")?);
    Ok(())
}


#[test]
fn the_system_clock_reads_a_time() -> TestResult {
    assert!(system_millis() > 0);
    Ok(())
}


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "status-page".to_owned(),
        tenant: TENANT.to_owned(),
        module: "status_page".to_owned(),
        target: "settings.yaml".to_owned(),
        request_id: "test".to_owned(),
    }
}


#[tokio::test]
async fn a_settings_reload_changes_the_limit_and_the_table_cap() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("settings.yaml");
    fs::write(&path, "rate_per_second: 1\nburst: 1\nmax_sources: 2\n")?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let (engine, shared) = open_settings_engine(path.clone(), Box::new(move |entry| append(&log, entry)), context())?;
    let state = Arc::new(new_state(TENANT.to_owned(), Arc::clone(&shared), Box::new(|| 0)));
    publish(&state, snapshot(TENANT, "one"))?;
    let router = status_router(Arc::clone(&state));
    assert_eq!(get_status(&router, "/", PEER).await?, StatusCode::OK);
    assert_eq!(get_status(&router, "/", PEER).await?, StatusCode::TOO_MANY_REQUESTS);
    fs::write(&path, format!("rate_per_second: 1\nburst: {RAISED_BURST}\nmax_sources: 1\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(shared.load().burst, RAISED_BURST);
    assert_eq!(get_status(&router, "/", OTHER_PEER).await?, StatusCode::OK);
    assert_eq!(state.buckets.lock().map_err(|error| error.to_string())?.len(), 1);
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    fs::write(&path, "rate_per_second: 0\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(shared.load().burst, RAISED_BURST);
    Ok(())
}


#[test]
fn an_invalid_first_settings_file_fails_the_open() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("settings.yaml");
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    fs::write(&path, "burst: 0\nmax_headers: 0\n")?;
    let zero = open_settings_engine(
        path.clone(),
        Box::new({
            let shared = Arc::clone(&log);
            move |entry| append(&shared, entry)
        }),
        context(),
    );
    assert!(zero.err().is_some_and(|error| error.to_string().contains("burst, max_headers")));
    fs::write(&path, "unknown_key: 1\n")?;
    let unknown = open_settings_engine(path, Box::new(move |entry| append(&log, entry)), context());
    assert!(unknown.is_err());
    Ok(())
}


#[test]
fn settings_validation_names_every_bad_field() -> TestResult {
    assert!(validate_settings(&PageSettings::default()).is_ok());
    let bad = PageSettings {
        rate_per_second: 0,
        burst: 0,
        max_sources: 0,
        max_connections: 0,
        header_read_timeout_seconds: 0,
        connection_timeout_seconds: 0,
        max_headers: 0,
        max_header_bytes: 1,
        cache_max_age_seconds: 0,
    };
    let text = validate_settings(&bad).err().map(|error| error.to_string()).ok_or("accepted")?;
    assert_eq!(text.matches(',').count() + 1, FIELD_COUNT);
    let huge = PageSettings {
        max_sources: usize::MAX,
        max_connections: usize::MAX,
        ..PageSettings::default()
    };
    assert!(validate_settings(&huge).is_err());
    assert_eq!(settings_state(&PageSettings::default()).len(), FIELD_COUNT);
    Ok(())
}
