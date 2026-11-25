use crate::types::TestError;
use alert_grouping::route::{alert_groups_access, alert_groups_document, alert_groups_router};
use alerts::error::StoreError;
use alerts::model::{Alert, AlertPage, Backend, Cursor, Page, Severity};
use alerts::store::summarise;
use alerts::types::{ListFn, StoreFuture};
use axum::Router;
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::model::{ApiConfig, Limits};
use core_api::routes::build_router;
use core_api::state::{build_state_from_files, MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_MAX_REQUESTS, RATE_WINDOW_SECONDS};
use core_auth::model::Account;
use core_auth::password::hash_password;
use core_auth::random::os_random;
use core_auth::store::update_store_file;
use core_pg::scope::TenantScope;
use serde_json::json;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};


pub const PASSWORD: &str = "correct horse battery staple";


pub const READER: &str = "reader";


pub const ANALYST: &str = "analyst";


pub const TENANT: &str = "acme";


pub const OTHER_TENANT: &str = "globex";


pub const OWNER_ONLY: u32 = 0o600;


pub const KEY_BYTES: usize = 32;


pub const KEY_FILL: u8 = 7;


pub const TEST_TIMEOUT: Duration = Duration::from_millis(300);


pub const TEST_MAX_CONNECTIONS: usize = 2;


pub const BASE_TIME: u64 = 1_700_000_000_000_000;


pub const PAGE: usize = 100;


pub struct Fixture {
    pub _dir: TempDir,
    pub router: Router,
}


pub fn alert(tenant: &str, id: &str, rule: &str, events: &[&str], created: u64) -> Alert {
    Alert {
        id: id.to_owned(),
        tenant: tenant.to_owned(),
        rule_id: rule.to_owned(),
        rule_title: "Whoami executed".to_owned(),
        severity: Severity::High,
        event_time: "2026-11-10T10:00:00Z".to_owned(),
        created_micros: created,
        host_name: Some("host-1".to_owned()),
        user_name: None,
        event_ids: events.iter().map(|name| (*name).to_owned()).collect(),
        summary: summarise(&json!({"process": {"name": "whoami"}})),
    }
}


pub fn numbered(tenant: &str, rule: &str, count: usize) -> Vec<Alert> {
    (0..count)
        .map(|index| {
            let name = format!("e{index}");
            alert(tenant, &format!("a{index:05}"), rule, &[name.as_str()], BASE_TIME + index as u64)
        })
        .collect()
}


pub fn cursor_after(alerts: &[Alert]) -> Option<Cursor> {
    alerts.last().map(|last| Cursor {
        created_micros: last.created_micros,
        id: last.id.clone(),
    })
}


pub fn page_of(alerts: Vec<Alert>, more: bool) -> AlertPage {
    let next = more.then(|| cursor_after(&alerts)).flatten();
    AlertPage { alerts, next }
}


pub fn chunked(alerts: &[Alert]) -> Vec<AlertPage> {
    let chunks: Vec<&[Alert]> = alerts.chunks(PAGE).collect();
    let last = chunks.len().saturating_sub(1);
    chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| page_of(chunk.to_vec(), index < last))
        .collect()
}


pub fn fixed_clock() -> u64 {
    BASE_TIME
}


pub fn backend_of(list: ListFn) -> Backend {
    Backend {
        list,
        get: Arc::new(|_scope, _id| Box::pin(async { Ok(None) })),
        triage: Arc::new(|_scope, _id, _change, _expected| Box::pin(async { Err(StoreError::Busy) })),
        clock: fixed_clock,
    }
}


pub fn list_of(serve: impl Fn(TenantScope, Page) -> StoreFuture<AlertPage> + Send + Sync + 'static) -> ListFn {
    Arc::new(serve)
}


pub fn private_file(path: &std::path::Path, content: &[u8]) -> Result<(), TestError> {
    fs::write(path, content)?;
    set_mode(path, OWNER_ONLY)
}


#[cfg(unix)]
pub fn set_mode(path: &std::path::Path, mode: u32) -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}


#[cfg(not(unix))]
pub fn set_mode(_path: &std::path::Path, _mode: u32) -> Result<(), TestError> {
    Ok(())
}


pub fn config_in(dir: &TempDir, tenant: &str) -> Result<ApiConfig, TestError> {
    let key_file = dir.path().join("store.key");
    private_file(&key_file, &[KEY_FILL; KEY_BYTES])?;
    let compromised_list = dir.path().join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    Ok(ApiConfig {
        module: "alerts".to_owned(),
        tenant: tenant.to_owned(),
        address: "127.0.0.1:0".parse()?,
        tls: None,
        accounts_store: dir.path().join("accounts.json"),
        audit_log: dir.path().join("audit.log"),
        key_file: key_file.display().to_string(),
        compromised_list,
        header_read_timeout: TEST_TIMEOUT,
        limits: Limits {
            rate_max_requests: RATE_MAX_REQUESTS,
            rate_window_seconds: RATE_WINDOW_SECONDS,
            max_sources: MAX_TRACKED_SOURCES,
            max_attempts: MAX_TRACKED_ATTEMPTS,
            body_read_timeout: TEST_TIMEOUT,
            max_connections_per_source: TEST_MAX_CONNECTIONS,
        },
        log_level: DEFAULT_LOG_LEVEL,
        oidc: None,
    })
}


pub fn seed_accounts(config: &ApiConfig) -> Result<(), TestError> {
    [READER, ANALYST].into_iter().try_for_each(|name| -> Result<(), TestError> {
        let account = Account {
            username: name.to_owned(),
            password_hash: hash_password(PASSWORD, os_random)?,
            roles: [name.to_owned()].into(),
            totp: None,
            sessions_valid_after: None,
        };
        update_store_file(&config.accounts_store, os_random, |accounts, _| {
            accounts.insert(name.to_owned(), account);
            Ok(())
        })?
        .saved?;
        Ok(())
    })
}


pub fn fixture(tenant: &str, backend: Backend) -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir, tenant)?;
    seed_accounts(&config)?;
    let state = Arc::new(build_state_from_files(&config, alert_groups_access(), vec![alert_groups_document()])?);
    let router = build_router(state, alert_groups_router(backend));
    Ok(Fixture { _dir: dir, router })
}
