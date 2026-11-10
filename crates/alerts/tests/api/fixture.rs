use crate::memory::{handle, Db};
use crate::types::TestError;
use alerts::api::{alerts_access, alerts_document, alerts_router};
use alerts::id::alert_id;
use alerts::model::{Alert, Backend, Severity};
use alerts::store::{get_alert, insert_alerts, list_alerts, summarise};
use alerts::types::RowFuture;
use axum::Router;
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::model::{ApiConfig, Limits};
use core_api::routes::build_router;
use core_api::state::{build_state_from_files, MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_MAX_REQUESTS, RATE_WINDOW_SECONDS};
use core_api::types::SharedState;
use core_auth::model::Account;
use core_auth::password::hash_password;
use core_auth::random::os_random;
use core_auth::store::update_store_file;
use core_pg::scope::{tenant_scope, TenantScope};
use serde_json::json;
use std::fs;
use std::future::ready;
use std::os::unix::fs::PermissionsExt;
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


pub struct Fixture {
    pub _dir: TempDir,
    pub state: SharedState,
    pub router: Router,
    pub db: Arc<Db>,
}


pub fn executor<'a>(db: &'a Db) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(handle(db, &scope, sql, &params))) }
}


pub fn memory_backend(db: &Arc<Db>) -> Backend {
    let list_db = Arc::clone(db);
    let get_db = Arc::clone(db);
    Backend {
        list: Arc::new(move |scope, page| {
            let held = Arc::clone(&list_db);
            Box::pin(async move { list_alerts(&executor(&held), &scope, &page).await })
        }),
        get: Arc::new(move |scope, id| {
            let held = Arc::clone(&get_db);
            Box::pin(async move { get_alert(&executor(&held), &scope, &id).await })
        }),
    }
}


pub fn alert(tenant: &str, rule: &str, names: &[&str], created: u64) -> Alert {
    let event_ids: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
    Alert {
        id: alert_id(tenant, rule, &event_ids),
        tenant: tenant.to_owned(),
        rule_id: rule.to_owned(),
        rule_title: "Whoami executed".to_owned(),
        severity: Severity::High,
        event_time: "2026-11-10T10:00:00Z".to_owned(),
        created_micros: created,
        host_name: Some("host-1".to_owned()),
        user_name: None,
        event_ids,
        summary: summarise(&json!({"process": {"name": "whoami"}})),
    }
}


pub async fn store(db: &Db, alerts: &[Alert]) -> Result<(), TestError> {
    let tenant = alerts.first().map_or(TENANT, |first| first.tenant.as_str());
    insert_alerts(&executor(db), &tenant_scope(tenant)?, alerts).await?;
    Ok(())
}


pub fn private_file(path: &std::path::Path, content: &[u8]) -> Result<(), TestError> {
    fs::write(path, content)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


pub fn config_in(dir: &TempDir) -> Result<ApiConfig, TestError> {
    let key_file = dir.path().join("store.key");
    private_file(&key_file, &[KEY_FILL; KEY_BYTES])?;
    let compromised_list = dir.path().join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    Ok(ApiConfig {
        module: "alerts".to_owned(),
        tenant: TENANT.to_owned(),
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


pub fn fixture_with(backend: impl FnOnce(&Arc<Db>) -> Backend) -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir)?;
    seed_accounts(&config)?;
    let db = Arc::new(Db::default());
    let built = build_state_from_files(&config, alerts_access(), vec![alerts_document()])?;
    let state: SharedState = Arc::new(built);
    let router = build_router(state.clone(), alerts_router(backend(&db)));
    Ok(Fixture {
        _dir: dir,
        state,
        router,
        db,
    })
}


pub fn fixture() -> Result<Fixture, TestError> {
    fixture_with(memory_backend)
}
