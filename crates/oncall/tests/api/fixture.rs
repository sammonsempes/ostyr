use crate::types::{Call, TestError};
use axum::Router;
use chrono::{DateTime, TimeZone, Utc};
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::model::{ApiConfig, Limits};
use core_api::routes::build_router;
use core_api::state::{build_state_from_files, MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_WINDOW_SECONDS};
use core_api::types::SharedState;
use core_auth::model::Account;
use core_auth::password::hash_password;
use core_auth::random::os_random;
use core_auth::rbac::PERMISSION_ONCALL_READ;
use core_auth::store::update_store_file;
use core_pg::scope::{tenant_of, TenantScope};
use oncall::alert::{Alert, AlertPage, Event, LifecycleState, Phase};
use oncall::api::{oncall_access, oncall_document, oncall_router};
use oncall::api_model::OncallBackend;
use oncall::error::{ReadError, StoreError};
use oncall::lifecycle::transition;
use oncall::store::timestamps;
use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tempfile::{tempdir, TempDir};


pub const PASSWORD: &str = "correct horse battery staple";


pub const READER: &str = "reader";


pub const ANALYST: &str = "analyst";


pub const TENANT: &str = "acme";


pub const OTHER_TENANT: &str = "globex";


pub const STAMP: i64 = 1_800_000_000;


pub const CLOCK_OFFSET: i64 = 600;


#[cfg(unix)]
pub const OWNER_ONLY: u32 = 0o600;


pub const KEY_BYTES: usize = 32;


pub const KEY_FILL: u8 = 7;


pub const TEST_TIMEOUT: Duration = Duration::from_millis(300);


pub const TEST_MAX_CONNECTIONS: usize = 2;


pub const OPEN_RATE: u32 = 100_000;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Answer,
    Busy,
    Fail,
    Down,
    BadCell,
    Moved,
}


pub struct Script {
    pub alerts: Mutex<BTreeMap<String, Vec<Alert>>>,
    pub calls: Mutex<Vec<Call>>,
    pub mode: Mutex<Mode>,
}


pub struct Fixture {
    pub _dir: TempDir,
    pub router: Router,
    pub script: Arc<Script>,
    pub state: SharedState,
    pub audit_path: std::path::PathBuf,
}


pub fn lock<Guarded>(mutex: &Mutex<Guarded>) -> MutexGuard<'_, Guarded> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn at(offset: i64) -> Result<DateTime<Utc>, TestError> {
    Ok(Utc.timestamp_opt(STAMP + offset, 0).single().ok_or("bad stamp")?)
}


pub fn alert(id: i64, fingerprint: &str, opened: DateTime<Utc>) -> Alert {
    Alert {
        id,
        fingerprint: fingerprint.to_owned(),
        state: LifecycleState {
            phase: Phase::Open,
            level: 0,
        },
        occurrences: 1,
        version: 1,
        opened_at: opened,
        acknowledged_at: None,
        resolved_at: None,
    }
}


pub fn stored(script: &Script, tenant: &str, alerts: Vec<Alert>) {
    lock(&script.alerts).insert(tenant.to_owned(), alerts);
}


pub fn set_mode(script: &Script, mode: Mode) {
    *lock(&script.mode) = mode;
}


pub fn failure(mode: Mode) -> Option<ReadError> {
    match mode {
        Mode::Answer => None,
        Mode::Busy => Some(ReadError::Lease(alerts::error::StoreError::Busy)),
        Mode::Fail => Some(ReadError::Unrepresentable),
        Mode::Down => Some(ReadError::Store(oncall::error::StoreError::NotFound)),
        Mode::Moved => Some(ReadError::Store(StoreError::Conflict)),
        Mode::BadCell => Some(ReadError::Store(oncall::error::StoreError::BadRow { column: "opened_at" })),
    }
}


pub fn clock() -> DateTime<Utc> {
    DateTime::UNIX_EPOCH + chrono::Duration::seconds(STAMP + CLOCK_OFFSET)
}


pub fn apply_in(script: &Script, tenant: &str, id: i64, event: Event, now: DateTime<Utc>) -> Result<Alert, ReadError> {
    lock(&script.calls).push((tenant.to_owned(), None, Some(id)));
    let mode = *lock(&script.mode);
    failure(mode).map_or(Ok(()), Err)?;
    let mut alerts = lock(&script.alerts);
    let alert = alerts
        .get_mut(tenant)
        .and_then(|list| list.iter_mut().find(|candidate| candidate.id == id))
        .ok_or(ReadError::Store(StoreError::NotFound))?;
    let next = transition(alert.state, event).map_err(|error| ReadError::Store(StoreError::Lifecycle(error)))?;
    let (acknowledged, resolved) = timestamps(alert, next, now);
    alert.state = next;
    alert.acknowledged_at = acknowledged;
    alert.resolved_at = resolved;
    alert.version += 1;
    Ok(alert.clone())
}


pub fn backend_of(script: &Arc<Script>) -> OncallBackend {
    let listing = Arc::clone(script);
    let getting = Arc::clone(script);
    let applying = Arc::clone(script);
    OncallBackend {
        list: Arc::new(move |scope: TenantScope, limit| {
            let held = Arc::clone(&listing);
            Box::pin(async move {
                lock(&held.calls).push((tenant_of(&scope).to_owned(), Some(limit), None));
                let mode = *lock(&held.mode);
                let alerts = lock(&held.alerts).get(tenant_of(&scope)).map_or_else(Vec::new, Clone::clone);
                failure(mode).map_or_else(
                    || {
                        Ok(AlertPage {
                            alerts: alerts.into_iter().take(limit as usize).collect(),
                            skipped: 0,
                        })
                    },
                    Err,
                )
            })
        }),
        get: Arc::new(move |scope: TenantScope, id| {
            let held = Arc::clone(&getting);
            Box::pin(async move {
                lock(&held.calls).push((tenant_of(&scope).to_owned(), None, Some(id)));
                let mode = *lock(&held.mode);
                let found = lock(&held.alerts)
                    .get(tenant_of(&scope))
                    .and_then(|list| list.iter().find(|candidate| candidate.id == id).cloned());
                failure(mode).map_or(Ok(found), Err)
            })
        }),
        apply: Arc::new(move |scope: TenantScope, id, event, now| {
            let held = Arc::clone(&applying);
            Box::pin(async move { apply_in(&held, tenant_of(&scope), id, event, now) })
        }),
        clock,
    }
}


pub fn config_in(dir: &TempDir) -> Result<ApiConfig, TestError> {
    let key_file = dir.path().join("store.key");
    fs::write(&key_file, [KEY_FILL; KEY_BYTES])?;
    restrict(&key_file)?;
    let compromised_list = dir.path().join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    Ok(ApiConfig {
        module: "oncall".to_owned(),
        tenant: TENANT.to_owned(),
        address: "127.0.0.1:0".parse()?,
        tls: None,
        accounts_store: dir.path().join("accounts.json"),
        audit_log: dir.path().join("audit.log"),
        key_file: key_file.display().to_string(),
        compromised_list,
        header_read_timeout: TEST_TIMEOUT,
        limits: Limits {
            rate_max_requests: OPEN_RATE,
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


#[cfg(unix)]
pub fn restrict(path: &std::path::Path) -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


#[cfg(not(unix))]
pub fn restrict(_path: &std::path::Path) -> Result<(), TestError> {
    Ok(())
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


pub fn fixture() -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir)?;
    seed_accounts(&config)?;
    let script = Arc::new(Script {
        alerts: Mutex::new(BTreeMap::new()),
        calls: Mutex::new(Vec::new()),
        mode: Mutex::new(Mode::Answer),
    });
    let built = build_state_from_files(&config, oncall_access(), vec![oncall_document()])?;
    let mut catalog = (*built.catalog.load_full()).clone();
    catalog.entry(ANALYST.to_owned()).or_default().insert(PERMISSION_ONCALL_READ.to_owned());
    built.catalog.store(Arc::new(catalog));
    let state: SharedState = Arc::new(built);
    let audit_path = config.audit_log.clone();
    let router = build_router(Arc::clone(&state), oncall_router(backend_of(&script)));
    Ok(Fixture {
        _dir: dir,
        router,
        script,
        state,
        audit_path,
    })
}
