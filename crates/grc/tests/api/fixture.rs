use crate::memory::{handle, lock, Db};
use crate::types::{Calls, TestError};
use axum::Router;
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::model::{ApiConfig, ApiState, Limits};
use core_api::routes::build_router;
use core_api::state::{build_state_from_files, MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_WINDOW_SECONDS};
use core_api::types::SharedState;
use core_auth::model::Account;
use core_auth::password::hash_password;
use core_auth::random::os_random;
use core_auth::store::update_store_file;
use core_pg::scope::{tenant_of, TenantScope};
use grc::api::{grc_access, grc_document, grc_router};
use grc::api_model::GrcBackend;
use grc::report::{ComplianceReport, ControlRow, StatusCounts};
use grc::store::{get_report, list_reports, store_report};
use grc::types::RowFuture;
use std::fs;
use std::future::ready;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;


pub const PASSWORD: &str = "correct horse battery staple";


pub const READER: &str = "reader";


pub const ANALYST: &str = "analyst";


pub const AUDITOR: &str = "auditor";


pub const ADMINISTRATOR: &str = "administrator";


pub const RESPONDER: &str = "responder";


pub const TENANT: &str = "acme";


pub const OTHER_TENANT: &str = "globex";


pub const NOW: i64 = 1_800_000_000;


pub const OPEN_RATE: u32 = 100_000;


pub const OWNER_ONLY: u32 = 0o600;


pub const KEY_BYTES: usize = 32;


pub const KEY_FILL: u8 = 7;


pub const TEST_TIMEOUT: Duration = Duration::from_millis(300);


pub const TEST_MAX_CONNECTIONS: usize = 2;


pub const VERSION: u32 = 2;


pub struct Fixture {
    pub _dir: TempDir,
    pub state: SharedState,
    pub router: Router,
    pub db: Arc<Db>,
    pub calls: Calls,
    pub audit_path: std::path::PathBuf,
}


pub fn executor<'a>(db: &'a Db) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + Sync + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(handle(db, &scope, sql, &params))) }
}


pub fn memory_backend(db: &Arc<Db>, calls: &Calls) -> GrcBackend {
    let list_db = Arc::clone(db);
    let get_db = Arc::clone(db);
    let list_calls = Arc::clone(calls);
    let get_calls = Arc::clone(calls);
    GrcBackend {
        list: Arc::new(move |scope, framework, limit| {
            let held = Arc::clone(&list_db);
            lock(&list_calls).push(format!("list {} {framework:?} {limit}", tenant_of(&scope)));
            Box::pin(async move { list_reports(&executor(&held), tenant_of(&scope), framework.as_deref(), limit).await })
        }),
        get: Arc::new(move |scope, id| {
            let held = Arc::clone(&get_db);
            lock(&get_calls).push(format!("get {} {id}", tenant_of(&scope)));
            Box::pin(async move { get_report(&executor(&held), tenant_of(&scope), id).await })
        }),
    }
}


pub fn report(tenant: &str, framework: &str, generated: &str, title: &str) -> ComplianceReport {
    ComplianceReport {
        tenant: tenant.to_owned(),
        framework: framework.to_owned(),
        version: VERSION,
        generated: generated.to_owned(),
        counts: StatusCounts {
            compliant: 1,
            partially_compliant: 0,
            non_compliant: 0,
            not_assessable: 0,
        },
        controls: vec![ControlRow {
            id: "c1".to_owned(),
            title: title.to_owned(),
            status: "compliant".to_owned(),
            evidence_digest: None,
            evidence_time: None,
            risks: Vec::new(),
            open_actions: Vec::new(),
        }],
        gaps: Vec::new(),
        plan: Vec::new(),
    }
}


pub async fn seed(db: &Db, tenant: &str, framework: &str, generated: &str, title: &str) -> Result<(), TestError> {
    store_report(&executor(db), tenant, &report(tenant, framework, generated, title)).await?;
    Ok(())
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


pub fn private_file(path: &std::path::Path, content: &[u8]) -> Result<(), TestError> {
    fs::write(path, content)?;
    set_mode(path, OWNER_ONLY)
}


pub fn config_in(dir: &TempDir) -> Result<ApiConfig, TestError> {
    let key_file = dir.path().join("store.key");
    private_file(&key_file, &[KEY_FILL; KEY_BYTES])?;
    let compromised_list = dir.path().join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    Ok(ApiConfig {
        module: "grc".to_owned(),
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


pub fn seed_accounts(config: &ApiConfig) -> Result<(), TestError> {
    [READER, ANALYST, AUDITOR, ADMINISTRATOR, RESPONDER]
        .into_iter()
        .try_for_each(|name| -> Result<(), TestError> {
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


pub fn frozen_clock() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(NOW)
}


pub fn with_frozen_clock(state: ApiState) -> ApiState {
    ApiState {
        clock: frozen_clock,
        ..state
    }
}


pub fn fixture_over(db: Arc<Db>, backend: impl FnOnce(&Arc<Db>, &Calls) -> GrcBackend) -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir)?;
    seed_accounts(&config)?;
    let calls: Calls = Arc::default();
    let state: SharedState = Arc::new(with_frozen_clock(build_state_from_files(&config, grc_access(), vec![grc_document()])?));
    let router = build_router(state.clone(), grc_router(backend(&db, &calls)));
    Ok(Fixture {
        audit_path: config.audit_log.clone(),
        _dir: dir,
        state,
        router,
        db,
        calls,
    })
}


pub fn fixture() -> Result<Fixture, TestError> {
    fixture_over(Arc::default(), memory_backend)
}
