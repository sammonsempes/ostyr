use crate::posture_fake::{executor, Fake};
use crate::types::TestError;
use axum::Router;
use cloud_posture::api::{posture_access, posture_document, posture_router};
use cloud_posture::api_model::PostureBackend;
use cloud_posture::page::read_parsed;
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::model::{ApiConfig, ApiState, Limits};
use core_api::routes::build_router;
use core_api::state::{build_state_from_files, MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_WINDOW_SECONDS};
use core_api::types::SharedState;
use core_auth::model::Account;
use core_auth::password::hash_password;
use core_auth::random::os_random;
use core_auth::store::update_store_file;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};


pub const PASSWORD: &str = "correct horse battery staple";


pub const READER: &str = "reader";


pub const ANALYST: &str = "analyst";


pub const AUDITOR: &str = "auditor";


pub const TENANT: &str = "acme";


pub const OTHER_TENANT: &str = "globex";


pub const OWNER_ONLY: u32 = 0o600;


pub const KEY_BYTES: usize = 32;


pub const KEY_FILL: u8 = 7;


pub const TEST_TIMEOUT: Duration = Duration::from_millis(300);


pub const TEST_MAX_CONNECTIONS: usize = 2;


pub const OPEN_RATE: u32 = 100_000;


pub struct Fixture {
    pub _dir: TempDir,
    pub router: Router,
    pub fake: Arc<Fake>,
    pub state: SharedState,
}


pub fn memory_backend(fake: &Arc<Fake>) -> PostureBackend {
    let held = Arc::clone(fake);
    PostureBackend {
        read: Arc::new(move |scope, account, cursor, limit| {
            let reading = Arc::clone(&held);
            Box::pin(async move { read_parsed(&executor(&reading), &scope, &account, cursor.as_ref(), limit).await })
        }),
    }
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


pub fn config_in(dir: &TempDir, tenant: &str) -> Result<ApiConfig, TestError> {
    let key_file = dir.path().join("store.key");
    private_file(&key_file, &[KEY_FILL; KEY_BYTES])?;
    let compromised_list = dir.path().join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    Ok(ApiConfig {
        module: "cloud-posture".to_owned(),
        tenant: tenant.to_owned(),
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
    [READER, ANALYST, AUDITOR].into_iter().try_for_each(|name| -> Result<(), TestError> {
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


pub fn fixture_over(fake: Arc<Fake>, tenant: &str, adjust: fn(ApiState) -> Result<ApiState, TestError>) -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir, tenant)?;
    seed_accounts(&config)?;
    let built = build_state_from_files(&config, posture_access(), vec![posture_document()])?;
    let state: SharedState = Arc::new(adjust(built)?);
    let router = build_router(Arc::clone(&state), posture_router(memory_backend(&fake)));
    Ok(Fixture {
        _dir: dir,
        router,
        fake,
        state,
    })
}


pub fn keep(state: ApiState) -> Result<ApiState, TestError> {
    Ok(state)
}


pub fn fixture() -> Result<Fixture, TestError> {
    fixture_over(Arc::new(Fake::default()), TENANT, keep)
}


pub fn other_router(fake: &Arc<Fake>) -> Result<Fixture, TestError> {
    fixture_over(Arc::clone(fake), OTHER_TENANT, keep)
}


pub fn router_of(backend: PostureBackend) -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir, TENANT)?;
    seed_accounts(&config)?;
    let state: SharedState = Arc::new(build_state_from_files(&config, posture_access(), vec![posture_document()])?);
    Ok(Fixture {
        _dir: dir,
        router: build_router(Arc::clone(&state), posture_router(backend)),
        fake: Arc::new(Fake::default()),
        state,
    })
}
