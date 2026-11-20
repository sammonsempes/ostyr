use crate::state_fake::{executor, Fake};
use crate::types::TestError;
use axum::Router;
use compliance::api::{compliance_access, compliance_document, compliance_router};
use compliance::api_model::StateBackend;
use compliance::read::{asset_state, list_state};
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::model::{ApiConfig, Limits};
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
}


pub fn memory_backend(fake: &Arc<Fake>) -> StateBackend {
    let list_fake = Arc::clone(fake);
    let asset_fake = Arc::clone(fake);
    StateBackend {
        list: Arc::new(move |scope, request| {
            let held = Arc::clone(&list_fake);
            Box::pin(async move { list_state(&executor(&held), &scope, &request.filter, request.cursor.as_ref(), request.limit).await })
        }),
        asset: Arc::new(move |scope, asset| {
            let held = Arc::clone(&asset_fake);
            Box::pin(async move { asset_state(&executor(&held), &scope, &asset).await })
        }),
    }
}


pub fn put_row(fake: &Fake, tenant: &str, key: (&str, &str, &str), cells: (&str, &str, &str)) {
    crate::state_fake::put(fake, tenant, key, cells);
}


pub fn read_count(fake: &Fake) -> usize {
    crate::state_fake::recorded(fake).len()
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


pub fn config_in(dir: &TempDir, rate: u32) -> Result<ApiConfig, TestError> {
    let key_file = dir.path().join("store.key");
    private_file(&key_file, &[KEY_FILL; KEY_BYTES])?;
    let compromised_list = dir.path().join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    Ok(ApiConfig {
        module: "compliance".to_owned(),
        tenant: TENANT.to_owned(),
        address: "127.0.0.1:0".parse()?,
        tls: None,
        accounts_store: dir.path().join("accounts.json"),
        audit_log: dir.path().join("audit.log"),
        key_file: key_file.display().to_string(),
        compromised_list,
        header_read_timeout: TEST_TIMEOUT,
        limits: Limits {
            rate_max_requests: rate,
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


pub fn fixture_with(backend: impl FnOnce(&Arc<Fake>) -> StateBackend) -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir, OPEN_RATE)?;
    seed_accounts(&config)?;
    let fake = Arc::new(Fake::default());
    let state: SharedState = Arc::new(build_state_from_files(&config, compliance_access(), vec![compliance_document()])?);
    let router = build_router(state, compliance_router(backend(&fake)));
    Ok(Fixture { _dir: dir, router, fake })
}


pub fn fixture() -> Result<Fixture, TestError> {
    fixture_with(memory_backend)
}
