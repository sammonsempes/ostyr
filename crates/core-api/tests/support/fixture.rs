use crate::types::TestError;
use axum::routing::{get, post};
use axum::Router;
use core_api::example::{example_access, example_document, example_router};
use core_api::model::{ApiConfig, ApiState, Requirement, Rule};
use core_api::routes::build_router;
use core_api::state::build_state;
use core_api::types::{AccessTable, SharedState};
use core_auth::model::Account;
use core_auth::password::hash_password;
use core_auth::random::os_random;
use core_auth::store::update_store_file;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};


pub const PASSWORD: &str = "correct horse battery staple";


pub const READER: &str = "reader";


pub const OWNER_ONLY: u32 = 0o600;


pub const KEY_BYTES: usize = 32;


pub const KEY_FILL: u8 = 7;


pub const TEST_HEADER_TIMEOUT: Duration = Duration::from_millis(300);


pub const TEST_BODY_TIMEOUT: Duration = Duration::from_millis(300);


pub const TEST_MAX_CONNECTIONS: usize = 2;


pub const TEST_ADDRESS: &str = "127.0.0.1:0";


pub struct Fixture {
    pub dir: TempDir,
    pub state: SharedState,
    pub router: Router,
    pub config: ApiConfig,
}


pub fn keep(state: ApiState) -> Result<ApiState, TestError> {
    Ok(state)
}


pub async fn guarded() -> &'static str {
    "guarded"
}


pub async fn plain() -> &'static str {
    "plain"
}


pub fn extra_router() -> Router<SharedState> {
    Router::new()
        .route("/example/secret", get(guarded))
        .route("/example/events", get(plain))
        .route("/example/change", post(plain))
        .merge(example_router())
}


pub fn extra_access() -> AccessTable {
    [
        (
            "GET /example/secret".to_owned(),
            Rule {
                requirement: Requirement::Permission("users.manage".to_owned()),
                sensitive: false,
            },
        ),
        (
            "GET /example/events".to_owned(),
            Rule {
                requirement: Requirement::Permission("events.read".to_owned()),
                sensitive: false,
            },
        ),
        (
            "POST /example/change".to_owned(),
            Rule {
                requirement: Requirement::Session,
                sensitive: false,
            },
        ),
    ]
    .into_iter()
    .chain(example_access())
    .collect()
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


pub fn private_file(path: &PathBuf, content: &[u8]) -> Result<(), TestError> {
    fs::write(path, content)?;
    set_mode(path, OWNER_ONLY)
}


pub fn config_in(dir: &TempDir) -> Result<ApiConfig, TestError> {
    let key_file = dir.path().join("store.key");
    private_file(&key_file, &[KEY_FILL; KEY_BYTES])?;
    let compromised_list = dir.path().join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    Ok(ApiConfig {
        module: "example".to_owned(),
        tenant: "acme".to_owned(),
        address: TEST_ADDRESS.parse()?,
        tls: None,
        accounts_store: dir.path().join("accounts.json"),
        audit_log: dir.path().join("audit.log"),
        key_file: key_file.display().to_string(),
        compromised_list,
        header_read_timeout: TEST_HEADER_TIMEOUT,
        body_read_timeout: TEST_BODY_TIMEOUT,
        max_connections_per_source: TEST_MAX_CONNECTIONS,
        oidc: None,
    })
}


pub fn seed_reader(config: &ApiConfig) -> Result<(), TestError> {
    let account = Account {
        username: READER.to_owned(),
        password_hash: hash_password(PASSWORD, os_random)?,
        roles: ["reader".to_owned()].into(),
        totp: None,
    };
    update_store_file(&config.accounts_store, os_random, |accounts, _| {
        accounts.insert(READER.to_owned(), account);
        Ok(())
    })?
    .saved?;
    Ok(())
}


pub fn fixture_with(adjust: impl FnOnce(ApiState) -> Result<ApiState, TestError>) -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir)?;
    seed_reader(&config)?;
    let built = build_state(&config, extra_access(), vec![example_document()])?;
    let state: SharedState = Arc::new(adjust(built)?);
    let router = build_router(state.clone(), extra_router());
    Ok(Fixture { dir, state, router, config })
}


pub fn fixture() -> Result<Fixture, TestError> {
    fixture_with(keep)
}
