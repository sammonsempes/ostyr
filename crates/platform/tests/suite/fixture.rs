use crate::types::TestError;
use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, Response};
use axum::Router;
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::model::{ApiConfig, Limits};
use core_api::routes::build_router;
use core_api::server::new_listener;
use core_api::state::{build_state_from_files, MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_MAX_REQUESTS, RATE_WINDOW_SECONDS};
use core_api::types::SharedState;
use core_auth::model::Account;
use core_auth::password::hash_password;
use core_auth::random::os_random;
use core_auth::store::update_store_file;
use platform::merge::{module_parts, modules_of, shared_permits, ACTOR};
use platform::model::Module;
use platform::types::Parts;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tower::ServiceExt;


pub const PASSWORD: &str = "correct horse battery staple";


pub const READER: &str = "reader";


pub const ANALYST: &str = "analyst";


const OWNER_ONLY: u32 = 0o600;


const KEY_BYTES: usize = 32;


const KEY_FILL: u8 = 7;


const TEST_TIMEOUT: Duration = Duration::from_millis(300);


const TEST_MAX_CONNECTIONS: usize = 2;


const CLIENT_PORT: u16 = 40_000;


const BODY_READ_LIMIT: usize = 1_048_576;


const PG_TEXT: &str = "host: 127.0.0.1\nport: 1\ndatabase: ostyr\nuser: ostyr\npassword_file: /run/pg.pass\nca_file: /run/ca.pem\n";


pub struct Fixture {
    pub _dir: TempDir,
    pub router: Router,
}


#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}


#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), TestError> {
    Ok(())
}


fn config_in(dir: &TempDir) -> Result<ApiConfig, TestError> {
    let key_file = dir.path().join("store.key");
    fs::write(&key_file, [KEY_FILL; KEY_BYTES])?;
    set_mode(&key_file, OWNER_ONLY)?;
    let compromised_list = dir.path().join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    Ok(ApiConfig {
        module: "platform".to_owned(),
        tenant: "acme".to_owned(),
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


fn seed_accounts(config: &ApiConfig) -> Result<(), TestError> {
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


pub fn module_text(modules: &str, pg_file: &Path) -> String {
    format!(
        "name: platform\nversion: \"1\"\ntenant: acme\nsettings:\n  modules: \"{modules}\"\n  pg_settings: {}\n",
        pg_file.display()
    )
}


fn prepared(modules: &str) -> Result<(TempDir, ApiConfig, Parts), TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir)?;
    seed_accounts(&config)?;
    let pg_file = dir.path().join("pg.yaml");
    fs::write(&pg_file, PG_TEXT)?;
    let module_file = dir.path().join("platform.yaml");
    fs::write(&module_file, module_text(modules, &pg_file))?;
    let selected: Vec<Module> = modules_of(&core_config::load::load_module(&module_file)?.settings)?;
    let (opened, _pg) = alerts::settings::open_pg_engine_as(&module_file, new_listener(), ACTOR)?;
    let engine = Arc::new(opened);
    let parts = module_parts(&selected, &engine, &shared_permits())?;
    Ok((dir, config, parts))
}


pub fn parts_of(modules: &str) -> Result<(TempDir, Parts), TestError> {
    let (dir, _config, parts) = prepared(modules)?;
    Ok((dir, parts))
}


pub fn fixture(modules: &str) -> Result<Fixture, TestError> {
    let (dir, config, (extra, access, documents)) = prepared(modules)?;
    let state: SharedState = Arc::new(build_state_from_files(&config, access, documents)?);
    let router = build_router(state, extra);
    Ok(Fixture { _dir: dir, router })
}


pub async fn call(router: &Router, method: &str, path: &str, token: Option<&str>, body: Body) -> Result<Response<Body>, TestError> {
    let mut builder = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(value) = token {
        builder = builder.header("authorization", format!("Bearer {value}"));
    }
    let mut request = builder.body(body)?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), CLIENT_PORT)));
    Ok(router.clone().oneshot(request).await?)
}


pub async fn body_json(response: Response<Body>) -> Result<serde_json::Value, TestError> {
    let bytes = to_bytes(response.into_body(), BODY_READ_LIMIT).await?;
    Ok(serde_json::from_slice(&bytes)?)
}


pub async fn login(router: &Router, user: &str) -> Result<String, TestError> {
    let body = Body::from(serde_json::json!({ "username": user, "password": PASSWORD }).to_string());
    let json = body_json(call(router, "POST", "/auth/login", None, body).await?).await?;
    Ok(json.get("token").and_then(serde_json::Value::as_str).ok_or("no token")?.to_owned())
}
