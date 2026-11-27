use crate::types::TestError;
use axum::Router;
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::model::{ApiConfig, Limits};
use core_api::routes::build_router;
use core_api::state::{build_state_from_files, MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_WINDOW_SECONDS};
use core_api::types::SharedState;
use core_auth::model::Account;
use core_auth::password::hash_password;
use core_auth::random::os_random;
use core_auth::store::update_store_file;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use hunt_packs::api::{hunts_access, hunts_document, hunts_router, permit_backend, read_findings};
use hunt_packs::store::{FindingRow, Param, LIST_SQL, OVERSIZED_SQL};
use hunt_packs::types::{FindingsFn, ListResult};
use std::fs;
use std::future::{ready, Ready};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::Semaphore;


pub const PASSWORD: &str = "correct horse battery staple";


pub const READER: &str = "reader";


pub const NOBODY: &str = "nobody";


pub const TENANT: &str = "acme";


pub const OTHER_TENANT: &str = "globex";


#[cfg(unix)]
pub const OWNER_ONLY: u32 = 0o600;


pub const KEY_BYTES: usize = 32;


pub const KEY_FILL: u8 = 7;


pub const TEST_TIMEOUT: Duration = Duration::from_millis(300);


pub const TEST_MAX_CONNECTIONS: usize = 2;


pub const OPEN_RATE: u32 = 100_000;


pub const PERMITS: usize = 8;


pub const MARKER: &str = "SECRET-MARKER-7f3a";


pub const BYTE_CAP: usize = 64;


pub const WINDOW_SECONDS: i64 = 3_600;


pub const MATCHES: i64 = 3;


const LIMIT_INDEX: usize = 2;


#[derive(Default)]
pub struct Db {
    pub rows: Mutex<Vec<(String, FindingRow)>>,
    pub tenants_seen: Mutex<Vec<String>>,
    pub fail_list: Mutex<bool>,
    pub empty_count: Mutex<bool>,
}


pub struct Fixture {
    pub _dir: TempDir,
    pub router: Router,
    pub db: Arc<Db>,
    pub permits: Arc<Semaphore>,
}


pub fn lock<Value>(mutex: &Mutex<Value>) -> MutexGuard<'_, Value> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn finding(pack_id: &str, window_end: i64) -> FindingRow {
    FindingRow {
        pack_id: pack_id.to_owned(),
        window_start: window_end - WINDOW_SECONDS,
        window_end,
        matches: MATCHES,
        max_matches: 1,
    }
}


pub fn put(db: &Db, tenant: &str, row: FindingRow) {
    lock(&db.rows).push((tenant.to_owned(), row));
}


pub fn marker_error() -> PgError {
    PgError::Io {
        file: MARKER.to_owned(),
        source: std::io::Error::other(MARKER),
    }
}


fn int_at(params: &[Param], index: usize) -> i64 {
    match params.get(index) {
        Some(Param::Int(value)) => *value,
        _ => 0,
    }
}


fn text_at(params: &[Param], index: usize) -> String {
    match params.get(index) {
        Some(Param::Text(value)) => value.clone(),
        _ => String::new(),
    }
}


pub fn list_rows(db: &Db, scope: &TenantScope, sql: &'static str, params: &[Param]) -> ListResult {
    lock(&db.tenants_seen).push(tenant_of(scope).to_owned());
    let broken = sql != LIST_SQL || *lock(&db.fail_list);
    let after = (int_at(params, 0), text_at(params, 1));
    let limit = usize::try_from(int_at(params, LIMIT_INDEX)).unwrap_or(0);
    let mut found: Vec<FindingRow> = lock(&db.rows)
        .iter()
        .filter(|(tenant, row)| tenant == tenant_of(scope) && row.pack_id.len() <= BYTE_CAP && (row.window_end, row.pack_id.clone()) > after)
        .map(|(_tenant, row)| row.clone())
        .collect();
    found.sort_by(|left, right| (left.window_end, &left.pack_id).cmp(&(right.window_end, &right.pack_id)));
    found.truncate(limit);
    if broken {
        Err(marker_error())
    } else {
        Ok(found)
    }
}


pub fn count_rows(db: &Db, scope: &TenantScope, sql: &'static str, _params: &[Param]) -> Result<Vec<i64>, PgError> {
    lock(&db.tenants_seen).push(tenant_of(scope).to_owned());
    let count = lock(&db.rows)
        .iter()
        .filter(|(tenant, row)| tenant == tenant_of(scope) && row.pack_id.len() > BYTE_CAP)
        .count();
    if sql != OVERSIZED_SQL {
        Err(marker_error())
    } else if *lock(&db.empty_count) {
        Ok(Vec::new())
    } else {
        Ok(vec![i64::try_from(count).unwrap_or(i64::MAX)])
    }
}


pub fn list_exec(db: &Arc<Db>) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<ListResult> {
    let held = Arc::clone(db);
    move |scope, sql, params| ready(list_rows(&held, scope, sql, &params))
}


pub fn count_exec(db: &Arc<Db>) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<Result<Vec<i64>, PgError>> {
    let held = Arc::clone(db);
    move |scope, sql, params| ready(count_rows(&held, scope, sql, &params))
}


pub fn memory_backend(db: &Arc<Db>) -> FindingsFn {
    let held = Arc::clone(db);
    Arc::new(move |scope, query| {
        let source = Arc::clone(&held);
        Box::pin(async move { read_findings(&mut list_exec(&source), &mut count_exec(&source), &scope, &query).await })
    })
}


pub fn config_in(dir: &TempDir) -> Result<ApiConfig, TestError> {
    let key_file = dir.path().join("store.key");
    private_file(&key_file, &[KEY_FILL; KEY_BYTES])?;
    let compromised_list = dir.path().join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    Ok(ApiConfig {
        module: "hunts".to_owned(),
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
pub fn private_file(path: &std::path::Path, content: &[u8]) -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, content)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


#[cfg(not(unix))]
pub fn private_file(path: &std::path::Path, content: &[u8]) -> Result<(), TestError> {
    fs::write(path, content)?;
    Ok(())
}


pub fn seed_accounts(config: &ApiConfig) -> Result<(), TestError> {
    [READER, NOBODY].into_iter().try_for_each(|name| -> Result<(), TestError> {
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


pub fn fixture_with(permits: usize, backend: impl FnOnce(&Arc<Db>) -> FindingsFn) -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir)?;
    seed_accounts(&config)?;
    let db = Arc::new(Db::default());
    let semaphore = Arc::new(Semaphore::new(permits));
    let built = build_state_from_files(&config, hunts_access(), vec![hunts_document()])?;
    let mut catalog = (*built.catalog.load_full()).clone();
    catalog.entry(NOBODY.to_owned()).or_default();
    built.catalog.store(Arc::new(catalog));
    let state: SharedState = Arc::new(built);
    let router = build_router(state, hunts_router(permit_backend(Arc::clone(&semaphore), backend(&db))));
    Ok(Fixture {
        _dir: dir,
        router,
        db,
        permits: semaphore,
    })
}


pub fn fixture() -> Result<Fixture, TestError> {
    fixture_with(PERMITS, memory_backend)
}
