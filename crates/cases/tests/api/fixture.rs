use crate::memory::{handle, Db};
use crate::types::TestError;
use alerts::types::RowFuture;
use axum::Router;
use cases::api::{cases_access, cases_document, cases_router};
use cases::api_model::CasesBackend;
use cases::model::{Case, CaseStatus, Severity, Task, TaskStatus};
use cases::store::{add_comment, attach_alert, create_case, list_links};
use cases::summary::{get_case_detail, list_case_summaries};
use cases::write::act_on_case;
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
use std::fs;
use std::future::ready;
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


pub const BASE_TIME: i64 = 1_700_000_000;


pub const OPEN_RATE: u32 = 100_000;


pub struct Fixture {
    pub _dir: TempDir,
    pub state: SharedState,
    pub router: Router,
    pub db: Arc<Db>,
}


pub fn executor<'a>(db: &'a Db) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(handle(db, &scope, sql, &params))) }
}


pub const NOW: i64 = 1_800_000_000;


pub fn fixed_clock() -> i64 {
    NOW
}


pub fn memory_backend(db: &Arc<Db>) -> CasesBackend {
    let list_db = Arc::clone(db);
    let get_db = Arc::clone(db);
    let act_db = Arc::clone(db);
    let comment_db = Arc::clone(db);
    let link_db = Arc::clone(db);
    let links_db = Arc::clone(db);
    CasesBackend {
        list: Arc::new(move |scope, page| {
            let held = Arc::clone(&list_db);
            Box::pin(async move { list_case_summaries(&executor(&held), &scope, &page).await })
        }),
        get: Arc::new(move |scope, id| {
            let held = Arc::clone(&get_db);
            Box::pin(async move { get_case_detail(&executor(&held), &scope, &id).await })
        }),
        act: Arc::new(move |scope, id, action, actor, now| {
            let held = Arc::clone(&act_db);
            Box::pin(async move { act_on_case(&executor(&held), &scope, &id, action, &actor, now).await })
        }),
        comment: Arc::new(move |scope, id, comment| {
            let held = Arc::clone(&comment_db);
            Box::pin(async move { add_comment(&executor(&held), &scope, &id, &comment).await })
        }),
        link: Arc::new(move |scope, id, alert_id, actor, now| {
            let held = Arc::clone(&link_db);
            Box::pin(async move { attach_alert(&executor(&held), &scope, &id, &alert_id, (&actor, now)).await })
        }),
        links: Arc::new(move |scope, id, page| {
            let held = Arc::clone(&links_db);
            Box::pin(async move { list_links(&executor(&held), &scope, &id, &page).await })
        }),
        clock: fixed_clock,
    }
}


pub fn case(tenant: &str, id: &str, created: i64) -> Case {
    Case {
        id: id.to_owned(),
        tenant: tenant.to_owned(),
        title: format!("Case {id}"),
        description: Some("details".to_owned()),
        severity: Severity::High,
        status: CaseStatus::New,
        resolution: None,
        assignee: Some("alice".to_owned()),
        template: Some("incident".to_owned()),
        case_type: Some("malware".to_owned()),
        created_at: created,
        updated_at: created,
        tasks: vec![Task {
            title: "triage".to_owned(),
            status: TaskStatus::Todo,
            due: None,
            log: Vec::new(),
        }],
        observables: Vec::new(),
        comments: Vec::new(),
        history: Vec::new(),
    }
}


pub async fn store(db: &Db, cases: &[Case]) -> Result<(), TestError> {
    for stored in cases {
        create_case(&executor(db), &tenant_scope(&stored.tenant)?, stored).await?;
    }
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


pub fn config_in(dir: &TempDir, rate: u32) -> Result<ApiConfig, TestError> {
    let key_file = dir.path().join("store.key");
    private_file(&key_file, &[KEY_FILL; KEY_BYTES])?;
    let compromised_list = dir.path().join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    Ok(ApiConfig {
        module: "cases".to_owned(),
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


pub fn fixture_rated(rate: u32, backend: impl FnOnce(&Arc<Db>) -> CasesBackend) -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir, rate)?;
    seed_accounts(&config)?;
    let db = Arc::new(Db::default());
    let built = build_state_from_files(&config, cases_access(), vec![cases_document()])?;
    let state: SharedState = Arc::new(built);
    let router = build_router(state.clone(), cases_router(backend(&db)));
    Ok(Fixture {
        _dir: dir,
        state,
        router,
        db,
    })
}


pub fn fixture_with(backend: impl FnOnce(&Arc<Db>) -> CasesBackend) -> Result<Fixture, TestError> {
    fixture_rated(RATE_MAX_REQUESTS, backend)
}


pub fn fixture() -> Result<Fixture, TestError> {
    fixture_rated(OPEN_RATE, memory_backend)
}
