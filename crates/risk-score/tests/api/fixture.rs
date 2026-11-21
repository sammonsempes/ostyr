use crate::types::TestError;
use axum::Router;
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::model::{ApiConfig, Limits};
use core_api::routes::build_router;
use core_api::state::{build_state_from_files, MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_WINDOW_SECONDS};
use core_api::types::SharedState;
use core_audit::log::{append, genesis_log};
use core_auth::model::Account;
use core_auth::password::hash_password;
use core_auth::random::os_random;
use core_auth::store::update_store_file;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use risk_score::api::{risk_access, risk_document, risk_router};
use risk_score::api_model::RiskState;
use risk_score::cache::risk_state;
use risk_score::error::RiskError;
use risk_score::model::{EntityKind, EntityRef, Score, Weights};
use risk_score::source::Outcome;
use risk_score::types::{ComputeFn, NowFn};
use risk_score::weights::{weights_loader, weights_state};
use std::collections::BTreeMap;
use std::fs;
use std::io::sink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::Semaphore;


pub const PASSWORD: &str = "correct horse battery staple";


pub const READER: &str = "reader";


pub const ANALYST: &str = "analyst";


pub const TENANT: &str = "acme";


pub const OTHER_TENANT: &str = "globex";


pub const MARKER: &str = "STORE-SECRET-MARKER";


#[cfg(unix)]
pub const OWNER_ONLY: u32 = 0o600;


pub const KEY_BYTES: usize = 32;


pub const KEY_FILL: u8 = 7;


pub const TEST_TIMEOUT: Duration = Duration::from_millis(300);


pub const TEST_MAX_CONNECTIONS: usize = 2;


pub const OPEN_RATE: u32 = 100_000;


pub const FIRST_NOW: i64 = 1_800_000_000;


pub const FULL_POINTS: u32 = 100;


pub const SWAPPED_POINTS: u32 = 50;


pub const WEIGHTS_TEXT: &str = "severity_points: {low: 1, medium: 5, high: 10, critical: 20}\nrare_threshold_per_million: 1000\n\
entity_rare_bonus_permille: 500\nfleet_rare_bonus_permille: 500\nfull_score_points: 100\n";


pub const SWAPPED_TEXT: &str = "severity_points: {low: 1, medium: 5, high: 10, critical: 20}\nrare_threshold_per_million: 1000\n\
entity_rare_bonus_permille: 500\nfleet_rare_bonus_permille: 500\nfull_score_points: 50\n";


pub const OUT_OF_RANGE_TEXT: &str = "severity_points: {low: 1, medium: 5, high: 10, critical: 20}\nrare_threshold_per_million: 1000\n\
entity_rare_bonus_permille: 500\nfleet_rare_bonus_permille: 500\nfull_score_points: 0\n";


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Answer,
    Fail,
    Hang,
    Gated,
    GatedFail,
}


pub struct Script {
    pub calls: AtomicUsize,
    pub tenants: Mutex<Vec<String>>,
    pub weights_seen: Mutex<Vec<u32>>,
    pub outcomes: Mutex<BTreeMap<String, Outcome>>,
    pub mode: Mutex<Mode>,
    pub gate: Semaphore,
    pub entered: Semaphore,
}


pub struct Fixture {
    pub _dir: TempDir,
    pub router: Router,
    pub risk: RiskState,
    pub script: Arc<Script>,
    pub engine: Arc<ReloadEngine<Weights>>,
    pub weights_file: PathBuf,
}


pub fn lock<Guarded>(mutex: &Mutex<Guarded>) -> MutexGuard<'_, Guarded> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn score(kind: EntityKind, id: &str, value: u8) -> Score {
    Score {
        entity: EntityRef { kind, id: id.to_owned() },
        value,
        contributions_used: 1,
        contributions_dropped: 0,
    }
}


pub fn outcome_of(scores: Vec<Score>) -> Outcome {
    Outcome {
        scores,
        alerts_read: 0,
        informational: 0,
        refused: BTreeMap::new(),
        truncated: None,
        fp_rules: Vec::new(),
        fp_rules_omitted: 0,
        unknown_verdicts: 0,
    }
}


pub fn new_script() -> Arc<Script> {
    Arc::new(Script {
        calls: AtomicUsize::new(0),
        tenants: Mutex::new(Vec::new()),
        weights_seen: Mutex::new(Vec::new()),
        outcomes: Mutex::new(BTreeMap::new()),
        mode: Mutex::new(Mode::Answer),
        gate: Semaphore::new(0),
        entered: Semaphore::new(0),
    })
}


pub fn set_outcome(script: &Script, tenant: &str, outcome: Outcome) {
    lock(&script.outcomes).insert(tenant.to_owned(), outcome);
}


pub fn set_mode(script: &Script, mode: Mode) {
    *lock(&script.mode) = mode;
}


pub fn calls(script: &Script) -> usize {
    script.calls.load(Ordering::SeqCst)
}


pub async fn run(script: Arc<Script>, scope: TenantScope, weights: Arc<Weights>) -> Result<Outcome, RiskError> {
    script.calls.fetch_add(1, Ordering::SeqCst);
    lock(&script.tenants).push(tenant_of(&scope).to_owned());
    lock(&script.weights_seen).push(weights.full_score_points);
    script.entered.add_permits(1);
    let mode = *lock(&script.mode);
    match mode {
        Mode::Hang => std::future::pending::<()>().await,
        Mode::Gated | Mode::GatedFail => {
            if let Ok(permit) = script.gate.acquire().await {
                permit.forget();
            }
        }
        Mode::Answer | Mode::Fail => {}
    }
    let found = lock(&script.outcomes).get(tenant_of(&scope)).cloned();
    match (mode, found) {
        (Mode::Fail | Mode::GatedFail, _) => Err(RiskError::OutOfRange { key: MARKER }),
        (_, Some(answer)) => Ok(answer),
        (_, None) => Ok(outcome_of(Vec::new())),
    }
}


pub fn compute_fn(script: &Arc<Script>) -> ComputeFn {
    let held = Arc::clone(script);
    Arc::new(move |scope, weights, _now| Box::pin(run(Arc::clone(&held), scope, weights)))
}


/// Every computation reads a clock that moves by one second, so two computations never share a `computed_at`.
pub fn ticking_clock() -> NowFn {
    let counter = Arc::new(AtomicI64::new(FIRST_NOW));
    Arc::new(move || counter.fetch_add(1, Ordering::SeqCst))
}


pub fn weights_engine(dir: &TempDir) -> Result<(Arc<ReloadEngine<Weights>>, PathBuf), TestError> {
    let weights_file = dir.path().join("weights.yaml");
    fs::write(&weights_file, WEIGHTS_TEXT)?;
    let log = genesis_log(sink());
    let context = ReloadContext {
        actor_id: "test".to_owned(),
        tenant: TENANT.to_owned(),
        module: "risk".to_owned(),
        target: weights_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = open_engine(
        weights_loader(weights_file.clone()),
        weights_state,
        Vec::new(),
        Box::new(move |entry| append(&log, entry)),
        context,
    )?;
    Ok((Arc::new(engine), weights_file))
}


pub fn scope(tenant: &str) -> Result<TenantScope, TestError> {
    Ok(tenant_scope(tenant)?)
}


pub fn config_in(dir: &TempDir) -> Result<ApiConfig, TestError> {
    let key_file = dir.path().join("store.key");
    fs::write(&key_file, [KEY_FILL; KEY_BYTES])?;
    restrict(&key_file)?;
    let compromised_list = dir.path().join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    Ok(ApiConfig {
        module: "risk".to_owned(),
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


pub fn state_with(script: &Arc<Script>, engine: &Arc<ReloadEngine<Weights>>) -> RiskState {
    risk_state(compute_fn(script), Arc::clone(engine), ticking_clock())
}


pub fn fixture_with(adjust: fn(RiskState) -> RiskState) -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir)?;
    seed_accounts(&config)?;
    let script = new_script();
    let (engine, weights_file) = weights_engine(&dir)?;
    let risk = adjust(state_with(&script, &engine));
    let state: SharedState = Arc::new(build_state_from_files(&config, risk_access(), vec![risk_document()])?);
    let router = build_router(state.clone(), risk_router(risk.clone()));
    Ok(Fixture {
        _dir: dir,
        router,
        risk,
        script,
        engine,
        weights_file,
    })
}


pub fn fixture() -> Result<Fixture, TestError> {
    fixture_with(std::convert::identity)
}
