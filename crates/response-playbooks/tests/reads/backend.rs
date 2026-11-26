use crate::memory::run_id;
use alerts::backend::MAX_CONNECTIONS;
use alerts::error::StoreError as LeaseError;
use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use core_pg::settings::{open_settings, PgSettings};
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use response_playbooks::api_model::{RunPage, RunsBackend};
use response_playbooks::backend::{detached, pg_backend, pool_failure};
use response_playbooks::error::ReadError;
use std::error::Error;
use std::io::sink;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Semaphore;


const DRAIN_LIMIT: usize = 100;


const STATEMENT_TIMEOUT_SECS: u64 = 5;


const SIZE: usize = 10;


const CURSOR: i64 = 9;


const SEQ: i64 = 3;


const BOUND_STATEMENTS: usize = 2;


const TENANT: &str = "acme";


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub _dir: TempDir,
}


pub fn run_handler() -> Handler {
    let id = run_id('a', 1);
    let meta = [id.as_str(), "alert", "pb", "dry_run", "completed", "1", "2", "3"]
        .map(str::to_owned)
        .to_vec();
    let detail: Vec<String> = meta.iter().cloned().chain(["[]".to_owned()]).collect();
    Arc::new(move |sql| {
        if sql.contains(" AND id = ") {
            Reply::Rows(vec![detail.clone()])
        } else if sql.contains("FROM playbook_runs") {
            Reply::Rows(vec![meta.clone()])
        } else {
            Reply::Done
        }
    })
}


pub fn failing_handler(reply: fn() -> Reply) -> Handler {
    Arc::new(move |_sql| reply())
}


pub fn drain(receiver: &mut UnboundedReceiver<String>) -> Vec<String> {
    std::iter::repeat_with(|| receiver.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


pub async fn served(handler: Handler) -> Result<Served, Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), "p", handler).await?;
    let dir = tempdir()?;
    let password_file = dir.path().join("pg.pass");
    let ca_file = dir.path().join("ca.pem");
    write_secret(&password_file, "p")?;
    std::fs::write(&ca_file, &pki.ca_pem)?;
    let settings_text = format!(
        "host: 127.0.0.1\nport: {}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\nstatement_timeout_secs: {STATEMENT_TIMEOUT_SECS}\n",
        fake.port,
        password_file.display(),
        ca_file.display()
    );
    let settings_file = dir.path().join("pg.yaml");
    std::fs::write(&settings_file, settings_text)?;
    let log = genesis_log(sink());
    let context = ReloadContext {
        actor_id: "test".to_owned(),
        tenant: TENANT.to_owned(),
        module: "playbooks".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served { engine, fake, _dir: dir })
}


pub async fn list_and_get(backend: &RunsBackend) -> (Result<usize, ReadError>, Result<bool, ReadError>) {
    let scope = tenant_scope(TENANT).ok();
    let page = RunPage { after: None, size: SIZE };
    let listed = match scope.clone() {
        Some(held) => (backend.list)(held, page).await.map(|list| list.runs.len()),
        None => Err(ReadError::BadRow),
    };
    let found = match scope {
        Some(held) => (backend.get)(held, run_id('a', 1)).await.map(|run| run.is_some()),
        None => Err(ReadError::BadRow),
    };
    (listed, found)
}


#[tokio::test]
async fn the_backend_lists_and_gets_scoped_to_the_tenant_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let mut served = served(run_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let scope = tenant_scope(TENANT)?;
    let listed = (backend.list)(
        scope.clone(),
        RunPage {
            after: Some(CURSOR),
            size: SIZE,
        },
    )
    .await?;
    assert_eq!(listed.runs.len(), 1);
    let found = (backend.get)(scope, run_id('a', 1)).await?.ok_or("no run")?;
    assert_eq!(found.meta.seq, SEQ);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert_eq!(bound.len(), BOUND_STATEMENTS, "{bound:?}");
    assert!(bound.iter().all(|entry| entry.starts_with("PARAMS acme|")), "{bound:?}");
    assert!(
        bound.iter().any(|entry| entry == &format!("PARAMS acme|{CURSOR}|{}", SIZE + 1)),
        "{bound:?}"
    );
    assert!(bound.iter().any(|entry| entry == &format!("PARAMS acme|{}", run_id('a', 1))), "{bound:?}");
    Ok(())
}


#[tokio::test]
async fn a_store_error_is_reduced_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(failing_handler(|| Reply::Error("42601"))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let (listed, found) = list_and_get(&backend).await;
    assert!(matches!(listed, Err(ReadError::Pg(PgError::Server { .. }))), "{listed:?}");
    assert!(matches!(found, Err(ReadError::Pg(PgError::Server { .. }))), "{found:?}");
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_dropped_connection_fails_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(failing_handler(|| Reply::Drop)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let (listed, found) = list_and_get(&backend).await;
    assert!(matches!(listed, Err(ReadError::Pg(_))), "{listed:?}");
    assert!(matches!(found, Err(ReadError::Pg(_))), "{found:?}");
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn an_empty_pool_is_busy_before_any_connection() -> Result<(), Box<dyn Error>> {
    let served = served(run_handler()).await?;
    let backend = pg_backend(Arc::clone(&served.engine), Arc::new(Semaphore::new(0)));
    let (listed, found) = list_and_get(&backend).await;
    assert!(matches!(listed, Err(ReadError::Busy)), "{listed:?}");
    assert!(matches!(found, Err(ReadError::Busy)), "{found:?}");
    Ok(())
}


fn exploding() -> Result<u8, ReadError> {
    std::panic::resume_unwind(Box::new("boom"))
}


#[tokio::test]
async fn a_panicking_read_is_a_fixed_task_failure() -> Result<(), Box<dyn Error>> {
    let outcome = detached(async { exploding() }).await;
    assert!(matches!(outcome, Err(ReadError::TaskFailed)), "{outcome:?}");
    Ok(())
}


#[test]
fn a_lease_failure_is_reduced_to_a_fixed_read_error() -> Result<(), Box<dyn Error>> {
    assert!(matches!(pool_failure(LeaseError::Busy), ReadError::Busy));
    assert!(matches!(pool_failure(LeaseError::BadId), ReadError::BadRow));
    assert!(matches!(
        pool_failure(LeaseError::Pg(PgError::Server {
            code: "42601".to_owned(),
            class: "syntax"
        })),
        ReadError::Pg(_)
    ));
    Ok(())
}


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


#[cfg(unix)]
fn write_secret(path: impl AsRef<std::path::Path>, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path.as_ref(), content)?;
    std::fs::set_permissions(path.as_ref(), std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))
}


#[cfg(not(unix))]
fn write_secret(path: impl AsRef<std::path::Path>, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path.as_ref(), content)
}
