mod types;


use alerts::backend::MAX_CONNECTIONS;
use alerts::error::StoreError as LeaseError;
use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use core_pg::settings::{open_settings, PgSettings};
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, int8_cell, Fake, Mode, Reply, INT8_OID, TEXT_OID};
use pg_fake::types::Handler;
use rcgen::SanType;
use status_page::api_model::{PageServices, StatusBackend};
use status_page::backend::{now_seconds, pg_backend};
use status_page::error::StoreError;
use status_page::store::{CREATE_SQL, RESOLVE_SQL, UPDATE_SQL};
use status_page::store_model::{IncidentRef, NewIncident};
use std::collections::BTreeSet;
use std::error::Error;
use std::io::sink;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::{Notify, Semaphore};
use types::{Outcomes, TestResult, DEADLINE_RESOLVE};


const DRAIN_LIMIT: usize = 100;


const STATEMENT_TIMEOUT_SECS: u64 = 5;


const BOOL_OID: i32 = 16;


const ID: i64 = 42;


const VERSION: i64 = 3;


const AT: i64 = 1_700_000_000;


const TENANT: &str = "acme";


const SERVICE: &str = "svc-web";


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub _dir: TempDir,
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
        module: "status-page".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served { engine, fake, _dir: dir })
}


pub fn page() -> Arc<PageServices> {
    Arc::new(PageServices {
        tenant: TENANT.to_owned(),
        services: BTreeSet::from([SERVICE.to_owned()]),
    })
}


pub fn backend_of(served: &Served, permits: &Arc<Semaphore>) -> StatusBackend {
    pg_backend(Arc::clone(&served.engine), Arc::clone(permits), page())
}


pub fn drain(receiver: &mut UnboundedReceiver<String>) -> Vec<String> {
    std::iter::repeat_with(|| receiver.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


pub fn pair_reply(parameters: Vec<i32>) -> Reply {
    Reply::Typed {
        parameters,
        columns: vec![INT8_OID, INT8_OID],
        rows: vec![vec![int8_cell(ID), int8_cell(VERSION)]],
    }
}


pub fn all_replies() -> Handler {
    Arc::new(|sql| {
        if sql == CREATE_SQL {
            pair_reply(vec![TEXT_OID, TEXT_OID, TEXT_OID, BOOL_OID, INT8_OID, TEXT_OID])
        } else if sql == UPDATE_SQL {
            pair_reply(vec![TEXT_OID, INT8_OID, INT8_OID, INT8_OID, TEXT_OID, TEXT_OID, INT8_OID])
        } else if sql == RESOLVE_SQL {
            pair_reply(vec![TEXT_OID, INT8_OID, INT8_OID, INT8_OID])
        } else {
            Reply::Done
        }
    })
}


pub fn failing(reply: fn() -> Reply) -> Handler {
    Arc::new(move |sql| {
        if sql == CREATE_SQL || sql == UPDATE_SQL || sql == RESOLVE_SQL {
            reply()
        } else {
            Reply::Done
        }
    })
}


pub fn pausing(arrived: Arc<Notify>) -> Handler {
    Arc::new(move |sql| {
        if sql == CREATE_SQL || sql == UPDATE_SQL || sql == RESOLVE_SQL {
            tokio::time::pause();
            arrived.notify_one();
            Reply::Hang
        } else {
            Reply::Done
        }
    })
}


pub fn incident() -> NewIncident {
    NewIncident {
        service: SERVICE.to_owned(),
        title: "Down".to_owned(),
        published: true,
        started_at: AT,
        internal_note: "note".to_owned(),
    }
}


pub fn reference() -> IncidentRef {
    IncidentRef { id: ID, version: VERSION }
}


pub async fn run_all(backend: &StatusBackend) -> Result<Outcomes, Box<dyn Error>> {
    let scope = tenant_scope(TENANT)?;
    Ok([
        (backend.create)(scope.clone(), incident()).await,
        (backend.update)(scope.clone(), reference(), AT, "msg".to_owned(), "private".to_owned()).await,
        (backend.resolve)(scope, reference(), AT).await,
    ])
}


#[tokio::test]
async fn the_three_writes_bind_the_tenant_first_and_return_the_permit() -> TestResult {
    let mut served = served(all_replies()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = backend_of(&served, &permits);
    let outcomes = run_all(&backend).await?;
    assert!(
        outcomes.iter().all(|outcome| matches!(outcome, Ok(found) if *found == reference())),
        "{outcomes:?}"
    );
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert_eq!(
        bound,
        vec![
            format!("PARAMS acme|{SERVICE}|Down|oid16:01|{AT}|note"),
            format!("PARAMS acme|{ID}|{VERSION}|{AT}|msg|private|100"),
            format!("PARAMS acme|{ID}|{VERSION}|{AT}"),
        ]
    );
    assert!((now_seconds() > 0) && ((backend.clock)() > 0));
    Ok(())
}


#[tokio::test]
async fn another_tenant_scope_binds_another_tenant() -> TestResult {
    let mut served = served(all_replies()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = backend_of(&served, &permits);
    (backend.resolve)(tenant_scope("globex")?, reference(), AT).await?;
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert_eq!(bound, vec![format!("PARAMS globex|{ID}|{VERSION}|{AT}")]);
    Ok(())
}


#[tokio::test]
async fn a_server_error_is_reduced_and_returns_the_permit() -> TestResult {
    let served = served(failing(|| Reply::Error("42601"))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let outcomes = run_all(&backend_of(&served, &permits)).await?;
    assert!(
        outcomes
            .iter()
            .all(|outcome| matches!(outcome, Err(StoreError::Pg(PgError::Server { .. })))),
        "{outcomes:?}"
    );
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_dropped_connection_fails_and_returns_the_permit() -> TestResult {
    let served = served(failing(|| Reply::Drop)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let outcomes = run_all(&backend_of(&served, &permits)).await?;
    assert!(outcomes.iter().all(|outcome| matches!(outcome, Err(StoreError::Pg(_)))), "{outcomes:?}");
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


pub async fn hung(which: usize) -> Result<(Outcomes, usize), Box<dyn Error>> {
    let served = served(pausing(Arc::new(Notify::new()))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = backend_of(&served, &permits);
    let scope = tenant_scope(TENANT)?;
    let outcome = match which {
        0 => (backend.create)(scope, incident()).await,
        1 => (backend.update)(scope, reference(), AT, "msg".to_owned(), "private".to_owned()).await,
        _ => (backend.resolve)(scope, reference(), AT).await,
    };
    Ok(([outcome, Ok(reference()), Ok(reference())], permits.available_permits()))
}


pub async fn deadline_of(which: usize) -> TestResult {
    let (outcomes, permits) = hung(which).await?;
    let deadline = matches!(
        outcomes.first(),
        Some(Err(StoreError::Pg(PgError::StatementTimeout {
            seconds: STATEMENT_TIMEOUT_SECS
        })))
    );
    assert!(deadline, "{which}: {outcomes:?}");
    assert_eq!(permits, MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_create_that_hangs_hits_the_settings_deadline() -> TestResult {
    deadline_of(0).await
}


#[tokio::test]
async fn an_update_that_hangs_hits_the_settings_deadline() -> TestResult {
    deadline_of(1).await
}


#[tokio::test]
async fn a_resolve_that_hangs_hits_the_settings_deadline() -> TestResult {
    deadline_of(DEADLINE_RESOLVE).await
}


#[tokio::test]
async fn a_cancelled_write_returns_the_permit_at_once() -> TestResult {
    let arrived = Arc::new(Notify::new());
    let served = served(pausing(Arc::clone(&arrived))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = backend_of(&served, &permits);
    let pending = (backend.create)(tenant_scope(TENANT)?, incident());
    let finished_early = tokio::select! {
        _outcome = pending => true,
        () = arrived.notified() => false,
    };
    assert!(!finished_early);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn an_empty_pool_is_busy_before_any_connection() -> TestResult {
    let mut served = served(all_replies()).await?;
    let backend = backend_of(&served, &Arc::new(Semaphore::new(0)));
    let outcomes = run_all(&backend).await?;
    assert!(
        outcomes.iter().all(|outcome| matches!(outcome, Err(StoreError::Lease(LeaseError::Busy)))),
        "{outcomes:?}"
    );
    assert!(drain(&mut served.fake.statements).is_empty());
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
