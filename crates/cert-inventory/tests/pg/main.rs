use alerts::backend::MAX_CONNECTIONS;
use alerts::error::StoreError as LeaseError;
use cert_inventory::api::{list_flow, request_of};
use cert_inventory::api_model::{CertBackend, ListQuery};
use cert_inventory::backend::{now_seconds, pg_backend};
use cert_inventory::error::InventoryStoreError;
use cert_inventory::model::{CertFilter, ListRequest};
use core_api::model::ApiIdentity;
use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use core_pg::settings::{open_settings, PgSettings};
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use std::error::Error;
use std::io::sink;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::{Notify, Semaphore};


const DRAIN_LIMIT: usize = 100;


const FINGERPRINT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";


const NOT_AFTER: &str = "2000000000";


const PAGE: usize = 10;


const BOUND_STATEMENTS: usize = 3;


const STATEMENT_TIMEOUT_SECS: u64 = 5;


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub _dir: TempDir,
}


pub fn cert_row() -> Vec<String> {
    [
        FINGERPRINT,
        "CN=a",
        "CN=ca",
        "[\"a.example\"]",
        "1",
        NOT_AFTER,
        "rsa",
        "2048",
        "false",
        "1",
        "2",
    ]
    .map(str::to_owned)
    .to_vec()
}


pub fn cert_handler() -> Handler {
    Arc::new(|sql| {
        if sql.contains("FROM cert_sightings") {
            Reply::Rows(vec![["scan", "host:/etc/a.pem", "3"].map(str::to_owned).to_vec()])
        } else if sql.contains("FROM cert_inventory") {
            Reply::Rows(vec![cert_row()])
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
        tenant: "acme".to_owned(),
        module: "cert-inventory".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served { engine, fake, _dir: dir })
}


pub fn first_page() -> ListRequest {
    ListRequest {
        filter: CertFilter::default(),
        cursor: None,
        limit: PAGE,
    }
}


pub async fn list_and_get(backend: &CertBackend) -> (Result<usize, InventoryStoreError>, Result<bool, InventoryStoreError>) {
    let scope = tenant_scope("acme").ok();
    let listed = match scope.clone() {
        Some(held) => (backend.list)(held, first_page()).await.map(|page| page.certs.len()),
        None => Err(InventoryStoreError::BadNow),
    };
    let found = match scope {
        Some(held) => (backend.get)(held, FINGERPRINT.to_owned()).await.map(|detail| detail.is_some()),
        None => Err(InventoryStoreError::BadNow),
    };
    (listed, found)
}


#[tokio::test]
async fn the_backend_lists_and_gets_scoped_to_the_tenant_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let mut served = served(cert_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let scope = tenant_scope("acme")?;
    let page = (backend.list)(scope.clone(), first_page()).await?;
    assert_eq!((page.certs.len(), page.skipped), (1, 0));
    let detail = (backend.get)(scope, FINGERPRINT.to_owned()).await?.ok_or("no detail")?;
    assert_eq!(detail.sightings.sightings.len(), 1);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert_eq!(bound.len(), BOUND_STATEMENTS, "{bound:?}");
    assert!(bound.iter().all(|entry| entry.starts_with("PARAMS acme|")), "{bound:?}");
    assert!(
        bound.iter().any(|entry| entry == &format!("PARAMS acme|{}|{}", i64::MAX, PAGE + 1)),
        "{bound:?}"
    );
    assert!(bound.iter().any(|entry| entry == &format!("PARAMS acme|{FINGERPRINT}")), "{bound:?}");
    assert!((now_seconds() > 0) && ((backend.clock)() > 0));
    Ok(())
}


#[tokio::test]
async fn a_store_error_is_reduced_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(failing_handler(|| Reply::Error("42601"))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let (listed, found) = list_and_get(&backend).await;
    assert!(matches!(listed, Err(InventoryStoreError::Pg(PgError::Server { .. }))));
    assert!(matches!(found, Err(InventoryStoreError::Pg(PgError::Server { .. }))));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_dropped_connection_fails_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(failing_handler(|| Reply::Drop)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let (listed, found) = list_and_get(&backend).await;
    assert!(matches!(listed, Err(InventoryStoreError::Pg(_))), "{listed:?}");
    assert!(matches!(found, Err(InventoryStoreError::Pg(_))), "{found:?}");
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


pub fn pausing_handler(arrived: Arc<Notify>) -> Handler {
    Arc::new(move |sql| {
        if sql.contains("FROM cert_inventory") {
            tokio::time::pause();
            arrived.notify_one();
            Reply::Hang
        } else {
            Reply::Done
        }
    })
}


pub fn deadline_expired<Found>(outcome: &Result<Found, InventoryStoreError>) -> bool {
    matches!(
        outcome,
        Err(InventoryStoreError::Pg(PgError::ClientDeadline {
            seconds: STATEMENT_TIMEOUT_SECS
        }))
    )
}


#[tokio::test]
async fn a_list_that_hangs_hits_the_deadline_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(pausing_handler(Arc::new(Notify::new()))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let outcome = (backend.list)(tenant_scope("acme")?, first_page()).await;
    assert!(deadline_expired(&outcome));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_get_that_hangs_hits_the_deadline_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(pausing_handler(Arc::new(Notify::new()))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let outcome = (backend.get)(tenant_scope("acme")?, FINGERPRINT.to_owned()).await;
    assert!(deadline_expired(&outcome));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_dropped_list_future_returns_the_permit_at_once() -> Result<(), Box<dyn Error>> {
    let arrived = Arc::new(Notify::new());
    let served = served(pausing_handler(Arc::clone(&arrived))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let pending = (backend.list)(tenant_scope("acme")?, first_page());
    let finished_early = tokio::select! {
        _outcome = pending => true,
        () = arrived.notified() => false,
    };
    assert!(!finished_early);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn an_empty_pool_is_busy_before_any_connection() -> Result<(), Box<dyn Error>> {
    let served = served(cert_handler()).await?;
    let permits = Arc::new(Semaphore::new(0));
    let backend = pg_backend(Arc::clone(&served.engine), permits);
    let (listed, found) = list_and_get(&backend).await;
    assert!(matches!(listed, Err(InventoryStoreError::Lease(LeaseError::Busy))));
    assert!(matches!(found, Err(InventoryStoreError::Lease(LeaseError::Busy))));
    Ok(())
}


#[tokio::test]
async fn a_malformed_cursor_never_reaches_the_backend() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let backend = CertBackend {
        list: Arc::new(move |_scope, _request| {
            counted.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(InventoryStoreError::BadNow) })
        }),
        get: Arc::new(|_scope, _fingerprint| Box::pin(async { Ok(None) })),
        clock: now_seconds,
    };
    let identity = ApiIdentity {
        module: "cert-inventory".to_owned(),
        tenant: "acme".to_owned(),
        generation: 0,
    };
    let query = |cursor: &str| ListQuery {
        expiring_before: None,
        cursor: Some(cursor.to_owned()),
        limit: None,
    };
    assert!(matches!(request_of(&query("junk")), Err(InventoryStoreError::BadCursor)));
    let refused = list_flow(&identity, &backend, Ok(query("1:zz"))).await;
    assert!(refused.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let canonical = format!("{NOT_AFTER}:{FINGERPRINT}");
    assert!(request_of(&query(&canonical)).is_ok());
    let reached = list_flow(&identity, &backend, Ok(query(&canonical))).await;
    assert!(reached.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
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
