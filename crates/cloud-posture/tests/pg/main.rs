use alerts::backend::MAX_CONNECTIONS;
use alerts::error::StoreError as LeaseError;
use cloud_posture::api::read_flow;
use cloud_posture::api_model::{PostureBackend, ReadQuery};
use cloud_posture::backend::pg_backend;
use cloud_posture::error::StoreError;
use cloud_posture::page::ROW_COLUMNS;
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
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Semaphore;


const DRAIN_LIMIT: usize = 100;


const ACCOUNT: &str = "123456789012";


const PAGE: usize = 10;


const CURSOR_HUGE: usize = 10_000;


const STATEMENT_TIMEOUT_SECS: u64 = 5;


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub _dir: TempDir,
}


pub fn page_row() -> Vec<String> {
    let header = ["run-a", "1700000000000000", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "", "0"];
    header
        .iter()
        .map(|text| (*text).to_owned())
        .chain(std::iter::repeat_n(String::new(), ROW_COLUMNS - header.len()))
        .collect()
}


pub fn page_handler() -> Handler {
    Arc::new(|sql| {
        if sql.contains("posture_page") {
            Reply::Rows(vec![page_row()])
        } else {
            Reply::Done
        }
    })
}


pub fn failing_handler(reply: fn() -> Reply) -> Handler {
    Arc::new(move |_sql| reply())
}


pub fn drain<Item>(receiver: &mut UnboundedReceiver<Item>) -> Vec<Item> {
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
        module: "cloud-posture".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served { engine, fake, _dir: dir })
}


pub fn query_of(cursor: Option<&str>, limit: Option<&str>) -> ReadQuery {
    ReadQuery {
        cursor: cursor.map(str::to_owned),
        limit: limit.map(str::to_owned),
    }
}


pub fn identity() -> ApiIdentity {
    ApiIdentity {
        module: "cloud-posture".to_owned(),
        tenant: "acme".to_owned(),
        generation: 0,
    }
}


pub async fn read_once(backend: &PostureBackend) -> Result<usize, StoreError> {
    let scope = tenant_scope("acme").map_err(StoreError::from)?;
    (backend.read)(scope, ACCOUNT.to_owned(), None, PAGE).await.map(|page| page.items.len())
}


#[tokio::test]
async fn the_backend_reads_one_page_scoped_to_the_tenant_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let mut served = served(page_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    assert_eq!(read_once(&backend).await?, 0);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert_eq!(bound.len(), 1, "{bound:?}");
    assert!(
        bound
            .iter()
            .all(|entry| entry.starts_with(&format!("PARAMS acme|{ACCOUNT}|32767||{}", PAGE + 1))),
        "{bound:?}"
    );
    Ok(())
}


#[tokio::test]
async fn a_store_error_is_reduced_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(failing_handler(|| Reply::Error("42601"))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    assert!(matches!(read_once(&backend).await, Err(StoreError::Pg(PgError::Server { .. }))));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_dropped_connection_fails_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(failing_handler(|| Reply::Drop)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let read = read_once(&backend).await;
    assert!(matches!(read, Err(StoreError::Pg(_))), "{read:?}");
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn an_empty_pool_is_busy_before_any_connection() -> Result<(), Box<dyn Error>> {
    let served = served(page_handler()).await?;
    let backend = pg_backend(Arc::clone(&served.engine), Arc::new(Semaphore::new(0)));
    assert!(matches!(read_once(&backend).await, Err(StoreError::Lease(LeaseError::Busy))));
    Ok(())
}


#[tokio::test]
async fn a_refused_account_limit_or_cursor_opens_no_connection_and_a_good_page_opens_one() -> Result<(), Box<dyn Error>> {
    let mut served = served(page_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let huge = "1".repeat(CURSOR_HUGE);
    let junk = ["junk", "run-a 1 3 e", huge.as_str()];
    for cursor in junk {
        assert!(
            read_flow(&identity(), &backend, Ok(ACCOUNT.to_owned()), Ok(query_of(Some(cursor), None)))
                .await
                .is_err(),
            "{cursor}"
        );
    }
    for limit in ["0", "501", "-1", ""] {
        assert!(
            read_flow(&identity(), &backend, Ok(ACCOUNT.to_owned()), Ok(query_of(None, Some(limit))))
                .await
                .is_err(),
            "{limit}"
        );
    }
    assert!(read_flow(&identity(), &backend, Ok("-bad".to_owned()), Ok(query_of(None, None)))
        .await
        .is_err());
    assert_eq!(drain(&mut served.fake.passwords).len(), 0);
    assert_eq!(drain(&mut served.fake.statements).len(), 0);
    assert!(read_flow(&identity(), &backend, Ok(ACCOUNT.to_owned()), Ok(query_of(None, None)))
        .await
        .is_ok());
    assert_eq!(drain(&mut served.fake.passwords).len(), 1);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
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
