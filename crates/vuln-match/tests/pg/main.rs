use alerts::backend::MAX_CONNECTIONS;
use alerts::error::StoreError as LeaseError;
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
use vuln_match::api::{asset_flow, list_flow};
use vuln_match::api_model::{FindingsBackend, ListQuery};
use vuln_match::backend::pg_backend;
use vuln_match::error::StoreError;
use vuln_match::limits::MAX_ASSET_FINDINGS;


const DRAIN_LIMIT: usize = 100;


const ASSET: &str = "host-a";


const PAGE: usize = 10;


const CURSOR_HUGE: usize = 10_000;


const BOUND_STATEMENTS: usize = 2;


const STATEMENT_TIMEOUT_SECS: u64 = 5;


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub _dir: TempDir,
}


pub fn finding_row() -> Vec<String> {
    [ASSET, "Debian:12", "curl", "CVE-1", "1.0", "", "7.5", "0.5", "false", "100", "1", "2"]
        .map(str::to_owned)
        .to_vec()
}


pub fn finding_handler() -> Handler {
    Arc::new(|sql| {
        if sql.contains("vuln_open_") {
            Reply::Rows(vec![finding_row()])
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
        module: "vuln-match".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served { engine, fake, _dir: dir })
}


pub async fn list_and_asset(backend: &FindingsBackend) -> (Result<usize, StoreError>, Result<bool, StoreError>) {
    let scope = tenant_scope("acme").ok();
    let listed = match scope.clone() {
        Some(held) => (backend.list)(held, None, PAGE).await.map(|page| page.findings.len()),
        None => Err(StoreError::BadAsset),
    };
    let found = match scope {
        Some(held) => (backend.asset)(held, ASSET.to_owned()).await.map(|page| !page.findings.is_empty()),
        None => Err(StoreError::BadAsset),
    };
    (listed, found)
}


#[tokio::test]
async fn the_backend_lists_and_reads_an_asset_scoped_to_the_tenant_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let mut served = served(finding_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let scope = tenant_scope("acme")?;
    let page = (backend.list)(scope.clone(), None, PAGE).await?;
    assert_eq!((page.findings.len(), page.skipped), (1, 0));
    let found = (backend.asset)(scope, ASSET.to_owned()).await?;
    assert_eq!(found.findings.len(), 1);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert_eq!(bound.len(), BOUND_STATEMENTS, "{bound:?}");
    assert!(bound.iter().all(|entry| entry.starts_with("PARAMS acme|")), "{bound:?}");
    assert!(bound.iter().any(|entry| entry == &format!("PARAMS acme|{}", PAGE + 1)), "{bound:?}");
    assert!(
        bound
            .iter()
            .any(|entry| entry == &format!("PARAMS acme|{ASSET}|{}", MAX_ASSET_FINDINGS + 1)),
        "{bound:?}"
    );
    Ok(())
}


#[tokio::test]
async fn a_store_error_is_reduced_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(failing_handler(|| Reply::Error("42601"))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let (listed, found) = list_and_asset(&backend).await;
    assert!(matches!(listed, Err(StoreError::Pg(PgError::Server { .. }))));
    assert!(matches!(found, Err(StoreError::Pg(PgError::Server { .. }))));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_dropped_connection_fails_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(failing_handler(|| Reply::Drop)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let (listed, found) = list_and_asset(&backend).await;
    assert!(matches!(listed, Err(StoreError::Pg(_))), "{listed:?}");
    assert!(matches!(found, Err(StoreError::Pg(_))), "{found:?}");
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn an_empty_pool_is_busy_before_any_connection() -> Result<(), Box<dyn Error>> {
    let served = served(finding_handler()).await?;
    let permits = Arc::new(Semaphore::new(0));
    let backend = pg_backend(Arc::clone(&served.engine), permits);
    let (listed, found) = list_and_asset(&backend).await;
    assert!(matches!(listed, Err(StoreError::Lease(LeaseError::Busy))));
    assert!(matches!(found, Err(StoreError::Lease(LeaseError::Busy))));
    Ok(())
}


pub fn query_of(cursor: Option<&str>, limit: Option<&str>) -> ListQuery {
    ListQuery {
        cursor: cursor.map(str::to_owned),
        limit: limit.map(str::to_owned),
    }
}


#[tokio::test]
async fn a_refused_cursor_limit_or_asset_opens_no_connection_and_a_good_page_opens_one() -> Result<(), Box<dyn Error>> {
    let mut served = served(finding_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let identity = ApiIdentity {
        module: "vuln-match".to_owned(),
        tenant: "acme".to_owned(),
        generation: 0,
    };
    let huge = "1".repeat(CURSOR_HUGE);
    for cursor in ["junk", "100 a e p", huge.as_str()] {
        assert!(
            list_flow(&identity, &backend, Ok(query_of(Some(cursor), None))).await.is_err(),
            "{cursor}"
        );
    }
    assert!(list_flow(&identity, &backend, Ok(query_of(None, Some("0")))).await.is_err());
    assert!(asset_flow(&identity, &backend, Ok("-bad".to_owned())).await.is_ok());
    assert_eq!(drain(&mut served.fake.passwords).len(), 0);
    assert_eq!(drain(&mut served.fake.statements).len(), 0);
    assert!(list_flow(&identity, &backend, Ok(query_of(Some("100 a e p r"), None))).await.is_ok());
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
