mod certs;
mod fake;
mod types;


use alerts::backend::{lease, MAX_CONNECTIONS};
use alerts::error::StoreError as LeaseError;
use certs::{loopback, make_pki};
use cmdb::backend::pg_backend;
use cmdb::error::StoreError;
use cmdb::model::Limits;
use cmdb::pg::{pg_executor, pg_rows};
use cmdb::store::load_assets;
use cmdb::stored::AssetPage;
use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use core_pg::settings::{open_settings, parse_settings, PgSettings};
use fake::{Fake, Mode, Reply};
use rcgen::SanType;
use std::error::Error;
use std::io::sink;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Semaphore;
use tokio_postgres::Client;
use types::Handler;


const DEADLINE: Duration = Duration::from_secs(30);


const DRAIN_LIMIT: usize = 100;


const TWO_ROWS: usize = 2;


const TABLES_READ: usize = 3;


pub async fn client_with(handler: Handler) -> Result<(Client, Fake, TempDir), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), "p", handler).await?;
    let dir = tempdir()?;
    let password_file = dir.path().join("pg.pass");
    let ca_file = dir.path().join("ca.pem");
    std::fs::write(&password_file, "p")?;
    std::fs::write(&ca_file, &pki.ca_pem)?;
    let text = format!(
        "host: 127.0.0.1\nport: {}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
        fake.port,
        password_file.display(),
        ca_file.display()
    );
    let client = connect(&parse_settings(&text, "pg.yaml")?).await?;
    Ok((client, fake, dir))
}


pub fn drain(receiver: &mut UnboundedReceiver<String>) -> Vec<String> {
    std::iter::repeat_with(|| receiver.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


pub fn by_sql() -> Handler {
    Arc::new(|sql| {
        if sql.contains("SYNTAX") {
            Reply::Error("42601")
        } else if sql.contains("TWOROWS") {
            Reply::Rows(vec![vec!["a".to_owned(), "b".to_owned()], vec!["c".to_owned(), "d".to_owned()]])
        } else {
            Reply::Done
        }
    })
}


#[tokio::test]
async fn pg_rows_binds_the_tenant_first_and_returns_text_columns() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with(by_sql()).await?;
    let scope = tenant_scope("acme")?;
    let rows = pg_rows(&client, DEADLINE, scope, "SELECT TWOROWS $1 $2", vec!["note".to_owned()]).await?;
    assert_eq!(rows.len(), TWO_ROWS);
    assert_eq!(rows.first().map(Vec::as_slice), Some(["a".to_owned(), "b".to_owned()].as_slice()));
    let statements = drain(&mut fake.statements);
    assert!(statements.iter().any(|entry| entry == "PARAMS acme|note"), "{statements:?}");
    Ok(())
}


#[tokio::test]
async fn pg_rows_reduces_a_server_error() -> Result<(), Box<dyn Error>> {
    let (client, _fake, _dir) = client_with(by_sql()).await?;
    let error = pg_rows(&client, DEADLINE, tenant_scope("acme")?, "SELECT SYNTAX $1", vec![])
        .await
        .err()
        .ok_or("accepted")?;
    assert!(matches!(error, PgError::Server { .. }), "{error}");
    Ok(())
}


#[tokio::test]
async fn load_assets_runs_against_a_real_client_scoped_to_the_tenant() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with(by_sql()).await?;
    let scope = tenant_scope("acme")?;
    let exec = pg_executor(&client, DEADLINE);
    let snapshot = load_assets(&exec, &scope, &Limits::default()).await?;
    assert!(snapshot.assets.is_empty());
    let statements = drain(&mut fake.statements);
    let bound: Vec<&String> = statements.iter().filter(|entry| entry.starts_with("PARAMS")).collect();
    assert_eq!(bound.len(), TABLES_READ, "{statements:?}");
    assert!(
        bound
            .iter()
            .all(|entry| entry.starts_with("PARAMS acme|true|") && entry.ends_with("|500")),
        "{bound:?}"
    );
    Ok(())
}


const PAGE_SIZE: usize = 10;


const BACKEND_STATEMENTS: usize = 4;


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub _dir: TempDir,
}


pub fn asset_handler() -> Handler {
    Arc::new(|sql| {
        if sql.contains("FROM cmdb_identity_keys WHERE tenant = $1 AND asset") {
            Reply::Rows(vec![vec!["serial_number".to_owned(), "SN-1".to_owned()]])
        } else if sql.contains("FROM cmdb_attributes WHERE tenant = $1 AND asset") {
            Reply::Rows(vec![vec!["owner".to_owned(), "alice".to_owned(), "declared".to_owned()]])
        } else if sql.contains("FROM cmdb_assets a") {
            Reply::Rows(vec![["srv-a", "server", "in_service", "3", "1", "1", "0"].map(str::to_owned).to_vec()])
        } else {
            Reply::Done
        }
    })
}


pub async fn served(handler: Handler) -> Result<Served, Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), "p", handler).await?;
    let dir = tempdir()?;
    let password_file = dir.path().join("pg.pass");
    let ca_file = dir.path().join("ca.pem");
    std::fs::write(&password_file, "p")?;
    std::fs::write(&ca_file, &pki.ca_pem)?;
    let settings_text = format!(
        "host: 127.0.0.1\nport: {}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
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
        module: "cmdb".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served { engine, fake, _dir: dir })
}


#[tokio::test]
async fn the_pg_backend_lists_and_gets_through_a_leased_connection_scoped_to_the_tenant() -> Result<(), Box<dyn Error>> {
    let mut served = served(asset_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let scope = tenant_scope("acme")?;
    let page = AssetPage {
        after: None,
        size: PAGE_SIZE,
    };
    let listed = (backend.list)(scope.clone(), page).await?;
    assert_eq!(listed.summaries.len(), 1);
    let found = (backend.get)(scope, "srv-a".to_owned()).await?;
    let detail = found.ok_or("no detail")?;
    assert_eq!(detail.summary.id, "srv-a");
    assert_eq!((detail.keys.len(), detail.attributes.len(), detail.truncated), (1, 1, false));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert_eq!(bound.len(), BACKEND_STATEMENTS, "{bound:?}");
    assert!(bound.iter().all(|entry| entry.starts_with("PARAMS acme|")), "{bound:?}");
    Ok(())
}


#[tokio::test]
async fn a_full_pool_is_busy_before_any_connection() -> Result<(), Box<dyn Error>> {
    let served = served(asset_handler()).await?;
    let permits = Arc::new(Semaphore::new(0));
    let refused = lease(&served.engine, &permits).await.err().ok_or("leased")?;
    assert!(matches!(refused, LeaseError::Busy));
    let backend = pg_backend(Arc::clone(&served.engine), permits);
    let scope = tenant_scope("acme")?;
    let page = AssetPage {
        after: None,
        size: PAGE_SIZE,
    };
    assert!(matches!(
        (backend.list)(scope.clone(), page).await,
        Err(StoreError::Lease(LeaseError::Busy))
    ));
    assert!(matches!(
        (backend.get)(scope, "srv-a".to_owned()).await,
        Err(StoreError::Lease(LeaseError::Busy))
    ));
    Ok(())
}
