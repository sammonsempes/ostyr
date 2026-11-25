mod certs;
mod fake;
mod types;


use alerts::backend::{detached, lease, pg_backend, unix_micros, LOG_IGNORED_CRATE, MAX_CONNECTIONS};
use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::{Page, TriageChange, TriageStatus};
use alerts::pg::{pg_executor, pg_rows};
use alerts::store::{get_triage, list_alerts, set_triage};
use certs::{loopback, make_pki};
use core_api::logging::reloadable_dispatch;
use core_audit::log::{append, genesis_log};
use core_config::reload::{reload, ReloadContext, ReloadEngine, ReloadOutcome};
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use core_pg::settings::{open_settings, parse_settings, PgSettings};
use fake::{Fake, Mode, Reply};
use rcgen::SanType;
use std::error::Error;
use std::io::{sink, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::{oneshot, Notify, Semaphore};
use tokio_postgres::Client;
use tracing::level_filters::LevelFilter;
use tracing::Dispatch;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use types::Handler;


const DEADLINE: Duration = Duration::from_secs(30);


const DRAIN_LIMIT: usize = 100;


const TWO_ROWS: usize = 2;


const PAGE_SIZE: usize = 10;


const TRIAGE_TIME: u64 = 5;


pub async fn client_with(handler: Handler) -> Result<(Client, Fake, TempDir), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), "p", handler).await?;
    let dir = tempdir()?;
    let password_file = dir.path().join("pg.pass");
    let ca_file = dir.path().join("ca.pem");
    write_secret(&password_file, "p")?;
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
async fn list_alerts_runs_against_a_real_client_scoped_to_the_tenant() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with(by_sql()).await?;
    let scope = tenant_scope("acme")?;
    let exec = pg_executor(&client, DEADLINE);
    let page = list_alerts(
        &exec,
        &scope,
        &Page {
            after: None,
            size: PAGE_SIZE,
        },
    )
    .await?;
    assert!(page.alerts.is_empty());
    let statements = drain(&mut fake.statements);
    let bound: Vec<&String> = statements.iter().filter(|entry| entry.starts_with("PARAMS")).collect();
    assert_eq!(bound.len(), 1, "{statements:?}");
    assert!(bound.iter().all(|entry| entry.as_str() == "PARAMS acme|11"), "{bound:?}");
    Ok(())
}


#[tokio::test]
async fn set_and_get_triage_round_trip_on_a_real_client() -> Result<(), Box<dyn Error>> {
    let handler: Handler = Arc::new(|sql| {
        if sql.contains("INSERT INTO alert_triage") {
            Reply::Rows(vec![vec!["1".to_owned(), "1".to_owned(), "r1".to_owned()]])
        } else {
            Reply::Rows(vec![vec![
                "closed".to_owned(),
                "ana".to_owned(),
                "done".to_owned(),
                "5".to_owned(),
                "1".to_owned(),
            ]])
        }
    });
    let (client, mut fake, _dir) = client_with(handler).await?;
    let scope = tenant_scope("acme")?;
    let exec = pg_executor(&client, DEADLINE);
    let id = alert_id("acme", "r1", &["e1".to_owned()]);
    let change = TriageChange {
        status: TriageStatus::Closed,
        actor: "ana".to_owned(),
        note: Some("done".to_owned()),
        now: TRIAGE_TIME,
    };
    let written = set_triage(&exec, &scope, &id, &change, None).await?;
    assert_eq!((written.triage.version, written.rule_id.as_str()), (1, "r1"));
    let read = get_triage(&exec, &scope, &id).await?.ok_or("no triage")?;
    assert_eq!(
        (read.status, read.actor.as_str(), read.note.as_deref(), read.updated_at),
        (TriageStatus::Closed, "ana", Some("done"), TRIAGE_TIME)
    );
    let statements = drain(&mut fake.statements);
    let bound: Vec<&String> = statements.iter().filter(|entry| entry.starts_with("PARAMS")).collect();
    assert_eq!(bound.len(), TWO_ROWS, "{statements:?}");
    assert!(bound.iter().all(|entry| entry.starts_with("PARAMS acme|")), "{bound:?}");
    Ok(())
}


pub const MARKER: &str = "marker-7f3a91";


pub const ALERT_COLUMNS: usize = 12;


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub dir: TempDir,
    pub settings_file: PathBuf,
    pub settings_text: String,
}


pub struct SharedBuffer(pub Arc<Mutex<Vec<u8>>>);


impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


pub static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(sink).finish()));


pub fn alert_row(id: &str) -> Vec<String> {
    let columns = [
        id,
        "r1",
        "Whoami executed",
        "high",
        "2026-11-10T10:00:00Z",
        "1700000000000000",
        "",
        "",
        "[\"e1\"]",
        "{}",
        "false",
        "2",
    ];
    assert_eq!(columns.len(), ALERT_COLUMNS);
    columns.iter().map(|column| (*column).to_owned()).collect()
}


pub fn alert_handler() -> Handler {
    let id = alert_id("acme", "r1", &["e1".to_owned()]);
    Arc::new(move |sql| {
        if sql.contains("INSERT INTO alert_triage") {
            Reply::Rows(vec![vec!["1".to_owned(), "1".to_owned(), "r1".to_owned()]])
        } else if sql.contains("FROM alerts") {
            Reply::Rows(vec![alert_row(&id)])
        } else {
            Reply::Done
        }
    })
}


pub fn settings_for(port: u16, dir: &TempDir, ca_pem: &str) -> Result<String, Box<dyn Error>> {
    let password_file = dir.path().join("pg.pass");
    let ca_file = dir.path().join("ca.pem");
    write_secret(&password_file, "p")?;
    std::fs::write(&ca_file, ca_pem)?;
    Ok(format!(
        "host: 127.0.0.1\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
        password_file.display(),
        ca_file.display()
    ))
}


pub async fn served(handler: Handler) -> Result<Served, Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), "p", handler).await?;
    let dir = tempdir()?;
    let settings_text = settings_for(fake.port, &dir, &pki.ca_pem)?;
    let settings_file = dir.path().join("pg.yaml");
    std::fs::write(&settings_file, &settings_text)?;
    let log = genesis_log(sink());
    let context = ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "acme".to_owned(),
        module: "alerts".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file.clone(), Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served {
        engine,
        fake,
        dir,
        settings_file,
        settings_text,
    })
}


#[tokio::test]
async fn the_pg_backend_lists_and_gets_through_a_leased_connection() -> Result<(), Box<dyn Error>> {
    let mut served = served(alert_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let scope = tenant_scope("acme")?;
    let page = (backend.list)(
        scope.clone(),
        Page {
            after: None,
            size: PAGE_SIZE,
        },
    )
    .await?;
    assert_eq!(page.alerts.len(), 1);
    let id = alert_id("acme", "r1", &["e1".to_owned()]);
    let found = (backend.get)(scope, id.clone()).await?;
    assert_eq!(found.map(|detail| detail.alert.id), Some(id.clone()));
    let change = TriageChange {
        status: TriageStatus::Closed,
        actor: "ana".to_owned(),
        note: None,
        now: TRIAGE_TIME,
    };
    let written = (backend.triage)(tenant_scope("acme")?, id, change, None).await?;
    assert_eq!((written.triage.version, written.rule_id.as_str()), (1, "r1"));
    assert!(unix_micros() > TRIAGE_TIME);
    assert!((backend.clock)() > TRIAGE_TIME);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert!(bound.iter().all(|entry| entry.starts_with("PARAMS acme|")), "{bound:?}");
    Ok(())
}


#[tokio::test]
async fn a_full_pool_is_busy_before_any_connection() -> Result<(), Box<dyn Error>> {
    let served = served(alert_handler()).await?;
    let permits = Arc::new(Semaphore::new(0));
    let refused = lease(&served.engine, &permits).await.err().ok_or("leased")?;
    assert!(matches!(refused, StoreError::Busy));
    Ok(())
}


#[tokio::test]
async fn the_pg_backend_is_busy_when_no_connection_is_free() -> Result<(), Box<dyn Error>> {
    let served = served(alert_handler()).await?;
    let backend = pg_backend(Arc::clone(&served.engine), Arc::new(Semaphore::new(0)));
    let scope = tenant_scope("acme")?;
    let listed = (backend.list)(
        scope.clone(),
        Page {
            after: None,
            size: PAGE_SIZE,
        },
    )
    .await;
    assert!(matches!(listed, Err(StoreError::Busy)));
    let id = alert_id("acme", "r1", &["e1".to_owned()]);
    let found = (backend.get)(scope.clone(), id.clone()).await;
    assert!(matches!(found, Err(StoreError::Busy)));
    let change = TriageChange {
        status: TriageStatus::Closed,
        actor: "ana".to_owned(),
        note: None,
        now: TRIAGE_TIME,
    };
    let triaged = (backend.triage)(scope, id, change, None).await;
    assert!(matches!(triaged, Err(StoreError::Busy)));
    Ok(())
}


#[tokio::test]
async fn settings_follow_the_file_and_an_invalid_file_keeps_the_old_ones() -> Result<(), Box<dyn Error>> {
    let served = served(alert_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    std::fs::write(&served.settings_file, "host: [")?;
    assert!(matches!(reload(&served.engine), ReloadOutcome::Refused { .. }));
    assert!(lease(&served.engine, &permits).await.is_ok());
    std::fs::write(&served.settings_file, served.settings_text.replace("port: ", "port: 1\n#"))?;
    assert!(matches!(reload(&served.engine), ReloadOutcome::Applied { .. }));
    let refused = lease(&served.engine, &permits).await.err().ok_or("connected")?;
    assert!(matches!(refused, StoreError::Pg(_)), "{refused}");
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    assert!(served.dir.path().exists());
    Ok(())
}


#[tokio::test]
async fn a_bridged_log_at_trace_never_carries_a_bound_parameter() -> Result<(), Box<dyn Error>> {
    LazyLock::force(&ANCHOR);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&captured);
    let (dispatch, _level) = reloadable_dispatch(BoxMakeWriter::new(move || SharedBuffer(Arc::clone(&writer))), LevelFilter::TRACE);
    tracing_log::LogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()?;
    tracing_log::log::set_max_level(tracing_log::log::LevelFilter::Trace);
    let guard = tracing::dispatcher::set_default(&dispatch);
    let (client, _fake, _dir) = client_with(by_sql()).await?;
    pg_rows(&client, DEADLINE, tenant_scope("acme")?, "SELECT TWOROWS $1 $2", vec![MARKER.to_owned()]).await?;
    tracing_log::log::info!("bridge canary");
    drop(guard);
    let text = String::from_utf8(captured.lock().unwrap_or_else(PoisonError::into_inner).clone())?;
    assert!(text.contains("bridge canary"), "{text}");
    assert!(!text.contains(MARKER), "{text}");
    assert!(!text.contains("tokio_postgres"), "{text}");
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


#[tokio::test]
async fn a_dropped_request_keeps_its_permit_until_the_store_call_ends() -> Result<(), Box<dyn Error>> {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let release = Arc::new(Notify::new());
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let work_permits = Arc::clone(&permits);
    let work_release = Arc::clone(&release);
    let request = tokio::spawn(detached(async move {
        let permit = work_permits.try_acquire_owned().map_err(|_full| StoreError::Busy)?;
        started_tx.send(()).map_err(|_gone| StoreError::Busy)?;
        work_release.notified().await;
        drop(permit);
        done_tx.send(()).map_err(|_gone| StoreError::Busy)
    }));
    started_rx.await?;
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS - 1);
    request.abort();
    assert!(request.await.is_err());
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS - 1);
    release.notify_one();
    done_rx.await?;
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


pub fn held_alerts(release: &Arc<Notify>) -> Handler {
    let held = Arc::clone(release);
    Arc::new(move |sql| {
        if sql.contains("FROM alerts") {
            Reply::Held(Arc::clone(&held))
        } else {
            Reply::Done
        }
    })
}


pub const MAX_WAITED_STATEMENTS: usize = 100;


pub async fn wait_for_alerts_statement(statements: &mut UnboundedReceiver<String>) -> Result<(), Box<dyn Error>> {
    let mut seen = false;
    let mut waited = 0;
    while !seen && waited < MAX_WAITED_STATEMENTS {
        waited += 1;
        let next = statements.recv().await.ok_or("fake closed")?;
        seen = next.contains("FROM alerts");
    }
    Ok(())
}


#[tokio::test]
async fn a_dropped_list_keeps_its_permit_until_the_statement_ends() -> Result<(), Box<dyn Error>> {
    let release = Arc::new(Notify::new());
    let mut served = served(held_alerts(&release)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let list = Arc::clone(&backend.list);
    let request = tokio::spawn(async move {
        list(
            tenant_scope("acme").map_err(|error| error.to_string())?,
            Page {
                after: None,
                size: PAGE_SIZE,
            },
        )
        .await
        .map(|_page| ())
        .map_err(|error| error.to_string())
    });
    wait_for_alerts_statement(&mut served.fake.statements).await?;
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS - 1);
    request.abort();
    assert!(request.await.is_err());
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS - 1);
    release.notify_one();
    let all = permits.acquire_many(u32::try_from(MAX_CONNECTIONS)?).await?;
    assert_eq!(permits.available_permits(), 0);
    drop(all);
    Ok(())
}


#[tokio::test]
async fn a_dropped_get_keeps_its_permit_until_the_statement_ends() -> Result<(), Box<dyn Error>> {
    let release = Arc::new(Notify::new());
    let mut served = served(held_alerts(&release)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let get = Arc::clone(&backend.get);
    let id = alert_id("acme", "r1", &["e1".to_owned()]);
    let request = tokio::spawn(async move {
        get(tenant_scope("acme").map_err(|error| error.to_string())?, id)
            .await
            .map(|_found| ())
            .map_err(|error| error.to_string())
    });
    wait_for_alerts_statement(&mut served.fake.statements).await?;
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS - 1);
    request.abort();
    assert!(request.await.is_err());
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS - 1);
    release.notify_one();
    let all = permits.acquire_many(u32::try_from(MAX_CONNECTIONS)?).await?;
    assert_eq!(permits.available_permits(), 0);
    drop(all);
    Ok(())
}


#[tokio::test]
async fn a_panicking_store_task_is_the_fixed_failure() -> Result<(), Box<dyn Error>> {
    let panicked: Result<(), StoreError> = detached(async {
        let cell = std::cell::RefCell::new(());
        let first = cell.borrow_mut();
        let second = cell.borrow_mut();
        drop((first, second));
        Ok(())
    })
    .await;
    let error = panicked.err().ok_or("no failure")?;
    assert!(matches!(error, StoreError::TaskFailed));
    assert_eq!(error.to_string(), "the store task did not finish");
    Ok(())
}
