mod types;


use alerts::backend::MAX_CONNECTIONS;
use alerts::error::StoreError as LeaseError;
use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_pg::connect::connect_current;
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use core_pg::settings::{open_settings, PgSettings};
use oncall::alert::{Cell, Param, Statement};
use oncall::backend::{bound, execute, pg_backend, pg_get, pg_list};
use oncall::error::{ReadError, StoreError};
use oncall::limits::MAX_OPEN_ALERTS;
use oncall::rows::{cell_bool, cell_int, cell_text, cell_time};
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, int8_cell, Fake, Mode, Reply, INT4_OID, INT8_OID, TEXT_OID};
use pg_fake::types::Handler;
use rcgen::SanType;
use std::error::Error;
use std::io::sink;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Semaphore;
use types::Cells;


const TIMESTAMPTZ_OID: i32 = 1184;


const BOOL_OID: i32 = 16;


const UNIX_TO_POSTGRES_SECONDS: i64 = 946_684_800;


const MICROS: i64 = 1_000_000;


const STAMP: i64 = 1_800_000_000;


const FIRST_ID: i64 = 11;


const DRAIN_LIMIT: usize = 100;


const LIMIT: u32 = 7;


const STATEMENT_SECONDS: u64 = 7;


const OPENED_COLUMN: usize = 6;


const PARAMETER_KINDS: usize = 4;


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub _dir: TempDir,
}


fn micros(unix: i64) -> Option<Vec<u8>> {
    int8_cell((unix - UNIX_TO_POSTGRES_SECONDS) * MICROS)
}


fn text(value: &str) -> Option<Vec<u8>> {
    Some(value.as_bytes().to_vec())
}


fn columns() -> Vec<i32> {
    vec![
        INT8_OID,
        TEXT_OID,
        TEXT_OID,
        INT8_OID,
        INT8_OID,
        INT8_OID,
        TIMESTAMPTZ_OID,
        TIMESTAMPTZ_OID,
        TIMESTAMPTZ_OID,
    ]
}


fn row(id: i64, fingerprint: &str, state: &str) -> Cells {
    vec![
        int8_cell(id),
        text(fingerprint),
        text(state),
        int8_cell(0),
        int8_cell(1),
        int8_cell(1),
        micros(STAMP),
        None,
        None,
    ]
}


fn typed(rows: Vec<Cells>) -> Reply {
    Reply::Typed {
        parameters: vec![TEXT_OID, INT8_OID],
        columns: columns(),
        rows,
    }
}


fn handler(reply: Reply) -> Handler {
    Arc::new(move |sql| {
        if sql.contains("FROM oncall_alerts") {
            reply.clone()
        } else {
            Reply::Done
        }
    })
}


pub fn drain(receiver: &mut UnboundedReceiver<String>) -> Vec<String> {
    std::iter::repeat_with(|| receiver.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


fn bound_params(receiver: &mut UnboundedReceiver<String>) -> Vec<String> {
    drain(receiver).into_iter().filter(|entry| entry.starts_with("PARAMS")).collect()
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
        "host: 127.0.0.1\nport: {}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\nstatement_timeout_secs: {STATEMENT_SECONDS}\n",
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
        module: "oncall".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served { engine, fake, _dir: dir })
}


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
async fn the_list_binds_the_tenant_first_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let mut served = served(handler(typed(vec![row(FIRST_ID, "cpu-high", "open"), row(FIRST_ID + 1, "x", "bogus")]))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let page = (backend.list)(tenant_scope("acme")?, LIMIT).await?;
    assert_eq!(page.alerts.len(), 1);
    assert_eq!(page.skipped, 1);
    assert_eq!(page.alerts.first().map(|found| found.id), Some(FIRST_ID));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    assert_eq!(bound_params(&mut served.fake.statements), [format!("PARAMS acme|{LIMIT}")]);
    Ok(())
}


#[tokio::test]
async fn the_get_binds_the_tenant_first_and_an_empty_answer_is_none() -> Result<(), Box<dyn Error>> {
    let mut found = served(handler(typed(vec![row(FIRST_ID, "cpu-high", "open")]))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&found.engine), Arc::clone(&permits));
    let alert = (backend.get)(tenant_scope("acme")?, FIRST_ID).await?;
    assert_eq!(alert.map(|value| value.fingerprint), Some("cpu-high".to_owned()));
    assert_eq!(bound_params(&mut found.fake.statements), [format!("PARAMS acme|{FIRST_ID}")]);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let empty = served(handler(typed(Vec::new()))).await?;
    let none = pg_get(Arc::clone(&empty.engine), Arc::clone(&permits), tenant_scope("globex")?, FIRST_ID).await?;
    assert!(none.is_none());
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_database_error_or_a_dropped_session_is_a_store_failure_and_the_permit_returns() -> Result<(), Box<dyn Error>> {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    for reply in [Reply::Error("XX000"), Reply::Drop] {
        let served = served(handler(reply)).await?;
        let listed = pg_list(Arc::clone(&served.engine), Arc::clone(&permits), tenant_scope("acme")?, LIMIT).await;
        assert!(matches!(listed, Err(ReadError::Store(StoreError::Pg(_)))));
        let got = pg_get(Arc::clone(&served.engine), Arc::clone(&permits), tenant_scope("acme")?, FIRST_ID).await;
        assert!(matches!(got, Err(ReadError::Store(StoreError::Pg(_)))));
        assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    }
    Ok(())
}


#[tokio::test]
async fn an_unreadable_column_or_a_null_id_is_a_refused_row() -> Result<(), Box<dyn Error>> {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let wrong_type = Reply::Typed {
        parameters: vec![TEXT_OID, INT8_OID],
        columns: vec![INT8_OID, INT4_OID],
        rows: vec![vec![int8_cell(1), Some(vec![0, 0, 0, 1])]],
    };
    let null_id = typed(vec![{
        let mut cells = row(FIRST_ID, "x", "open");
        cells.remove(0);
        cells.insert(0, None);
        cells
    }]);
    for reply in [wrong_type, null_id] {
        let served = served(handler(reply)).await?;
        let got = pg_get(Arc::clone(&served.engine), Arc::clone(&permits), tenant_scope("acme")?, FIRST_ID).await;
        assert!(matches!(got, Err(ReadError::Store(StoreError::BadRow { .. }))));
    }
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_time_the_driver_cannot_decode_refuses_only_its_row() -> Result<(), Box<dyn Error>> {
    let mut far = row(FIRST_ID + 1, "far", "open");
    far.remove(OPENED_COLUMN);
    far.insert(OPENED_COLUMN, int8_cell(i64::MAX));
    let mixed = served(handler(typed(vec![far.clone(), row(FIRST_ID, "good", "open")]))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let page = pg_list(Arc::clone(&mixed.engine), Arc::clone(&permits), tenant_scope("acme")?, LIMIT).await?;
    assert_eq!(page.alerts.iter().map(|found| found.id).collect::<Vec<_>>(), [FIRST_ID]);
    assert_eq!(page.skipped, 1);
    let alone = served(handler(typed(vec![far]))).await?;
    let got = pg_get(Arc::clone(&alone.engine), permits, tenant_scope("acme")?, FIRST_ID + 1).await;
    assert!(matches!(got, Err(ReadError::Store(StoreError::BadRow { .. }))));
    Ok(())
}


#[tokio::test]
async fn a_limit_outside_the_range_is_refused_by_the_store_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(handler(typed(Vec::new()))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    for limit in [0, MAX_OPEN_ALERTS + 1] {
        let listed = pg_list(Arc::clone(&served.engine), Arc::clone(&permits), tenant_scope("acme")?, limit).await;
        assert!(matches!(listed, Err(ReadError::Store(StoreError::LimitOutOfRange { .. }))));
    }
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn an_empty_pool_is_busy_before_any_connection() -> Result<(), Box<dyn Error>> {
    let mut served = served(handler(typed(Vec::new()))).await?;
    let permits = Arc::new(Semaphore::new(0));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let listed = (backend.list)(tenant_scope("acme")?, LIMIT).await;
    assert!(matches!(listed, Err(ReadError::Lease(LeaseError::Busy))));
    let got = (backend.get)(tenant_scope("acme")?, FIRST_ID).await;
    assert!(matches!(got, Err(ReadError::Lease(LeaseError::Busy))));
    assert_eq!(permits.available_permits(), 0);
    assert!(drain(&mut served.fake.statements).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_cancelled_request_returns_its_permit() -> Result<(), Box<dyn Error>> {
    let mut served = served(handler(Reply::Hang)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let task = tokio::spawn(pg_list(Arc::clone(&served.engine), Arc::clone(&permits), tenant_scope("acme")?, LIMIT));
    let mut reached = false;
    for _ in 0..DRAIN_LIMIT {
        if !reached {
            reached = served.fake.statements.recv().await.ok_or("fake closed")?.contains("FROM oncall_alerts");
        }
    }
    assert!(reached);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS - 1);
    task.abort();
    assert!(task.await.is_err());
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[test]
fn every_parameter_kind_is_bound() -> Result<(), Box<dyn Error>> {
    let statement = Statement {
        sql: "SELECT 1",
        params: vec![Param::Int(1), Param::Text("a".to_owned()), Param::OptText(None), Param::Time(None)],
    };
    assert_eq!(bound(&statement).len(), PARAMETER_KINDS);
    Ok(())
}


fn pausing_handler() -> Handler {
    Arc::new(|sql| {
        if sql.contains("FROM oncall_alerts") {
            tokio::time::pause();
            Reply::Hang
        } else {
            Reply::Done
        }
    })
}


#[tokio::test]
async fn a_hung_list_hits_the_configured_statement_deadline_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(pausing_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let listed = pg_list(Arc::clone(&served.engine), Arc::clone(&permits), tenant_scope("acme")?, LIMIT).await;
    assert!(matches!(
        listed,
        Err(ReadError::Store(StoreError::Pg(PgError::StatementTimeout { seconds: STATEMENT_SECONDS })))
    ));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_hung_get_hits_the_configured_statement_deadline_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(pausing_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let got = pg_get(Arc::clone(&served.engine), Arc::clone(&permits), tenant_scope("acme")?, FIRST_ID).await;
    assert!(matches!(
        got,
        Err(ReadError::Store(StoreError::Pg(PgError::StatementTimeout { seconds: STATEMENT_SECONDS })))
    ));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


fn bool_reply(rows: Vec<Cells>) -> Reply {
    Reply::Typed {
        parameters: vec![TEXT_OID],
        columns: vec![BOOL_OID, INT4_OID],
        rows,
    }
}


#[tokio::test]
async fn a_stored_true_bool_decodes_as_true_and_an_undecodable_cell_is_not_a_bool() -> Result<(), Box<dyn Error>> {
    let served = served(Arc::new(|_sql| bool_reply(vec![vec![Some(vec![1]), Some(vec![0, 0, 0, 1])]]))).await?;
    let client = connect_current(&served.engine).await?;
    let statement = Statement {
        sql: "SELECT created, other FROM oncall_alerts WHERE tenant = $1",
        params: Vec::new(),
    };
    let rows = execute(&client, Duration::from_secs(STATEMENT_SECONDS), tenant_scope("acme")?, statement).await?;
    let row = rows.first().ok_or("no row")?;
    assert_eq!(row.first(), Some(&Cell::Bool(true)));
    assert_eq!(row.get(1), Some(&Cell::Unreadable));
    assert!(cell_bool(row, 0, "created")?);
    assert!(cell_bool(row, 1, "created").is_err());
    assert!(cell_int(row, 1, "x").is_err() && cell_text(row, 1, "x").is_err() && cell_time(row, 1, "x").is_err());
    Ok(())
}
