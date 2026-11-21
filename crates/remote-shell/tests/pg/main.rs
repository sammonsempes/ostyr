use alerts::backend::MAX_CONNECTIONS;
use alerts::error::StoreError as LeaseError;
use core_api::model::ApiIdentity;
use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_pg::connect::connect_current;
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use core_pg::settings::{open_settings, PgSettings};
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, int8_cell, Fake, Mode, Reply, INT8_OID, TEXT_OID};
use pg_fake::types::Handler;
use rcgen::SanType;
use remote_shell::api::{get_flow, list_flow};
use remote_shell::api_model::ListQuery;
use remote_shell::backend::{bound, pg_backend, pg_execute};
use remote_shell::error::StoreError;
use remote_shell::store::{LIST_AFTER_SQL, LIST_SQL, SESSION_SQL};
use remote_shell::store_model::{Cell, ListFilter, Param, Statement};
use std::error::Error;
use std::io::sink;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Semaphore;


const DRAIN_LIMIT: usize = 100;


const PAGE: u32 = 10;


const BOOL_OID: i32 = 16;


const BYTEA_OID: i32 = 17;


const STATEMENT_TIMEOUT_SECS: u64 = 5;


const CURSOR_HUGE: usize = 10_000;


const OPENED: i64 = 1_800_000_000;


const HASH_LEN: usize = 32;


const FRAMES: i64 = 3;


const BAD_INT8_LEN: usize = 3;


const FORCED_PARAMS: usize = 5;


const BOUND_STATEMENTS: usize = 2;


const BAD_REQUEST: u16 = 400;


const NOT_FOUND: u16 = 404;


const OK: u16 = 200;


const BYTES: [u8; 2] = [1, 2];


const IDX_BYTES: usize = 2;


const IDX_NULL: usize = 3;


const IDX_TEXT: usize = 4;


const IDX_BAD_TEXT: usize = 5;


const IDX_BOOL: usize = 6;


const BAD_UTF8: [u8; 2] = [0xff, 0xfe];


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub _dir: TempDir,
}


fn text(value: &str) -> Option<Vec<u8>> {
    Some(value.as_bytes().to_vec())
}


fn columns() -> Vec<i32> {
    vec![
        TEXT_OID, TEXT_OID, TEXT_OID, TEXT_OID, INT8_OID, INT8_OID, TEXT_OID, INT8_OID, BYTEA_OID, INT8_OID,
    ]
}


pub fn session_cells(session: &str, requester: &str) -> Vec<Option<Vec<u8>>> {
    vec![
        text(session),
        text(requester),
        text("host-1"),
        text("INC-1"),
        int8_cell(OPENED),
        int8_cell(OPENED + 1),
        text("user_close"),
        int8_cell(FRAMES),
        Some(vec![1; HASH_LEN]),
        int8_cell(0),
    ]
}


fn parameters_of(sql: &str) -> Vec<i32> {
    if sql.contains("(opened_at, session_id) <") {
        vec![TEXT_OID, TEXT_OID, TEXT_OID, BOOL_OID, INT8_OID, INT8_OID, TEXT_OID]
    } else if sql.contains("session_id = $2") {
        vec![TEXT_OID, TEXT_OID]
    } else {
        vec![TEXT_OID, TEXT_OID, TEXT_OID, BOOL_OID, INT8_OID]
    }
}


pub fn typed(sql: &str, rows: Vec<Vec<Option<Vec<u8>>>>) -> Reply {
    Reply::Typed {
        parameters: parameters_of(sql),
        columns: columns(),
        rows,
    }
}


pub fn session_handler(rows: fn() -> Vec<Vec<Option<Vec<u8>>>>) -> Handler {
    Arc::new(move |sql| {
        if sql.contains("FROM remote_shell_sessions") && sql.contains("tenant = $1") {
            typed(sql, rows())
        } else if sql.contains("FROM remote_shell_sessions") {
            Reply::Error("42601")
        } else {
            Reply::Done
        }
    })
}


pub fn one_session() -> Vec<Vec<Option<Vec<u8>>>> {
    vec![session_cells("s-1", "alice")]
}


pub fn two_sessions_one_hostile() -> Vec<Vec<Option<Vec<u8>>>> {
    vec![session_cells("s-1", "alice"), session_cells("s-2", "al ice")]
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
        module: "remote-shell".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served { engine, fake, _dir: dir })
}


pub fn query_of(cursor: Option<&str>, limit: Option<&str>) -> ListQuery {
    ListQuery {
        cursor: cursor.map(str::to_owned),
        limit: limit.map(str::to_owned),
        ..ListQuery::default()
    }
}


pub fn identity() -> ApiIdentity {
    ApiIdentity {
        module: "remote-shell".to_owned(),
        tenant: "acme".to_owned(),
        generation: 0,
    }
}


#[tokio::test]
async fn the_backend_lists_and_reads_scoped_to_the_tenant_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let mut served = served(session_handler(one_session)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let scope = tenant_scope("acme")?;
    let filter = ListFilter {
        asset: Some("host-1".to_owned()),
        requester: None,
        open_only: true,
    };
    let page = (backend.list)(scope.clone(), filter, None, PAGE).await?;
    assert_eq!((page.rows.len(), page.skipped), (1, 0));
    let row = page.rows.first().ok_or("no row")?;
    assert_eq!(row.recording_hash.as_deref(), Some(vec![1; HASH_LEN].as_slice()));
    assert_eq!(
        (row.opened_at, row.closed_at, row.recording_frames),
        (OPENED, Some(OPENED + 1), Some(FRAMES))
    );
    let found = (backend.get)(scope, "s-1".to_owned()).await?;
    assert_eq!(found.map(|stored| stored.session_id), Some("s-1".to_owned()));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert_eq!(bound.len(), BOUND_STATEMENTS, "{bound:?}");
    assert!(bound.iter().all(|entry| entry.starts_with("PARAMS acme|")), "{bound:?}");
    assert!(bound.iter().any(|entry| entry == "PARAMS acme|s-1"), "{bound:?}");
    assert!(bound.iter().any(|entry| entry.starts_with("PARAMS acme|host-1||")), "{bound:?}");
    assert!(LIST_SQL.contains("tenant = $1") && LIST_AFTER_SQL.contains("tenant = $1") && SESSION_SQL.contains("tenant = $1"));
    Ok(())
}


#[tokio::test]
async fn a_store_error_is_reduced_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(failing_handler(|| Reply::Error("42601"))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let scope = tenant_scope("acme")?;
    let listed = (backend.list)(scope.clone(), ListFilter::default(), None, PAGE).await;
    let found = (backend.get)(scope, "s-1".to_owned()).await;
    assert!(matches!(listed, Err(StoreError::Pg(PgError::Server { .. }))));
    assert!(matches!(found, Err(StoreError::Pg(PgError::Server { .. }))));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_dropped_connection_fails_and_an_empty_pool_is_busy_before_any_connection() -> Result<(), Box<dyn Error>> {
    let mut served = served(failing_handler(|| Reply::Drop)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let scope = tenant_scope("acme")?;
    assert!(matches!(
        (backend.list)(scope.clone(), ListFilter::default(), None, PAGE).await,
        Err(StoreError::Pg(_))
    ));
    assert!(matches!((backend.get)(scope.clone(), "s-1".to_owned()).await, Err(StoreError::Pg(_))));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    drain(&mut served.fake.passwords);
    let empty = pg_backend(Arc::clone(&served.engine), Arc::new(Semaphore::new(0)));
    let listed = (empty.list)(scope.clone(), ListFilter::default(), None, PAGE).await;
    let found = (empty.get)(scope, "s-1".to_owned()).await;
    assert!(matches!(listed, Err(StoreError::Lease(LeaseError::Busy))));
    assert!(matches!(found, Err(StoreError::Lease(LeaseError::Busy))));
    assert_eq!(drain(&mut served.fake.passwords).len(), 0);
    Ok(())
}


#[tokio::test]
async fn a_refused_request_opens_no_connection_and_a_good_one_opens_one() -> Result<(), Box<dyn Error>> {
    let mut served = served(session_handler(one_session)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let huge = "1".repeat(CURSOR_HUGE);
    let bad_queries = [
        query_of(Some("junk"), None),
        query_of(Some("100.-x"), None),
        query_of(Some(huge.as_str()), None),
        query_of(None, Some("0")),
        query_of(None, Some("201")),
        ListQuery {
            open: Some("1".to_owned()),
            ..ListQuery::default()
        },
        ListQuery {
            asset: Some("-bad".to_owned()),
            ..ListQuery::default()
        },
        ListQuery {
            requester: Some("a b".to_owned()),
            ..ListQuery::default()
        },
    ];
    for query in bad_queries {
        let response = list_flow(&identity(), &backend, Ok(query)).await;
        assert_eq!(response.status(), BAD_REQUEST);
    }
    assert_eq!(get_flow(&identity(), &backend, Some("-bad".to_owned())).await.status(), NOT_FOUND);
    assert_eq!(get_flow(&identity(), &backend, None).await.status(), NOT_FOUND);
    assert_eq!(drain(&mut served.fake.passwords).len(), 0);
    assert_eq!(drain(&mut served.fake.statements).len(), 0);
    assert_eq!(list_flow(&identity(), &backend, Ok(query_of(Some("100.s-1"), None))).await.status(), OK);
    assert_eq!(drain(&mut served.fake.passwords).len(), 1);
    assert_eq!(get_flow(&identity(), &backend, Some("s-1".to_owned())).await.status(), OK);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_hostile_stored_row_is_refused_alone() -> Result<(), Box<dyn Error>> {
    let served = served(session_handler(two_sessions_one_hostile)).await?;
    let backend = pg_backend(Arc::clone(&served.engine), Arc::new(Semaphore::new(MAX_CONNECTIONS)));
    let page = (backend.list)(tenant_scope("acme")?, ListFilter::default(), None, PAGE).await?;
    assert_eq!((page.rows.len(), page.skipped), (1, 1));
    Ok(())
}


fn mixed_reply() -> Reply {
    Reply::Typed {
        parameters: vec![TEXT_OID; FORCED_PARAMS],
        columns: vec![INT8_OID, INT8_OID, BYTEA_OID, BYTEA_OID, TEXT_OID, TEXT_OID, BOOL_OID],
        rows: vec![vec![
            int8_cell(OPENED),
            Some(vec![0; BAD_INT8_LEN]),
            Some(BYTES.to_vec()),
            None,
            text("ok"),
            Some(BAD_UTF8.to_vec()),
            Some(vec![1]),
        ]],
    }
}


#[tokio::test]
async fn every_cell_kind_decodes_and_an_undecodable_one_is_unreadable() -> Result<(), Box<dyn Error>> {
    let served = served(failing_handler(mixed_reply)).await?;
    let client = connect_current(&served.engine).await?;
    let statement = Statement {
        sql: "SELECT a, b, c, d, e, f, g FROM remote_shell_sessions WHERE tenant = $1",
        params: Vec::new(),
    };
    let rows = pg_execute(&client, Duration::from_secs(STATEMENT_TIMEOUT_SECS), tenant_scope("acme")?, statement).await?;
    let row = rows.first().ok_or("no row")?;
    assert_eq!(row.first(), Some(&Cell::Int(OPENED)));
    assert_eq!(row.get(1), Some(&Cell::Unreadable));
    assert_eq!(row.get(IDX_BYTES), Some(&Cell::Bytes(BYTES.to_vec())));
    assert_eq!(row.get(IDX_NULL), Some(&Cell::Null));
    assert_eq!(row.get(IDX_TEXT), Some(&Cell::Text("ok".to_owned())));
    assert_eq!(row.get(IDX_BAD_TEXT), Some(&Cell::Unreadable));
    assert_eq!(row.get(IDX_BOOL), Some(&Cell::Unreadable));
    Ok(())
}


#[test]
fn each_parameter_kind_is_bound() -> Result<(), Box<dyn Error>> {
    let params = [Param::Int(1), Param::Text("t".to_owned()), Param::Bool(true), Param::Bytes(vec![1])];
    assert_eq!(bound(&params).len(), params.len());
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
