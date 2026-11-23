use alerts::backend::MAX_CONNECTIONS;
use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use core_pg::settings::{open_settings, PgSettings};
use hunt_packs::api_model::{FindingsQuery, FindingsReply};
use hunt_packs::backend::pg_backend;
use hunt_packs::error::FindingsError;
use hunt_packs::store::{FindingRow, StateError, LIST_SQL, OVERSIZED_SQL, STATEMENT_DEADLINE};
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, int8_cell, Fake, Mode, Reply, INT8_OID, TEXT_OID};
use pg_fake::types::Handler;
use rcgen::SanType;
use socket2::{Domain, Socket, Type};
use std::error::Error;
use std::io::sink;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Semaphore;
use tokio::time::timeout;


const DRAIN_LIMIT: usize = 100;


const PACK: &str = "lateral-movement";


const START: i64 = 100;


const END: i64 = 200;


const MATCHES: i64 = 7;


const BASELINE: i64 = 3;


const OVERSIZED: i64 = 4;


const PAGE_SIZE: i64 = 50;


const COLUMNS: usize = 5;


const HANG_MARGIN: Duration = Duration::from_secs(10);


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub _dir: TempDir,
    pub _closed: Option<Socket>,
}


pub fn text_cell(text: &str) -> Option<Vec<u8>> {
    Some(text.as_bytes().to_vec())
}


pub fn list_reply(wrong_column: Option<usize>) -> Reply {
    let mut columns = vec![TEXT_OID, INT8_OID, INT8_OID, INT8_OID, INT8_OID];
    if let Some(slot) = wrong_column.and_then(|index| columns.get_mut(index)) {
        *slot = if *slot == TEXT_OID { INT8_OID } else { TEXT_OID };
    }
    let row = vec![text_cell(PACK), int8_cell(START), int8_cell(END), int8_cell(MATCHES), int8_cell(BASELINE)];
    Reply::Typed {
        parameters: vec![TEXT_OID, INT8_OID, TEXT_OID, INT8_OID],
        columns,
        rows: vec![row],
    }
}


pub fn count_reply(column: i32) -> Reply {
    Reply::Typed {
        parameters: vec![TEXT_OID, INT8_OID],
        columns: vec![column],
        rows: vec![vec![int8_cell(OVERSIZED)]],
    }
}


pub fn answering(list: Reply, count: Reply) -> Handler {
    Arc::new(move |sql| {
        if sql == LIST_SQL {
            list.clone()
        } else if sql == OVERSIZED_SQL {
            count.clone()
        } else {
            Reply::Done
        }
    })
}


pub fn healthy() -> Handler {
    answering(list_reply(None), count_reply(INT8_OID))
}


pub fn settings_text(port: u16, password: &Path, ca: &Path) -> String {
    format!(
        "host: 127.0.0.1\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
        password.display(),
        ca.display()
    )
}


/// A bound, never listening socket: connections to it are refused and its port stays taken while it lives.
pub fn closed_socket() -> std::io::Result<(Socket, u16)> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.bind(&SocketAddr::from((loopback(), 0)).into())?;
    let port = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| std::io::Error::other("not an inet address"))?
        .port();
    Ok((socket, port))
}


pub async fn served_on(handler: Handler, dead_port: bool) -> Result<Served, Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), "p", handler).await?;
    let dir = tempdir()?;
    let password_file = dir.path().join("pg.pass");
    let ca_file = dir.path().join("ca.pem");
    write_secret(&password_file, "p")?;
    std::fs::write(&ca_file, &pki.ca_pem)?;
    let (closed, port) = if dead_port {
        closed_socket().map(|(socket, port)| (Some(socket), port))?
    } else {
        (None, fake.port)
    };
    let settings_file = dir.path().join("pg.yaml");
    std::fs::write(&settings_file, settings_text(port, &password_file, &ca_file))?;
    let log = genesis_log(sink());
    let context = ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "acme".to_owned(),
        module: "hunts".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served {
        engine,
        fake,
        _dir: dir,
        _closed: closed,
    })
}


pub async fn served(handler: Handler) -> Result<Served, Box<dyn Error>> {
    served_on(handler, false).await
}


pub fn drain(receiver: &mut UnboundedReceiver<String>) -> Vec<String> {
    std::iter::repeat_with(|| receiver.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


pub fn first_page() -> FindingsQuery {
    FindingsQuery {
        after: (-1, String::new()),
        size: PAGE_SIZE,
    }
}


pub async fn read_once(served: &Served, permits: &Arc<Semaphore>) -> Result<FindingsReply, FindingsError> {
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(permits));
    let scope = tenant_scope("acme").map_err(StateError::from)?;
    backend(scope, first_page()).await
}


pub fn pg_error(outcome: Result<FindingsReply, FindingsError>) -> Result<PgError, Box<dyn Error>> {
    match outcome {
        Err(FindingsError::Store(StateError::Pg(error))) => Ok(error),
        other => Err(format!("not a store error: {other:?}").into()),
    }
}


#[tokio::test]
async fn a_read_binds_the_tenant_first_and_decodes_the_rows() -> Result<(), Box<dyn Error>> {
    let mut served = served(healthy()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let reply = read_once(&served, &permits).await?;
    let expected = FindingRow {
        pack_id: PACK.to_owned(),
        window_start: START,
        window_end: END,
        matches: MATCHES,
        max_matches: BASELINE,
    };
    assert_eq!(reply.page.rows, vec![expected]);
    assert_eq!(reply.oversized, OVERSIZED);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert_eq!(bound, vec!["PARAMS acme|-1||50".to_owned(), "PARAMS acme|1001".to_owned()], "{bound:?}");
    Ok(())
}


#[tokio::test]
async fn a_store_error_is_reduced_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(answering(Reply::Error("42601"), count_reply(INT8_OID))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let error = pg_error(read_once(&served, &permits).await)?;
    assert!(matches!(error, PgError::Server { .. }), "{error}");
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_count_error_is_reduced_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(answering(list_reply(None), Reply::Error("42601"))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let error = pg_error(read_once(&served, &permits).await)?;
    assert!(matches!(error, PgError::Server { .. }), "{error}");
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_dropped_connection_is_a_store_error_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served(answering(Reply::Drop, count_reply(INT8_OID))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    pg_error(read_once(&served, &permits).await)?;
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_statement_that_hangs_hits_the_deadline_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let pausing: Handler = Arc::new(|sql| {
        if sql == LIST_SQL {
            tokio::time::pause();
            Reply::Hang
        } else {
            Reply::Done
        }
    });
    let served = served(pausing).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let outcome = timeout(STATEMENT_DEADLINE + HANG_MARGIN, read_once(&served, &permits)).await?;
    let error = pg_error(outcome)?;
    assert!(matches!(error, PgError::ClientDeadline { .. }), "{error}");
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_refused_connection_is_a_store_error_and_returns_the_permit() -> Result<(), Box<dyn Error>> {
    let served = served_on(healthy(), true).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    pg_error(read_once(&served, &permits).await)?;
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


pub async fn refused_column(column: usize) -> Result<(), Box<dyn Error>> {
    let served = served(answering(list_reply(Some(column)), count_reply(INT8_OID))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let error = pg_error(read_once(&served, &permits).await)?;
    assert!(matches!(error, PgError::Client(_)), "column {column}: {error}");
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_list_column_of_the_wrong_type_is_refused() -> Result<(), Box<dyn Error>> {
    for column in 0..COLUMNS {
        refused_column(column).await?;
    }
    Ok(())
}


#[tokio::test]
async fn a_count_column_of_the_wrong_type_is_refused() -> Result<(), Box<dyn Error>> {
    let served = served(answering(list_reply(None), count_reply(TEXT_OID))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let error = pg_error(read_once(&served, &permits).await)?;
    assert!(matches!(error, PgError::Client(_)), "{error}");
    Ok(())
}


#[tokio::test]
async fn an_empty_pool_is_busy_before_any_connection() -> Result<(), Box<dyn Error>> {
    let mut served = served(healthy()).await?;
    let permits = Arc::new(Semaphore::new(0));
    let refused = read_once(&served, &permits).await;
    assert!(matches!(refused, Err(FindingsError::Busy)), "{refused:?}");
    assert!(drain(&mut served.fake.statements).is_empty());
    assert_eq!(permits.available_permits(), 0);
    Ok(())
}


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


#[cfg(unix)]
fn write_secret(path: impl AsRef<Path>, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path.as_ref(), content)?;
    std::fs::set_permissions(path.as_ref(), std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))
}


#[cfg(not(unix))]
fn write_secret(path: impl AsRef<Path>, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path.as_ref(), content)
}
