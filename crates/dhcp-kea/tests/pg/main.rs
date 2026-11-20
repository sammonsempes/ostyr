mod types;


use alerts::backend::{lease, MAX_CONNECTIONS};
use alerts::error::StoreError;
use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_pg::error::PgError;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::{open_settings, PgSettings};
use dhcp_kea::backend::{lease_failure, pg_backend};
use dhcp_kea::error::HistoryError;
use dhcp_kea::history::{LookupResult, AT_SQL, MAC_SQL, MAX_LOOKUP_ROWS};
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use std::error::Error;
use std::io::sink;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Semaphore;
use types::TestResult;


const DRAIN_LIMIT: usize = 100;


const NOW: i64 = 1_700_000_000;


const DAY: i64 = 86_400;


const MAC_TEXT: &str = "AA-BB-CC-DD-EE-01";


const ADDRESS_NOT_EIGHT_BYTES: &str = "10.0.0.25";


const STATEMENT_TIMEOUT_SECS: u64 = 7;


const TWO_ROWS: usize = 2;


const SUBNET: i64 = 7;


const SUBNET_TEXT: &str = "7";


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub _dir: TempDir,
}


pub fn drain(receiver: &mut UnboundedReceiver<String>) -> Vec<String> {
    std::iter::repeat_with(|| receiver.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


pub fn lease_row(mac: &str, hostname: &str) -> Vec<String> {
    [
        ADDRESS_NOT_EIGHT_BYTES,
        mac,
        hostname,
        &(NOW - DAY).to_string(),
        &(NOW + DAY).to_string(),
        "lease-assigned",
        SUBNET_TEXT,
    ]
    .map(str::to_owned)
    .to_vec()
}


pub fn lookups_answer(rows: Vec<Vec<String>>, failure: Option<&'static str>, hang: bool, drop_session: bool) -> Handler {
    Arc::new(move |sql| {
        if drop_session && sql.starts_with("SET") {
            Reply::Drop
        } else if !sql.contains("FROM dhcp_lease_history") {
            Reply::Done
        } else if hang {
            Reply::Hang
        } else {
            failure.map_or_else(|| Reply::Rows(rows.clone()), Reply::Error)
        }
    })
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
        module: "dhcp".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served { engine, fake, _dir: dir })
}


pub fn scope() -> Result<TenantScope, Box<dyn Error>> {
    Ok(tenant_scope("acme")?)
}


pub async fn ask_at(served: &Served, permits: &Arc<Semaphore>) -> Result<LookupResult, HistoryError> {
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(permits));
    let tenant = tenant_scope("acme").map_err(|_bad| HistoryError::Answer)?;
    (backend.at)(tenant, ADDRESS_NOT_EIGHT_BYTES.to_owned(), NOW).await
}


pub async fn ask_mac(served: &Served, permits: &Arc<Semaphore>) -> Result<LookupResult, HistoryError> {
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(permits));
    let tenant = tenant_scope("acme").map_err(|_bad| HistoryError::Answer)?;
    (backend.by_mac)(tenant, MAC_TEXT.to_owned(), NOW - DAY, NOW + DAY).await
}


#[tokio::test]
async fn the_address_lookup_binds_the_tenant_and_decodes_rows_with_null_columns() -> TestResult {
    let rows = vec![lease_row(MAC_TEXT, "pc"), lease_row("", "")];
    let mut served = served(lookups_answer(rows, None, false, false)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let found = ask_at(&served, &permits).await?;
    assert_eq!(found.intervals.len(), TWO_ROWS);
    let first = found.intervals.first().ok_or("no first")?;
    assert_eq!(
        (first.mac.as_deref(), first.hostname.as_deref(), first.subnet_id),
        (Some(MAC_TEXT), Some("pc"), SUBNET)
    );
    let second = found.intervals.get(1).ok_or("no second")?;
    assert_eq!((second.mac.as_deref(), second.hostname.as_deref()), (None, None));
    assert_eq!((found.skipped, found.truncated), (0, false));
    let statements = drain(&mut served.fake.statements);
    let limit = MAX_LOOKUP_ROWS + 1;
    assert!(statements.iter().any(|entry| entry == AT_SQL), "{statements:?}");
    assert!(
        statements
            .iter()
            .any(|entry| *entry == format!("PARAMS acme|{ADDRESS_NOT_EIGHT_BYTES}|{NOW}|{limit}")),
        "{statements:?}"
    );
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn the_mac_lookup_binds_the_tenant_and_the_window_end() -> TestResult {
    let mut served = served(lookups_answer(vec![lease_row(MAC_TEXT, "pc")], None, false, false)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let found = ask_mac(&served, &permits).await?;
    assert_eq!(found.intervals.len(), 1);
    let statements = drain(&mut served.fake.statements);
    let limit = MAX_LOOKUP_ROWS + 1;
    let end = NOW + DAY;
    assert!(statements.iter().any(|entry| entry == MAC_SQL), "{statements:?}");
    assert!(
        statements.iter().any(|entry| *entry == format!("PARAMS acme|{MAC_TEXT}|{end}|{limit}")),
        "{statements:?}"
    );
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_store_error_is_a_pg_error_and_returns_the_permit() -> TestResult {
    let served = served(lookups_answer(vec![], Some("42601"), false, false)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let at = ask_at(&served, &permits).await.err().ok_or("answered")?;
    let by_mac = ask_mac(&served, &permits).await.err().ok_or("answered")?;
    assert!(matches!(at, HistoryError::Pg(_)), "{at}");
    assert!(matches!(by_mac, HistoryError::Pg(_)), "{by_mac}");
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_connection_dropped_at_the_session_setting_is_a_pg_error_and_returns_the_permit() -> TestResult {
    let served = served(lookups_answer(vec![], None, false, true)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let at = ask_at(&served, &permits).await.err().ok_or("answered")?;
    let by_mac = ask_mac(&served, &permits).await.err().ok_or("answered")?;
    assert!(matches!(at, HistoryError::Pg(_)) && matches!(by_mac, HistoryError::Pg(_)));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_refused_connection_is_a_pg_error_and_returns_the_permit() -> TestResult {
    let served = served(lookups_answer(vec![], None, false, false)).await?;
    write_secret(served._dir.path().join("pg.pass"), "wrong")?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let at = ask_at(&served, &permits).await.err().ok_or("answered")?;
    let by_mac = ask_mac(&served, &permits).await.err().ok_or("answered")?;
    assert!(matches!(at, HistoryError::Pg(_)) && matches!(by_mac, HistoryError::Pg(_)));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


pub async fn until_lookup(receiver: &mut UnboundedReceiver<String>) -> Result<(), Box<dyn Error>> {
    let mut seen = false;
    let mut attempts = 0;
    while !seen && attempts < DRAIN_LIMIT {
        seen = receiver.recv().await.ok_or("fake closed")?.contains("FROM dhcp_lease_history");
        attempts += 1;
    }
    seen.then_some(()).ok_or("the lookup never arrived".into())
}


pub async fn hung_lookup(by_mac: bool) -> Result<HistoryError, Box<dyn Error>> {
    let mut served = served(lookups_answer(vec![], None, true, false)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let request = if by_mac {
        (backend.by_mac)(scope()?, MAC_TEXT.to_owned(), NOW - DAY, NOW + DAY)
    } else {
        (backend.at)(scope()?, ADDRESS_NOT_EIGHT_BYTES.to_owned(), NOW)
    };
    let task = tokio::spawn(request);
    until_lookup(&mut served.fake.statements).await?;
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS - 1);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(STATEMENT_TIMEOUT_SECS + 1)).await;
    let error = task.await?.err().ok_or("answered")?;
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(error)
}


#[tokio::test]
async fn an_address_lookup_hang_ends_at_the_configured_statement_deadline_and_returns_the_permit() -> TestResult {
    let error = hung_lookup(false).await?;
    assert!(
        matches!(
            error,
            HistoryError::Pg(PgError::StatementTimeout {
                seconds: STATEMENT_TIMEOUT_SECS
            })
        ),
        "{error:?}"
    );
    Ok(())
}


#[tokio::test]
async fn a_mac_lookup_hang_ends_at_the_configured_statement_deadline_and_returns_the_permit() -> TestResult {
    let error = hung_lookup(true).await?;
    assert!(
        matches!(
            error,
            HistoryError::Pg(PgError::StatementTimeout {
                seconds: STATEMENT_TIMEOUT_SECS
            })
        ),
        "{error:?}"
    );
    Ok(())
}


#[tokio::test]
async fn a_request_dropped_while_its_statement_hangs_returns_the_permit_at_once() -> TestResult {
    let mut served = served(lookups_answer(vec![], None, true, false)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let task = tokio::spawn((backend.at)(scope()?, ADDRESS_NOT_EIGHT_BYTES.to_owned(), NOW));
    until_lookup(&mut served.fake.statements).await?;
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS - 1);
    task.abort();
    let outcome = task.await.err().ok_or("finished")?;
    assert!(outcome.is_cancelled());
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn no_permit_is_busy_before_any_connection() -> TestResult {
    let served = served(lookups_answer(vec![], None, false, false)).await?;
    let permits = Arc::new(Semaphore::new(0));
    assert!(matches!(ask_at(&served, &permits).await, Err(HistoryError::Busy)));
    assert!(matches!(ask_mac(&served, &permits).await, Err(HistoryError::Busy)));
    let refused = lease(&served.engine, &permits).await.err().ok_or("leased")?;
    assert!(matches!(refused, StoreError::Busy));
    Ok(())
}


#[test]
fn any_other_lease_failure_is_the_fixed_answer_error() -> TestResult {
    assert!(matches!(lease_failure(StoreError::TenantMismatch), HistoryError::Answer));
    assert!(matches!(lease_failure(StoreError::Busy), HistoryError::Busy));
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
