#[path = "../../../cmdb/tests/pg/certs.rs"]
mod certs;
#[path = "../../../cmdb/tests/pg/fake.rs"]
mod fake;
mod types;


use alerts::backend::{lease, MAX_CONNECTIONS};
use alerts::error::StoreError as LeaseError;
use certs::{loopback, make_pki};
use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_pg::scope::tenant_scope;
use core_pg::settings::{open_settings, PgSettings};
use fake::{Fake, Mode, Reply};
use rcgen::SanType;
use risk_score::backend::pg_backend;
use risk_score::error::RiskError;
use risk_score::model::{EntityKind, SeverityPoints, Weights};
use std::error::Error;
use std::io::sink;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Semaphore;
use types::{Handler, Running};


const NOW: i64 = 1_800_000_000;


const MICROS: i64 = 1_000_000;


const AGE_SECONDS: i64 = 100;


const DRAIN_LIMIT: usize = 100;


pub fn query_handler(reply: Reply) -> Handler {
    Arc::new(move |sql| if sql.contains("FROM alerts") { reply.clone() } else { Reply::Done })
}


const HANG_DETECTOR: Duration = Duration::from_secs(120);


const STATEMENT_SECONDS: u64 = 30;


pub async fn until_alerts_query(statements: &mut UnboundedReceiver<String>) -> Result<(), Box<dyn Error>> {
    let mut seen = false;
    for _ in 0..DRAIN_LIMIT {
        if !seen {
            seen = statements.recv().await.ok_or("fake closed")?.contains("FROM alerts");
        }
    }
    Ok(())
}


pub async fn hanging_computation(served: &mut Served, permits: &Arc<Semaphore>) -> Result<Running, Box<dyn Error>> {
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(permits));
    let task = tokio::spawn(backend(tenant_scope("acme")?, Arc::new(weights()), NOW));
    until_alerts_query(&mut served.fake.statements).await?;
    Ok(task)
}


#[tokio::test]
async fn a_dropped_computation_cancels_its_query_and_then_returns_its_permit() -> Result<(), Box<dyn Error>> {
    let mut served = served(query_handler(Reply::Hang)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let task = hanging_computation(&mut served, &permits).await?;
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS - 1);
    task.abort();
    assert!(task.await.is_err());
    let all = u32::try_from(MAX_CONNECTIONS)?;
    tokio::time::timeout(HANG_DETECTOR, permits.acquire_many(all)).await??.forget();
    Ok(())
}


#[tokio::test]
async fn a_failed_cancel_keeps_the_permit_for_the_statement_deadline() -> Result<(), Box<dyn Error>> {
    let mut served = served(query_handler(Reply::Hang)).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let task = hanging_computation(&mut served, &permits).await?;
    std::fs::remove_file(served._dir.path().join("ca.pem"))?;
    tokio::time::pause();
    task.abort();
    assert!(task.await.is_err());
    for _ in 0..DRAIN_LIMIT {
        tokio::task::yield_now().await;
    }
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS - 1);
    tokio::time::advance(Duration::from_secs(STATEMENT_SECONDS + 1)).await;
    for _ in 0..DRAIN_LIMIT {
        tokio::task::yield_now().await;
    }
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    Ok(())
}


#[tokio::test]
async fn a_failed_computation_still_cancels_before_it_returns_its_permit() -> Result<(), Box<dyn Error>> {
    let served = served(query_handler(Reply::Error("XX000"))).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let result = backend(tenant_scope("acme")?, Arc::new(weights()), NOW).await;
    assert!(matches!(result, Err(RiskError::Store(_))));
    let all = u32::try_from(MAX_CONNECTIONS)?;
    tokio::time::timeout(HANG_DETECTOR, permits.acquire_many(all)).await??.forget();
    Ok(())
}


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


const SEVERITY_POINTS: u32 = 10;


const FULL_SCORE_POINTS: u32 = 100;


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub _dir: TempDir,
}


pub fn alert_handler() -> Handler {
    let created = ((NOW - AGE_SECONDS) * MICROS).to_string();
    Arc::new(move |sql| {
        if sql.contains("FROM alerts") {
            Reply::Rows(vec![["a1", "rule-1", "high", created.as_str(), "web01", "alice"]
                .map(str::to_owned)
                .to_vec()])
        } else {
            Reply::Done
        }
    })
}


pub fn weights() -> Weights {
    Weights {
        severity_points: SeverityPoints {
            low: 1,
            medium: 1,
            high: SEVERITY_POINTS,
            critical: SEVERITY_POINTS,
        },
        rare_threshold_per_million: 0,
        entity_rare_bonus_permille: 0,
        fleet_rare_bonus_permille: 0,
        full_score_points: FULL_SCORE_POINTS,
    }
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
        module: "risk".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served { engine, fake, _dir: dir })
}


#[tokio::test]
async fn the_pg_backend_scores_the_tenant_through_a_leased_connection() -> Result<(), Box<dyn Error>> {
    let mut served = served(alert_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let outcome = backend(tenant_scope("acme")?, Arc::new(weights()), NOW).await?;
    assert_eq!(outcome.alerts_read, 1);
    let kinds: Vec<EntityKind> = outcome.scores.iter().map(|score| score.entity.kind).collect();
    assert_eq!(kinds, [EntityKind::User, EntityKind::Host]);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert!(
        !bound.is_empty() && bound.iter().all(|entry| entry.starts_with("PARAMS acme|")),
        "{bound:?}"
    );
    Ok(())
}


#[tokio::test]
async fn a_full_pool_is_busy_before_any_connection() -> Result<(), Box<dyn Error>> {
    let served = served(alert_handler()).await?;
    let permits = Arc::new(Semaphore::new(0));
    let refused = lease(&served.engine, &permits).await.err().ok_or("leased")?;
    assert!(matches!(refused, LeaseError::Busy));
    let backend = pg_backend(Arc::clone(&served.engine), permits);
    let result = backend(tenant_scope("acme")?, Arc::new(weights()), NOW).await;
    assert!(matches!(result, Err(RiskError::Store(LeaseError::Busy))));
    Ok(())
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
