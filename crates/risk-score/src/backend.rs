use crate::error::RiskError;
use crate::model::Weights;
use crate::source::{tenant_scores, Limits, Outcome, MICROS_PER_SECOND};
use crate::types::{ComputeFn, NowFn};
use alerts::backend::unix_micros;
use alerts::error::StoreError;
use alerts::model::Lease;
use alerts::pg::pg_executor;
use core_config::reload::{current_config, ReloadEngine};
use core_pg::connect::connect;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use core_pg::tls::client_config;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};
use tokio_postgres_rustls::MakeRustlsConnect;


pub const ACTOR: &str = "risk-score";


pub fn system_now() -> i64 {
    (unix_micros() / MICROS_PER_SECOND).cast_signed()
}


pub fn system_clock() -> NowFn {
    Arc::new(system_now)
}


/// The connection of one computation: while `armed`, dropping it cancels the running query and keeps the permit until that is over.
pub struct Session {
    pub lease: Arc<Lease>,
    pub settings: Arc<PgSettings>,
    pub armed: bool,
    pub handle: Handle,
}


impl Drop for Session {
    fn drop(&mut self) {
        if self.armed {
            self.handle.spawn(cancel_and_release(Arc::clone(&self.lease), Arc::clone(&self.settings)));
        }
    }
}


/// A separate connection with the settings and TLS of the client, under the same connect timeout; true when the server took the request.
pub async fn cancel_query(lease: &Lease, settings: &PgSettings) -> bool {
    let tls = client_config(Path::new(&settings.ca_file)).map(MakeRustlsConnect::new);
    match tls {
        Ok(connector) => {
            let attempt = timeout(
                Duration::from_secs(settings.connect_timeout_secs),
                lease.client.cancel_token().cancel_query(connector),
            )
            .await;
            attempt.is_ok_and(|sent| sent.is_ok())
        }
        Err(_unreadable) => false,
    }
}


/// The permit and the session are released only once the query is cancelled, else after the statement deadline that bounds it.
pub async fn cancel_and_release(lease: Arc<Lease>, settings: Arc<PgSettings>) {
    if !cancel_query(&lease, &settings).await {
        tracing::warn!("risk query cancel failed, the permit is held for the statement deadline");
        sleep(lease.deadline).await;
    }
}


pub async fn read_scores(lease: &Lease, scope: TenantScope, weights: Arc<Weights>, now: i64) -> Result<Outcome, RiskError> {
    let executor = pg_executor(&lease.client, lease.deadline);
    tenant_scores(&executor, &scope, &weights, now, &Limits::default()).await
}


/// One connection for the whole computation, a permit per running computation (else `Busy`), one settings snapshot for connect and cancel.
pub async fn pg_compute(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    weights: Arc<Weights>,
    now: i64,
) -> Result<Outcome, RiskError> {
    let permit = Arc::clone(&permits).try_acquire_owned().map_err(|_closed_or_full| StoreError::Busy)?;
    let settings = current_config(&engine);
    let client = connect(&settings).await.map_err(StoreError::from)?;
    let deadline = Duration::from_secs(settings.statement_timeout_secs);
    let lease = Arc::new(Lease { client, deadline, permit });
    let mut session = Session {
        lease: Arc::clone(&lease),
        settings,
        armed: true,
        handle: Handle::current(),
    };
    let outcome = read_scores(&lease, scope, weights, now).await;
    session.armed = outcome.is_err();
    outcome
}


pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> ComputeFn {
    Arc::new(move |scope, weights, now| Box::pin(pg_compute(Arc::clone(&engine), Arc::clone(&permits), scope, weights, now)))
}
