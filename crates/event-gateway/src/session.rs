use crate::error::GatewayError;
use crate::model::{Gateway, GatewaySettings, Link, Session, MODULE};
use crate::types::ConnectionFields;
use async_nats::jetstream::context::ContextBuilder;
use async_nats::jetstream::Context;
use async_nats::{Client, ConnectOptions};
use core_config::reload::{current_config, ReloadEngine};
use siem_ingest::error::NatsError;
use siem_ingest::nats::{bounded, mark_dropped, millis, read_bounded, tls_config, MAX_NATS_FILE_BYTES};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::warn;


/// Largest left shift of the backoff, so the doubling cannot overflow.
pub const MAX_BACKOFF_SHIFT: u32 = 20;


pub const BACKOFF_FACTOR: u64 = 2;


/// Connection options from one settings snapshot: files are read once, bounded, and the credentials never leave this function.
pub fn connect_options(settings: &GatewaySettings, dropped: Arc<AtomicBool>) -> Result<ConnectOptions, NatsError> {
    let tls = settings
        .nats_ca_file
        .as_deref()
        .map(|path| read_bounded(path, "CA", MAX_NATS_FILE_BYTES).and_then(|pem| tls_config(&pem)))
        .transpose()?;
    let credentials = settings
        .nats_credentials_file
        .as_deref()
        .map(|path| read_bounded(path, "credentials", MAX_NATS_FILE_BYTES))
        .transpose()?;
    let password = settings
        .nats_password_file
        .as_deref()
        .map(|path| read_bounded(path, "password", MAX_NATS_FILE_BYTES))
        .transpose()?;
    let base = ConnectOptions::new()
        .name(MODULE)
        .ping_interval(millis(settings.ping_interval_ms))
        .connection_timeout(millis(settings.connect_timeout_ms))
        .request_timeout(Some(millis(settings.publish_timeout_ms)))
        .ignore_discovered_servers()
        .event_callback(move |event| {
            let flag = Arc::clone(&dropped);
            async move { mark_dropped(&flag, &event) }
        });
    let first = if settings.nats_tls_first { base.tls_first() } else { base };
    let trusted = match tls {
        Some(config) => first.tls_client_config(config),
        None => first,
    };
    let authenticated = match (settings.nats_user.as_ref(), password) {
        (Some(user), Some(bytes)) => trusted.user_and_password(user.clone(), String::from_utf8_lossy(&bytes).trim_end().to_owned()),
        _ => trusted,
    };
    match credentials {
        Some(bytes) => authenticated
            .credentials(&String::from_utf8_lossy(&bytes))
            .map_err(NatsError::Credentials),
        None => Ok(authenticated),
    }
}


/// Connects under the connect deadline; the JetStream confirmation of a publish waits at most `publish_timeout_ms`.
pub async fn open_session(settings: &Arc<GatewaySettings>) -> Result<Session, GatewayError> {
    let dropped = Arc::new(AtomicBool::new(false));
    let options = connect_options(settings, Arc::clone(&dropped))?;
    let client = bounded(millis(settings.connect_timeout_ms), options.connect(settings.nats_url.as_str())).await?;
    let jetstream = ContextBuilder::new().timeout(millis(settings.publish_timeout_ms)).build(client.clone());
    Ok(Session {
        client,
        jetstream,
        dropped,
        settings: Arc::clone(settings),
    })
}


/// Every setting a connection is built from.
pub fn connection_fields(settings: &GatewaySettings) -> ConnectionFields<'_> {
    (
        (
            settings.nats_url.as_str(),
            settings.nats_tls_first,
            settings.nats_ca_file.as_deref(),
            settings.nats_credentials_file.as_deref(),
            settings.nats_user.as_deref(),
            settings.nats_password_file.as_deref(),
        ),
        (settings.connect_timeout_ms, settings.publish_timeout_ms, settings.ping_interval_ms),
    )
}


/// A change of any connection setting, or a dropped connection, makes the live session stale.
pub fn is_fresh(session: &Session, settings: &GatewaySettings) -> bool {
    !session.dropped.load(Ordering::SeqCst) && connection_fields(&session.settings) == connection_fields(settings)
}


/// Doubles from the initial delay with each failure, up to the ceiling.
pub fn backoff_delay(settings: &GatewaySettings, failures: u32) -> Duration {
    let doubled = settings
        .backoff_initial_ms
        .saturating_mul(BACKOFF_FACTOR.saturating_pow(failures.saturating_sub(1).min(MAX_BACKOFF_SHIFT)));
    millis(doubled.min(settings.backoff_max_ms))
}


/// Opens a session unless the last failure is still inside its backoff; records the outcome for the next caller.
pub async fn connect_or_back_off(link: &mut Link, settings: &Arc<GatewaySettings>) -> Result<Session, GatewayError> {
    let now = Instant::now();
    if link.retry_at.is_some_and(|at| now < at) {
        Err(GatewayError::BackingOff)
    } else {
        let opened = open_session(settings).await;
        match &opened {
            Ok(_) => {
                link.failures = 0;
                link.retry_at = None;
            }
            Err(_) => {
                link.failures = link.failures.saturating_add(1);
                link.retry_at = Some(now + backoff_delay(settings, link.failures));
                warn!(failures = link.failures, "the NATS connection failed, backing off");
            }
        }
        opened
    }
}


/// The live session handles, or a new session; a stale one is dropped first. The lock is held only here, never while publishing.
pub async fn session_for(gateway: &Gateway, settings: &Arc<GatewaySettings>) -> Result<(Client, Context), GatewayError> {
    let mut link = gateway.link.lock().await;
    let kept = link.session.take().filter(|session| is_fresh(session, settings));
    let session = match kept {
        Some(live) => live,
        None => connect_or_back_off(&mut link, settings).await?,
    };
    let handles = (session.client.clone(), session.jetstream.clone());
    link.session = Some(session);
    Ok(handles)
}


pub fn new_gateway(settings: Arc<ReloadEngine<GatewaySettings>>) -> Gateway {
    Gateway {
        settings,
        link: Mutex::new(Link::default()),
        in_flight: Arc::new(AtomicUsize::new(0)),
    }
}


pub fn settings_of(gateway: &Gateway) -> Arc<GatewaySettings> {
    current_config(&gateway.settings)
}
