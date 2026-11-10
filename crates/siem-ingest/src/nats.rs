use crate::error::NatsError;
use crate::model::{AckAction, Delivery, Link, Session, Wiring};
use crate::parse::truncate_reason;
use crate::settings::{IngestSettings, MODULE};
use crate::tenant::EVENTS_SUBJECT_PREFIX;
use crate::types::{AckToken, ConnectionFields};
use async_nats::jetstream::consumer::{pull, AckPolicy};
use async_nats::jetstream::{self, AckKind};
use async_nats::Event;
use async_nats::{ConnectOptions, HeaderMap};
use bytes::Bytes;
use core_config::reload::{current_config, ReloadEngine};
use core_config::types::BoxError;
use futures_util::future::try_join_all;
use futures_util::{StreamExt, TryStreamExt};
use rustls::crypto::ring::default_provider;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use std::collections::HashMap;
use std::fs::File;
use std::future::Future;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::runtime::Builder;
use tracing::warn;


pub const MAX_NATS_FILE_BYTES: u64 = 65_536;


pub const RUNTIME_WORKERS: usize = 1;


pub const TENANT_HEADER: &str = "Ostyr-Tenant";


pub const REASON_HEADER: &str = "Ostyr-Reason";


pub const FIRST_TOKEN: AckToken = 1;


/// At most `cap` bytes of a file: a longer one is refused, and the content never reaches an error text.
pub fn read_bounded(path: &Path, what: &'static str, cap: u64) -> Result<Vec<u8>, NatsError> {
    let mut content = Vec::new();
    File::open(path)
        .and_then(|file| file.take(cap + 1).read_to_end(&mut content))
        .map_err(|source| NatsError::File { what, source })?;
    if content.len() as u64 > cap {
        Err(NatsError::FileTooLarge { what })
    } else {
        Ok(content)
    }
}


/// Trusts only the certificates of the CA file, through the same bytes that were read and bounded.
pub fn tls_config(pem: &[u8]) -> Result<ClientConfig, NatsError> {
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(NatsError::CaInvalid)?;
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certificates);
    if added == 0 {
        Err(NatsError::CaEmpty)
    } else {
        ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
            .map_err(NatsError::Tls)
    }
}


/// Runs a request under a deadline; the cause of a failure stays in the source chain.
pub async fn bounded<Output, Failure, Pending>(limit: Duration, pending: Pending) -> Result<Output, NatsError>
where
    Failure: Into<BoxError>,
    Pending: Future<Output = Result<Output, Failure>>,
{
    tokio::time::timeout(limit, pending)
        .await
        .map_err(NatsError::Timeout)?
        .map_err(|failure| NatsError::Request(failure.into()))
}


pub fn millis(value: u64) -> Duration {
    Duration::from_millis(value)
}


/// Connection options from one settings snapshot: files are read once, bounded, and the credentials never leave this function's callees.
pub fn connect_options(settings: &IngestSettings, dropped: Arc<AtomicBool>) -> Result<ConnectOptions, NatsError> {
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
        .ping_interval(millis(settings.nats_ping_interval_ms))
        .connection_timeout(millis(settings.nats_request_timeout_ms))
        .request_timeout(Some(millis(settings.nats_request_timeout_ms)))
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


/// A server that accepts payloads above `max_batch_bytes` could send a message the pull request's byte bound can never deliver.
pub fn check_payload_limit(server: usize, cap: usize) -> Result<(), NatsError> {
    if server > cap {
        Err(NatsError::PayloadLimit { server, cap })
    } else {
        Ok(())
    }
}


/// Durable, explicit acknowledgement, on the events subjects only.
pub fn consumer_config(settings: &IngestSettings) -> pull::Config {
    pull::Config {
        durable_name: Some(settings.nats_consumer.clone()),
        ack_policy: AckPolicy::Explicit,
        ack_wait: millis(settings.nats_ack_wait_ms),
        filter_subject: format!("{EVENTS_SUBJECT_PREFIX}.>"),
        ..Default::default()
    }
}


/// The client reconnects by itself with the options it was built with: a disconnect marks the session stale, so the next fetch rebuilds it from fresh settings.
pub fn mark_dropped(flag: &AtomicBool, event: &Event) {
    if *event == Event::Disconnected {
        flag.store(true, Ordering::SeqCst);
    }
}


pub async fn open_session(settings: &Arc<IngestSettings>) -> Result<Session, NatsError> {
    let dropped = Arc::new(AtomicBool::new(false));
    let options = connect_options(settings, Arc::clone(&dropped))?;
    let client = bounded(millis(settings.nats_request_timeout_ms), options.connect(settings.nats_url.as_str())).await?;
    check_payload_limit(client.max_payload(), settings.max_batch_bytes)?;
    let context = jetstream::new(client.clone());
    let creation = context.create_consumer_on_stream(consumer_config(settings), settings.nats_stream.clone());
    let consumer = bounded(millis(settings.nats_request_timeout_ms), creation).await?;
    Ok(Session {
        client,
        jetstream: context,
        consumer,
        held: HashMap::new(),
        dropped,
        settings: Arc::clone(settings),
    })
}


/// Every setting a connection, a consumer or a pull request is built from; a change makes the live session stale.
pub fn connection_fields(settings: &IngestSettings) -> ConnectionFields<'_> {
    (
        (
            settings.nats_url.as_str(),
            settings.nats_tls_first,
            settings.nats_ca_file.as_deref(),
            settings.nats_credentials_file.as_deref(),
            settings.nats_user.as_deref(),
            settings.nats_password_file.as_deref(),
        ),
        (
            settings.nats_stream.as_str(),
            settings.nats_consumer.as_str(),
            settings.nats_ack_wait_ms,
            settings.nats_ping_interval_ms,
            settings.nats_request_timeout_ms,
            settings.max_batch_bytes,
        ),
    )
}


pub fn is_fresh(session: &Session, settings: &IngestSettings) -> bool {
    !session.dropped.load(Ordering::SeqCst) && connection_fields(&session.settings) == connection_fields(settings)
}


pub fn log_release(outcome: Result<(), NatsError>) {
    if let Err(error) = outcome {
        warn!(error = %truncate_reason(&error.to_string()), "a message of a replaced session could not be released");
    }
}


/// Naks what a replaced session holds so the server redelivers at once, then flushes; a failure is logged, a dropped connection is skipped.
pub async fn release_held(session: Session) {
    let timeout = millis(session.settings.nats_request_timeout_ms);
    let reachable = !session.dropped.load(Ordering::SeqCst);
    for message in session.held.values().filter(|_| reachable) {
        log_release(bounded(timeout, message.ack_with(AckKind::Nak(None))).await);
    }
    if reachable {
        log_release(bounded(timeout, session.client.flush()).await);
    }
}


/// One pull request bounded by messages and bytes; the server ends it at the expiry, the guard covers a server that never answers.
pub async fn collect_batch(session: &Session, settings: &IngestSettings, max: usize) -> Result<Vec<jetstream::Message>, BoxError> {
    let batch = session
        .consumer
        .batch()
        .max_messages(max)
        .max_bytes(settings.max_batch_bytes)
        .expires(millis(settings.nats_fetch_deadline_ms))
        .messages()
        .await?;
    batch.take(max).try_collect().await
}


pub async fn pull_messages(session: &Session, settings: &IngestSettings, max: usize) -> Result<Vec<jetstream::Message>, NatsError> {
    let guard = millis(settings.nats_fetch_deadline_ms + settings.nats_request_timeout_ms);
    bounded(guard, collect_batch(session, settings, max)).await
}


/// Header values of a message: the map is name to list of values, and the cap bounds the values.
pub fn header_values(message: &jetstream::Message) -> usize {
    message
        .headers
        .as_ref()
        .map_or(0, |headers| headers.iter().map(|(_, values)| values.len()).sum())
}


/// A message with more headers than the cap is split off to be terminated, the rest become deliveries with a session token each.
pub fn admit_messages(
    session: &mut Session,
    counter: &AtomicU64,
    messages: Vec<jetstream::Message>,
    max_headers: usize,
) -> (Vec<Delivery>, Vec<jetstream::Message>) {
    let (usable, refused): (Vec<_>, Vec<_>) = messages.into_iter().partition(|message| header_values(message) <= max_headers);
    let deliveries = usable
        .into_iter()
        .map(|message| {
            let token = counter.fetch_add(1, Ordering::SeqCst);
            let delivery = Delivery {
                subject: message.subject.to_string(),
                payload: message.payload.to_vec(),
                token,
            };
            session.held.insert(token, message);
            delivery
        })
        .collect();
    (deliveries, refused)
}


/// Terminates a message the adapter refuses; a failure is logged and the server redelivers after the ack wait.
pub async fn terminate(message: &jetstream::Message, settings: &IngestSettings) {
    let outcome = bounded(millis(settings.nats_request_timeout_ms), message.ack_with(AckKind::Term)).await;
    if let Err(error) = outcome {
        warn!(error = %truncate_reason(&error.to_string()), "a refused message could not be terminated");
    }
}


pub async fn pull_deliveries(session: &mut Session, counter: &AtomicU64, settings: &IngestSettings, max: usize) -> Result<Vec<Delivery>, NatsError> {
    let messages = pull_messages(session, settings, max).await?;
    let (deliveries, refused) = admit_messages(session, counter, messages, settings.nats_max_headers);
    warn_refused(refused.len());
    for message in &refused {
        terminate(message, settings).await;
    }
    Ok(deliveries)
}


pub fn warn_refused(count: usize) {
    if count > 0 {
        warn!(count, "messages with too many headers were terminated");
    }
}


/// Keeps a live session, else opens one; the token counter lives in the link so tokens never repeat across sessions.
pub async fn fetch_in(
    slot: &mut Option<Session>,
    counter: &AtomicU64,
    settings: &Arc<IngestSettings>,
    max: usize,
) -> Result<Vec<Delivery>, NatsError> {
    let (live, stale): (Vec<Session>, Vec<Session>) = slot.take().into_iter().partition(|session| is_fresh(session, settings));
    for old in stale {
        release_held(old).await;
    }
    let mut session = match live.into_iter().next() {
        Some(kept) => kept,
        None => open_session(settings).await?,
    };
    let outcome = pull_deliveries(&mut session, counter, settings, max).await;
    if outcome.is_ok() {
        *slot = Some(session);
    }
    outcome
}


pub fn lock_session(link: &Link) -> MutexGuard<'_, Option<Session>> {
    link.session.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn fetch_batch(link: &Link, max: usize) -> Result<Vec<Delivery>, BoxError> {
    let mut slot = lock_session(link);
    let settings = current_config(&link.settings);
    let outcome = link.runtime.block_on(fetch_in(&mut slot, &link.next_token, &settings, max));
    outcome.map_err(BoxError::from)
}


pub async fn settle_token(slot: &mut Option<Session>, settings: &IngestSettings, token: AckToken, action: AckAction) -> Result<(), NatsError> {
    let session = slot.as_mut().ok_or(NatsError::NotConnected)?;
    let message = session.held.remove(&token).ok_or(NatsError::UnknownToken)?;
    let kind = match action {
        AckAction::Ack => AckKind::Ack,
        AckAction::Nak => AckKind::Nak(None),
    };
    bounded(millis(settings.nats_request_timeout_ms), message.ack_with(kind)).await
}


/// Sends an in-progress acknowledgement (`+WPI`) for every message still held, which restarts the server's `ack_wait` timer for it.
pub async fn progress_in(slot: &Option<Session>, settings: &IngestSettings) -> Result<usize, NatsError> {
    let session = slot.as_ref().ok_or(NatsError::NotConnected)?;
    let limit = millis(settings.nats_request_timeout_ms);
    try_join_all(session.held.values().map(|message| bounded(limit, message.ack_with(AckKind::Progress))))
        .await
        .map(|sent| sent.len())
}


pub fn report_progress(link: &Link) -> Result<(), BoxError> {
    let slot = lock_session(link);
    let settings = current_config(&link.settings);
    let outcome = link.runtime.block_on(progress_in(&slot, &settings));
    outcome.map(drop).map_err(BoxError::from)
}


pub fn acknowledge(link: &Link, token: AckToken, action: AckAction) -> Result<(), BoxError> {
    let mut slot = lock_session(link);
    let settings = current_config(&link.settings);
    let outcome = link.runtime.block_on(settle_token(&mut slot, &settings, token, action));
    outcome.map_err(BoxError::from)
}


pub fn dead_letter_headers(tenant: &str, reason: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(TENANT_HEADER, tenant);
    headers.insert(REASON_HEADER, reason);
    headers
}


/// Published with a confirmation from the stream: without it the caller naks, so a lost dead letter is never acknowledged.
pub async fn publish_in(slot: &Option<Session>, settings: &IngestSettings, (tenant, payload, reason): (&str, &[u8], &str)) -> Result<(), NatsError> {
    let session = slot.as_ref().ok_or(NatsError::NotConnected)?;
    let headers = dead_letter_headers(tenant, reason);
    let subject = settings.nats_dead_letter_subject.clone();
    let body = Bytes::copy_from_slice(payload);
    let confirmed = async { session.jetstream.publish_with_headers(subject, headers, body).await?.await };
    bounded(millis(settings.nats_request_timeout_ms), confirmed).await.map(|_| ())
}


pub fn publish_dead_letter(link: &Link, tenant: &str, payload: &[u8], reason: &str) -> Result<(), BoxError> {
    let slot = lock_session(link);
    let settings = current_config(&link.settings);
    let outcome = link.runtime.block_on(publish_in(&slot, &settings, (tenant, payload, reason)));
    outcome.map_err(BoxError::from)
}


/// The three closures of the pipeline over one lazily opened session; nothing connects until the first fetch, so a down server backs off in the loop.
pub fn nats_wiring(settings: Arc<ReloadEngine<IngestSettings>>) -> Result<Wiring, NatsError> {
    let runtime = Builder::new_multi_thread()
        .worker_threads(RUNTIME_WORKERS)
        .enable_all()
        .build()
        .map_err(NatsError::Runtime)?;
    let link = Arc::new(Link {
        runtime,
        settings,
        session: Mutex::new(None),
        next_token: AtomicU64::new(FIRST_TOKEN),
    });
    let fetch_link = Arc::clone(&link);
    let ack_link = Arc::clone(&link);
    let progress_link = Arc::clone(&link);
    let dead_link = link;
    Ok(Wiring {
        fetch: Box::new(move |max| fetch_batch(&fetch_link, max)),
        ack: Box::new(move |token, action| acknowledge(&ack_link, token, action)),
        dead_letter: Box::new(move |tenant, payload, reason| publish_dead_letter(&dead_link, tenant, payload, reason)),
        progress: Arc::new(move || report_progress(&progress_link)),
    })
}
