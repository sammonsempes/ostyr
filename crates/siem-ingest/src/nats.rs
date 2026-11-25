use crate::error::{without_peer_text, NatsError};
use crate::model::{AckAction, Collected, Delivery, Link, PullCounts, Pulled, Session, Wiring};
use crate::parse::truncate_reason;
use crate::settings::{IngestSettings, MODULE};
use crate::tenant::{dead_letter_token, EVENTS_SUBJECT_PREFIX};
use crate::types::{AckToken, ConnectionFields};
use async_nats::jetstream::consumer::pull::Batch;
use async_nats::jetstream::consumer::{self, pull, AckPolicy};
use async_nats::jetstream::{self, AckKind};
use async_nats::Event;
use async_nats::{ConnectOptions, HeaderMap};
use bytes::Bytes;
use core_config::reload::{current_config, ReloadEngine};
use core_config::secret_file::{open_secret, SecretFileError};
use core_config::types::BoxError;
use futures_util::future::try_join_all;
use futures_util::StreamExt;
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


pub const ORIGINAL_BYTES_HEADER: &str = "Ostyr-Original-Bytes";


pub const TRUNCATED_HEADER: &str = "Ostyr-Truncated";


pub const PAYLOAD_LIMIT_VARIANT: &str = "PayloadLimit";


/// A dead-letter body is cut here; the stream's `--max-msg-size` (lab `DEAD_MAX_MSG_SIZE`, 8192) leaves 4 KiB for the headers.
pub const MAX_DEAD_LETTER_BODY_BYTES: usize = 4096;


pub const MESSAGE_ID_HEADER: &str = "Nats-Msg-Id";


pub const FIRST_TOKEN: AckToken = 1;


/// Subject, reply subject and header framing the server counts against a pull's `max_bytes` on top of `max_payload` (derived in the crate notes).
pub const PULL_OVERHEAD_BYTES: usize = 1024;


/// async-nats reads a `max_bytes` of 0 as no byte limit in the request.
pub const NO_BYTE_LIMIT: usize = 0;


pub const HEAD_PULL_MESSAGES: usize = 1;


/// The status the server ends a pull with when the next message would pass its `max_bytes`, as async-nats words it in the error item.
pub const BYTE_CAP_STATUS: &str = ": 409, ";


pub const BYTE_CAP_DESCRIPTION: &str = "Message Size Exceeds MaxBytes";


pub const INBOX_PREFIX: &str = "_INBOX_";


pub const JS_EVENTS_PREFIX: &str = "JS.EVENTS.API";


/// The reply-subject prefix of one NATS user: a service subscribes only to its own, so no service reads another's replies.
pub fn inbox_prefix(user: &str) -> String {
    format!("{INBOX_PREFIX}{user}")
}


/// An authenticated connection gets its user's inbox prefix; one without a user keeps the default.
pub fn with_inbox(options: ConnectOptions, user: Option<&str>) -> ConnectOptions {
    match user {
        Some(name) => options.custom_inbox_prefix(inbox_prefix(name)),
        None => options,
    }
}


/// At most `cap` bytes of a reader: a longer one is refused, and the content never reaches an error text.
pub fn read_capped<Source: Read>(reader: Source, what: &'static str, cap: u64) -> Result<Vec<u8>, NatsError> {
    let mut content = Vec::new();
    reader
        .take(cap + 1)
        .read_to_end(&mut content)
        .map_err(|source| NatsError::File { what, source })?;
    if content.len() as u64 > cap {
        Err(NatsError::FileTooLarge { what })
    } else {
        Ok(content)
    }
}


/// At most `cap` bytes of a non-secret file (the CA).
pub fn read_bounded(path: &Path, what: &'static str, cap: u64) -> Result<Vec<u8>, NatsError> {
    File::open(path)
        .map_err(|source| NatsError::File { what, source })
        .and_then(|file| read_capped(file, what, cap))
}


/// A failed open keeps its `File` form; a refused check names the file and the check.
pub fn secret_failure(what: &'static str, error: SecretFileError) -> NatsError {
    match error {
        SecretFileError::Io { source, .. } => NatsError::File { what, source },
        other => NatsError::SecretFile { what, source: other },
    }
}


/// At most `cap` bytes of a secret file, opened without following a symlink and refused unless private and owned by the process user or root.
pub fn read_secret_bounded(path: &Path, what: &'static str, cap: u64) -> Result<Vec<u8>, NatsError> {
    let handle = open_secret(path).map_err(|error| secret_failure(what, error))?;
    read_capped(handle, what, cap)
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


/// Runs a request under a deadline; a failure becomes a fixed class, since its cause can hold text the peer sent.
pub async fn bounded<Output, Failure, Pending>(limit: Duration, pending: Pending) -> Result<Output, NatsError>
where
    Failure: Into<BoxError>,
    Pending: Future<Output = Result<Output, Failure>>,
{
    tokio::time::timeout(limit, pending)
        .await
        .map_err(NatsError::Timeout)?
        .map_err(|failure| NatsError::Request(without_peer_text(failure.into())))
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
        .map(|path| read_secret_bounded(path, "credentials", MAX_NATS_FILE_BYTES))
        .transpose()?;
    let password = settings
        .nats_password_file
        .as_deref()
        .map(|path| read_secret_bounded(path, "password", MAX_NATS_FILE_BYTES))
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
    let named = with_inbox(authenticated, settings.nats_user.as_deref());
    match credentials {
        Some(bytes) => named.credentials(&String::from_utf8_lossy(&bytes)).map_err(NatsError::Credentials),
        None => Ok(named),
    }
}


/// A throughput guard: a server whose payload limit plus the pull overhead passes `max_batch_bytes` could send a message the first pull never delivers.
pub fn check_payload_limit(server: usize, cap: usize) -> Result<(), NatsError> {
    if server.saturating_add(PULL_OVERHEAD_BYTES) > cap {
        Err(NatsError::PayloadLimit { server, cap })
    } else {
        Ok(())
    }
}


/// What the durable pre-created by the operator must be: pull, explicit acknowledgement, the events subjects only, the configured ack wait.
pub fn check_consumer_config(config: &consumer::Config, settings: &IngestSettings) -> Result<(), NatsError> {
    let filter = format!("{EVENTS_SUBJECT_PREFIX}.>");
    if config.ack_policy != AckPolicy::Explicit {
        Err(NatsError::ConsumerConfig { field: "ack_policy" })
    } else if config.filter_subject != filter || !config.filter_subjects.is_empty() {
        Err(NatsError::ConsumerConfig { field: "filter_subject" })
    } else if config.ack_wait != millis(settings.nats_ack_wait_ms) {
        Err(NatsError::ConsumerConfig { field: "ack_wait" })
    } else {
        Ok(())
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
    let context = jetstream::with_prefix(client.clone(), JS_EVENTS_PREFIX);
    let lookup = context.get_consumer_from_stream::<pull::Config, _, _>(settings.nats_consumer.as_str(), settings.nats_stream.as_str());
    let consumer = bounded(millis(settings.nats_request_timeout_ms), lookup).await?;
    check_consumer_config(&consumer.cached_info().config, settings)?;
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


/// True for the error item async-nats yields when the server ends a pull at the byte cap (409 with the byte-cap description); no peer text is kept.
pub fn is_byte_cap_end(failure: &BoxError) -> bool {
    failure
        .downcast_ref::<std::io::Error>()
        .map(ToString::to_string)
        .is_some_and(|text| text.contains(BYTE_CAP_STATUS) && text.contains(BYTE_CAP_DESCRIPTION))
}


/// The messages of one pull; the byte-cap end is a normal end, any other error item fails the fetch.
pub async fn drain(batch: Batch, max: usize) -> Result<Pulled, BoxError> {
    let items: Vec<Result<jetstream::Message, BoxError>> = batch.take(max).collect().await;
    items.into_iter().try_fold(
        Pulled {
            messages: Vec::new(),
            byte_cap_end: false,
        },
        |mut pulled, item| match item {
            Ok(message) => {
                pulled.messages.push(message);
                Ok(pulled)
            }
            Err(failure) if is_byte_cap_end(&failure) => {
                pulled.byte_cap_end = true;
                Ok(pulled)
            }
            Err(failure) => Err(failure),
        },
    )
}


/// One pull request bounded by messages and bytes; the server ends it at the expiry, the guard covers a server that never answers.
pub async fn first_pull(session: &Session, settings: &IngestSettings, max: usize) -> Result<Pulled, BoxError> {
    let batch = session
        .consumer
        .batch()
        .max_messages(max)
        .max_bytes(settings.max_batch_bytes)
        .expires(millis(settings.nats_fetch_deadline_ms))
        .messages()
        .await?;
    drain(batch, max).await
}


/// The head of the stream alone, with no byte limit and no wait: what a byte-cap end with no message left behind.
pub async fn head_pull(session: &Session, settings: &IngestSettings) -> Result<Pulled, BoxError> {
    let batch = session
        .consumer
        .fetch()
        .max_messages(HEAD_PULL_MESSAGES)
        .max_bytes(NO_BYTE_LIMIT)
        .expires(millis(settings.nats_request_timeout_ms))
        .messages()
        .await?;
    drain(batch, HEAD_PULL_MESSAGES).await
}


/// Joins the first pull with the head pull that followed it, if any.
pub fn assemble(first: Pulled, head: Option<Pulled>) -> Collected {
    let head_pulled = head.is_some();
    let head_capped = head.as_ref().is_some_and(|pulled| pulled.byte_cap_end);
    let head_messages = head.into_iter().flat_map(|pulled| pulled.messages);
    Collected {
        messages: first.messages.into_iter().chain(head_messages).collect(),
        byte_cap_ends: u64::from(first.byte_cap_end) + u64::from(head_capped),
        head_pulled,
    }
}


pub async fn collect_batch(session: &Session, settings: &IngestSettings, max: usize) -> Result<Collected, BoxError> {
    let first = first_pull(session, settings, max).await?;
    let alone = first.byte_cap_end && first.messages.is_empty();
    let head = if alone { Some(head_pull(session, settings).await?) } else { None };
    Ok(assemble(first, head))
}


pub async fn pull_messages(session: &Session, settings: &IngestSettings, max: usize) -> Result<Collected, NatsError> {
    let guard = millis(settings.nats_fetch_deadline_ms + settings.nats_request_timeout_ms);
    bounded(guard, collect_batch(session, settings, max)).await
}


/// Adds what a fetch found to the counts the pipeline reads each cycle.
pub fn count_pulls(pulls: &PullCounts, collected: &Collected) {
    pulls.byte_cap.fetch_add(collected.byte_cap_ends, Ordering::SeqCst);
    pulls.head_alone.fetch_add(u64::from(collected.head_pulled), Ordering::SeqCst);
}


/// A head pull that delivered nothing: the server will not hand over its own head, the only case left that stalls the consumer.
pub fn check_head_delivered(collected: &Collected) -> Result<(), NatsError> {
    if collected.head_pulled && collected.messages.is_empty() {
        Err(NatsError::HeadTooLarge)
    } else {
        Ok(())
    }
}


/// Header values of a message: the map is name to list of values, and the cap bounds the values.
pub fn header_values(message: &jetstream::Message) -> usize {
    message
        .headers
        .as_ref()
        .map_or(0, |headers| headers.iter().map(|(_, values)| values.len()).sum())
}


/// Every `Nats-Msg-Id` value of a message; the cap on header values has already bounded their number.
pub fn message_ids(message: &jetstream::Message) -> Vec<String> {
    message
        .headers
        .iter()
        .flat_map(|headers| headers.get_all(MESSAGE_ID_HEADER))
        .map(|value| value.as_str().to_owned())
        .collect()
}


/// The stream's stored time (the same on every redelivery) in unix nanoseconds; none when the reply carries no usable one.
pub fn stored_nanos(message: &jetstream::Message) -> Option<u64> {
    message
        .info()
        .ok()
        .and_then(|info| u64::try_from(info.published.unix_timestamp_nanos()).ok())
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
                message_ids: message_ids(&message),
                stored_nanos: stored_nanos(&message),
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


pub async fn pull_deliveries(
    session: &mut Session,
    (counter, pulls): (&AtomicU64, &PullCounts),
    settings: &IngestSettings,
    max: usize,
) -> Result<Vec<Delivery>, NatsError> {
    let collected = pull_messages(session, settings, max).await?;
    count_pulls(pulls, &collected);
    check_head_delivered(&collected)?;
    let (deliveries, refused) = admit_messages(session, counter, collected.messages, settings.nats_max_headers);
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
    (counter, pulls): (&AtomicU64, &PullCounts),
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
    let outcome = pull_deliveries(&mut session, (counter, pulls), settings, max).await;
    if matches!(outcome, Ok(_) | Err(NatsError::HeadTooLarge)) {
        *slot = Some(session);
    }
    outcome
}


pub fn lock_session(link: &Link) -> MutexGuard<'_, Option<Session>> {
    link.session.lock().unwrap_or_else(PoisonError::into_inner)
}


/// The field a refused durable differs in, or none for any other outcome.
pub fn refused_field(outcome: &Result<Vec<Delivery>, NatsError>) -> Option<&'static str> {
    match outcome {
        Err(NatsError::ConsumerConfig { field }) => Some(*field),
        _ => None,
    }
}


/// A refused durable stalls ingestion, so it is logged by name once per distinct field and logged again after a fetch that worked.
pub fn log_refusal(link: &Link, outcome: &Result<Vec<Delivery>, NatsError>) {
    let field = refused_field(outcome);
    let mut logged = link.refused_field.lock().unwrap_or_else(PoisonError::into_inner);
    if field.is_some() && *logged != field {
        warn!(field, "the pre-created durable is refused, ingestion is stalled");
    }
    *logged = field;
    if matches!(outcome, Err(NatsError::PayloadLimit { .. })) {
        let variant = PAYLOAD_LIMIT_VARIANT;
        warn!(variant, "the server payload limit passes the pull byte cap, ingestion is stalled");
    }
}


pub fn fetch_batch(link: &Link, max: usize) -> Result<Vec<Delivery>, BoxError> {
    let mut slot = lock_session(link);
    let settings = current_config(&link.settings);
    let outcome = link
        .runtime
        .block_on(fetch_in(&mut slot, (&link.next_token, &link.pulls), &settings, max));
    log_refusal(link, &outcome);
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


pub fn dead_letter_headers(token: &str, reason: &str, (original_bytes, cut): (usize, bool)) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(TENANT_HEADER, token);
    headers.insert(REASON_HEADER, reason);
    headers.insert(ORIGINAL_BYTES_HEADER, original_bytes.to_string());
    if cut {
        headers.insert(TRUNCATED_HEADER, "true");
    }
    headers
}


/// Published with a confirmation from the stream: without it the caller naks, so a lost dead letter is never acknowledged.
pub async fn publish_in(slot: &Option<Session>, settings: &IngestSettings, (tenant, payload, reason): (&str, &[u8], &str)) -> Result<(), NatsError> {
    let session = slot.as_ref().ok_or(NatsError::NotConnected)?;
    let token = dead_letter_token(tenant, settings.max_tenant_bytes);
    let subject = format!("{}.{token}", settings.nats_dead_letter_subject);
    let cut = payload.len() > MAX_DEAD_LETTER_BODY_BYTES;
    let headers = dead_letter_headers(&token, reason, (payload.len(), cut));
    let body = Bytes::copy_from_slice(payload.get(..MAX_DEAD_LETTER_BODY_BYTES).unwrap_or(payload));
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
    let pulls = Arc::new(PullCounts::default());
    let link = Arc::new(Link {
        runtime,
        settings,
        session: Mutex::new(None),
        next_token: AtomicU64::new(FIRST_TOKEN),
        refused_field: Mutex::new(None),
        pulls: Arc::clone(&pulls),
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
        pulls,
    })
}
