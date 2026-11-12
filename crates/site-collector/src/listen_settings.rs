use crate::admission::validate_config;
use crate::error::ListenError;
use crate::flow::validate_flow_limits;
use crate::forward_model::MAX_FORWARD_BATCH_RECORDS;
use crate::listen_model::{Bound, ListenerSettings, SharedSocket, MAX_TENANT_BYTES, READ_TIMEOUT_MS, SETTINGS_SECTION};
use crate::model::{BucketLimits, CollectorConfig};
use crate::types::SourceKeySet;
use arc_swap::ArcSwap;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;


/// The key of a source in the admission table: an IPv6 address counts by its /64, an IPv4-mapped one as IPv4.
pub fn source_key(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V6(v6) => {
            let [first, second, third, fourth, ..] = v6.segments();
            IpAddr::V6(Ipv6Addr::new(first, second, third, fourth, 0, 0, 0, 0))
        }
        other => other,
    }
}


pub fn declared_keys(settings: &ListenerSettings) -> SourceKeySet {
    settings.sources.iter().copied().map(source_key).collect()
}


pub fn collector_config_of(settings: &ListenerSettings) -> CollectorConfig {
    CollectorConfig {
        global: BucketLimits {
            rate_per_second: settings.rate_per_second,
            burst: settings.burst,
        },
        source_share_percent: settings.source_share_percent,
        unknown_share_percent: settings.unknown_share_percent,
        sources: declared_keys(settings),
        drop_unknown: settings.drop_unknown,
        max_sources: settings.max_sources,
    }
}


pub fn parse_listen(text: &str) -> Result<SocketAddr, ListenError> {
    text.parse().map_err(ListenError::BadAddress)
}


/// The socket address when the whole snapshot is acceptable: a tenant, valid limits, a parsable address.
pub fn validate_settings(settings: &ListenerSettings) -> Result<SocketAddr, ListenError> {
    (1..=MAX_TENANT_BYTES)
        .contains(&settings.tenant.len())
        .then_some(())
        .ok_or(ListenError::BadTenant)?;
    (1..=MAX_FORWARD_BATCH_RECORDS)
        .contains(&settings.forward_batch_records)
        .then_some(())
        .ok_or(ListenError::BadForwardBatch)?;
    validate_config(&collector_config_of(settings))?;
    validate_flow_limits(&settings.flow)?;
    parse_listen(&settings.listen)
}


pub fn bind_socket(address: SocketAddr) -> Result<UdpSocket, ListenError> {
    UdpSocket::bind(address)
        .and_then(|socket| socket.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS))).map(|()| socket))
        .map_err(ListenError::Bind)
}


/// One line per field, so a reload's diff and audit entry show which setting changed.
pub fn settings_state(settings: &ListenerSettings) -> ConfigState {
    [
        ("listen", format!("{:?}", settings.listen)),
        ("kind", format!("{:?}", settings.kind)),
        ("flow", format!("{:?}", settings.flow)),
        ("tenant", format!("{:?}", settings.tenant)),
        ("rate_per_second", settings.rate_per_second.to_string()),
        ("burst", settings.burst.to_string()),
        ("source_share_percent", settings.source_share_percent.to_string()),
        ("unknown_share_percent", settings.unknown_share_percent.to_string()),
        ("max_sources", settings.max_sources.to_string()),
        ("forward_batch_records", settings.forward_batch_records.to_string()),
        ("drop_unknown", settings.drop_unknown.to_string()),
        ("sources", format!("{:?}", settings.sources)),
    ]
    .into_iter()
    .chain(
        settings
            .bind_failed
            .load(Ordering::SeqCst)
            .then(|| ("listen_applied", "false".to_owned())),
    )
    .map(|(name, value)| (format!("{SETTINGS_SECTION}.{name}"), value))
    .collect()
}


pub fn settings_loader(path: PathBuf) -> Box<LoaderFn<ListenerSettings>> {
    Box::new(move || load_file::<ListenerSettings>(&path))
}


/// True when the candidate's parsed address differs from the one in use.
pub fn address_changed(shared: &SharedSocket, address: SocketAddr) -> bool {
    parse_listen(&shared.bound.load().listen).map_or(true, |current| current != address)
}


/// Validates the candidate and proves its new address can be bound, then releases it at once: no socket is held outside the applied state.
pub fn check_bindable(shared: &SharedSocket, candidate: &ListenerSettings) -> Result<(), ListenError> {
    let address = validate_settings(candidate)?;
    (candidate.kind == shared.kind).then_some(()).ok_or(ListenError::KindChanged)?;
    address_changed(shared, address)
        .then(|| bind_socket(address))
        .transpose()
        .map(|_probe| ())
}


/// Binds the new address and swaps it in; a lost race keeps the old socket, is counted and logged, and marks the settings so the next reload retries.
pub fn rebind(shared: &SharedSocket, applied: &ListenerSettings) {
    let outcome = parse_listen(&applied.listen)
        .and_then(|address| address_changed(shared, address).then(|| bind_socket(address)).transpose())
        .map(|bound| {
            bound.into_iter().for_each(|socket| {
                shared.bound.store(Arc::new(Bound {
                    listen: applied.listen.clone(),
                    socket,
                }));
            });
        });
    outcome.err().into_iter().for_each(|error| {
        shared.rebind_failures.fetch_add(1, Ordering::SeqCst);
        applied.bind_failed.store(true, Ordering::SeqCst);
        tracing::error!(%error, listen = %applied.listen, "cannot bind the new listening address after validation, the old socket is kept");
    });
}


pub fn listener_subscriber(shared: Arc<SharedSocket>) -> Subscriber<ListenerSettings> {
    let for_apply = Arc::clone(&shared);
    Subscriber {
        section: SETTINGS_SECTION.to_owned(),
        validate: Box::new(move |candidate| check_bindable(&shared, candidate).map_err(BoxError::from)),
        apply: Box::new(move |applied| rebind(&for_apply, applied)),
    }
}


/// The first load must be valid and bind. Later reloads are validated, audited and swapped atomically; an invalid file or a failed bind keeps the old state.
pub fn open_listener_engine(
    path: PathBuf,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<(ReloadEngine<ListenerSettings>, Arc<SharedSocket>), ListenError> {
    let engine = open_engine(settings_loader(path), settings_state, Vec::new(), audit, context)?;
    let first = current_config(&engine);
    let address = validate_settings(&first)?;
    let shared = Arc::new(SharedSocket {
        bound: ArcSwap::from_pointee(Bound {
            listen: first.listen.clone(),
            socket: bind_socket(address)?,
        }),
        rebind_failures: AtomicU64::new(0),
        kind: first.kind,
    });
    let subscribed = ReloadEngine {
        subscribers: vec![listener_subscriber(Arc::clone(&shared))],
        ..engine
    };
    Ok((subscribed, shared))
}
