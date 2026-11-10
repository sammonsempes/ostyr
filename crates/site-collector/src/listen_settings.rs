use crate::admission::validate_config;
use crate::error::ListenError;
use crate::listen_model::{Bound, ListenerSettings, SharedSocket, MAX_TENANT_BYTES, READ_TIMEOUT_MS, SETTINGS_SECTION};
use crate::model::{BucketLimits, CollectorConfig};
use arc_swap::ArcSwap;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
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


pub fn collector_config_of(settings: &ListenerSettings) -> CollectorConfig {
    CollectorConfig {
        global: BucketLimits {
            rate_per_second: settings.rate_per_second,
            burst: settings.burst,
        },
        source_share_percent: settings.source_share_percent,
        unknown_share_percent: settings.unknown_share_percent,
        sources: settings.sources.iter().copied().map(source_key).collect(),
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
    validate_config(&collector_config_of(settings))?;
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
        ("tenant", format!("{:?}", settings.tenant)),
        ("rate_per_second", settings.rate_per_second.to_string()),
        ("burst", settings.burst.to_string()),
        ("source_share_percent", settings.source_share_percent.to_string()),
        ("unknown_share_percent", settings.unknown_share_percent.to_string()),
        ("max_sources", settings.max_sources.to_string()),
        ("drop_unknown", settings.drop_unknown.to_string()),
        ("sources", format!("{:?}", settings.sources)),
    ]
    .into_iter()
    .map(|(name, value)| (format!("{SETTINGS_SECTION}.{name}"), value))
    .collect()
}


pub fn settings_loader(path: PathBuf) -> Box<LoaderFn<ListenerSettings>> {
    Box::new(move || load_file::<ListenerSettings>(&path))
}


/// Validates the candidate and binds its address when it changed; a failed bind refuses the reload, so the old socket stays.
pub fn prepare_socket(shared: &SharedSocket, candidate: &ListenerSettings) -> Result<(), ListenError> {
    let address = validate_settings(candidate)?;
    shared.pending.lock().unwrap_or_else(PoisonError::into_inner).take();
    let changed = parse_listen(&shared.bound.load().listen).map_or(true, |current| current != address);
    let pending = if changed {
        Some(Bound {
            listen: candidate.listen.clone(),
            socket: bind_socket(address)?,
        })
    } else {
        None
    };
    *shared.pending.lock().unwrap_or_else(PoisonError::into_inner) = pending;
    Ok(())
}


/// Makes the socket bound by `prepare_socket` the one in use.
pub fn publish_socket(shared: &SharedSocket) {
    let pending = shared.pending.lock().unwrap_or_else(PoisonError::into_inner).take();
    pending.into_iter().for_each(|bound| shared.bound.store(Arc::new(bound)));
}


pub fn listener_subscriber(shared: Arc<SharedSocket>) -> Subscriber<ListenerSettings> {
    let for_apply = Arc::clone(&shared);
    Subscriber {
        section: SETTINGS_SECTION.to_owned(),
        validate: Box::new(move |candidate| prepare_socket(&shared, candidate).map_err(BoxError::from)),
        apply: Box::new(move |_applied| publish_socket(&for_apply)),
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
        pending: Mutex::new(None),
    });
    let subscribed = ReloadEngine {
        subscribers: vec![listener_subscriber(Arc::clone(&shared))],
        ..engine
    };
    Ok((subscribed, shared))
}
