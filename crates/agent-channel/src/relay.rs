use crate::agent_app::{AgentFile, AGENT_VERSION};
use crate::client::{connect_channel, heartbeat};
use crate::error::{AppError, ChannelError, EndpointFault};
use crate::limits::bounded_text;
use crate::model::{MAX_RELAYS, PREFERRED_RETRY_SECONDS};
use crate::types::{DialFn, SharedClientConfig};
use rustls_pki_types::ServerName;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;
use tonic::transport::Channel;
use tonic::Code;


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointKind {
    Internal,
    Relay,
}


impl Display for EndpointKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Internal => "internal",
            Self::Relay => "relay",
        })
    }
}


/// The endpoint a run is pinned to; `cut` is when a run on a relay ends cleanly to try the internal server again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selected {
    pub index: usize,
    pub kind: EndpointKind,
    pub address: SocketAddr,
    pub cut: Option<Instant>,
}


/// The internal endpoint is skipped until `until`; shared by the successive runs of one agent process.
#[derive(Debug)]
pub struct HoldDown {
    pub until: Mutex<Instant>,
}


impl Default for HoldDown {
    fn default() -> Self {
        Self {
            until: Mutex::new(Instant::now()),
        }
    }
}


pub fn kind_of(index: usize) -> EndpointKind {
    if index == 0 {
        EndpointKind::Internal
    } else {
        EndpointKind::Relay
    }
}


fn refused(index: usize, reason: EndpointFault) -> AppError {
    AppError::Endpoint { index, reason }
}


fn check_usable(index: usize, address: SocketAddr) -> Result<SocketAddr, AppError> {
    let broadcast = matches!(address.ip(), IpAddr::V4(v4) if v4.is_broadcast());
    if address.port() == 0 {
        Err(refused(index, EndpointFault::ZeroPort))
    } else if matches!(address.ip(), IpAddr::V6(v6) if v6.is_unicast_link_local()) {
        Err(refused(index, EndpointFault::LinkLocal))
    } else if address.ip().is_unspecified() || address.ip().is_multicast() || broadcast {
        Err(refused(index, EndpointFault::Unusable))
    } else {
        Ok(address)
    }
}


/// An IPv6 endpoint carries no scope id and no flow label (checked before the IPv4-mapped fold drops them).
pub fn check_scope(index: usize, parsed: SocketAddr) -> Result<SocketAddr, AppError> {
    match parsed {
        SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0 => Err(refused(index, EndpointFault::Scoped)),
        other => Ok(other),
    }
}


/// Parses one endpoint; an IPv4-mapped IPv6 address is folded to IPv4 so duplicates compare on the real value.
pub fn parse_endpoint(index: usize, text: &str) -> Result<SocketAddr, AppError> {
    let parsed: SocketAddr = text.parse().map_err(|_error| refused(index, EndpointFault::Unparsable))?;
    let unscoped = check_scope(index, parsed)?;
    check_usable(index, SocketAddr::new(unscoped.ip().to_canonical(), unscoped.port()))
}


/// The internal address first, then the relays in file order; the whole file is refused by entry index on any bad entry.
pub fn endpoint_addresses(file: &AgentFile) -> Result<Vec<SocketAddr>, AppError> {
    if file.relays.len() > MAX_RELAYS {
        Err(AppError::TooManyRelays {
            count: file.relays.len(),
            max: MAX_RELAYS,
        })
    } else {
        ServerName::try_from(file.server_name.clone()).map_err(|_error| refused(0, EndpointFault::ServerName))?;
        std::iter::once(file.server.as_str())
            .chain(file.relays.iter().map(String::as_str))
            .enumerate()
            .try_fold(Vec::new(), |mut accepted, (index, text)| {
                let address = parse_endpoint(index, text)?;
                if accepted.contains(&address) {
                    Err(refused(index, EndpointFault::Duplicate))
                } else {
                    accepted.push(address);
                    Ok(accepted)
                }
            })
    }
}


fn hold_until(hold: &HoldDown) -> Instant {
    *hold.until.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn is_held(hold: &HoldDown) -> bool {
    Instant::now() < hold_until(hold)
}


pub fn hold_internal(hold: &HoldDown) {
    *hold.until.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now() + Duration::from_secs(PREFERRED_RETRY_SECONDS);
}


/// Endpoints with their index in the order they are tried: internal first, unless it is held down, then it is the last resort.
pub fn selection_order(addresses: &[SocketAddr], internal_held: bool) -> Vec<(usize, SocketAddr)> {
    let indexed = addresses.iter().copied().enumerate();
    if internal_held {
        indexed.clone().skip(1).chain(indexed.take(1)).collect()
    } else {
        indexed.collect()
    }
}


/// Connects and makes the first call; any failure is a failed endpoint, never a half-used channel.
pub async fn open_checked(address: SocketAddr, config: SharedClientConfig, server_name: &str) -> Result<Channel, ChannelError> {
    let channel = connect_channel(address, config, server_name).await?;
    heartbeat(channel.clone(), AGENT_VERSION).await?;
    Ok(channel)
}


async fn try_endpoint(
    index: usize,
    address: SocketAddr,
    config: &SharedClientConfig,
    server_name: &str,
    hold: &HoldDown,
) -> Result<Selected, ChannelError> {
    let kind = kind_of(index);
    let opened = open_checked(address, Arc::clone(config), server_name).await;
    let rate_refused = opened.as_ref().err().is_some_and(is_rate_refusal);
    if let Err(error) = &opened {
        let text = error_text(error);
        tracing::warn!(index, %kind, error = ?text, rate_refused, "agent endpoint failed");
    }
    if opened.is_err() && kind == EndpointKind::Internal && !rate_refused {
        hold_internal(hold);
    }
    opened.map(|_channel| Selected {
        index,
        kind,
        address,
        cut: (kind == EndpointKind::Relay).then(|| hold_until(hold)),
    })
}


/// Dials and heartbeats the endpoints in order, each under the connect and unary deadlines; the first that answers is used for the whole run.
pub async fn select_endpoint(
    addresses: &[SocketAddr],
    config: &SharedClientConfig,
    server_name: &str,
    hold: &HoldDown,
) -> Result<Selected, ChannelError> {
    let mut result = Err(ChannelError::EndpointLost);
    for (index, address) in selection_order(addresses, is_held(hold)) {
        if result.as_ref().is_err_and(|error| !is_rate_refusal(error)) {
            result = try_endpoint(index, address, config, server_name, hold).await;
        }
    }
    if let Ok(selected) = &result {
        tracing::info!(index = selected.index, kind = %selected.kind, "agent endpoint selected");
    }
    result
}


/// An error as logged: a server status keeps its code and a bounded message, never the server's whole text.
pub fn error_text(error: &ChannelError) -> String {
    match error {
        ChannelError::RetriesExhausted { attempts, last } => {
            format!(
                "event delivery abandoned after {attempts} consecutive failed attempts: {}",
                leaf_text(last)
            )
        }
        other => leaf_text(other),
    }
}


fn leaf_text(error: &ChannelError) -> String {
    match error {
        ChannelError::Status(status) => format!("call refused: {:?}: {}", status.code(), bounded_text(status.message())),
        ChannelError::RetriesExhausted { attempts, .. } => format!("event delivery abandoned after {attempts} consecutive failed attempts"),
        other => other.to_string(),
    }
}


/// The server answered a rate or slot refusal: it is alive, so the endpoint is neither dropped nor held down.
pub fn is_rate_refusal(error: &ChannelError) -> bool {
    matches!(error, ChannelError::Status(status) if status.code() == Code::ResourceExhausted && status.source().is_none())
}


/// A dialer pinned to one address: a failed connect, handshake or first call trips `cancel`, which ends both streams at once.
pub fn pinned_dialer(address: SocketAddr, config: SharedClientConfig, server_name: String, cancel: Arc<watch::Sender<bool>>) -> Box<DialFn> {
    Box::new(move || {
        let shared = Arc::clone(&config);
        let name = server_name.clone();
        let tripwire = Arc::clone(&cancel);
        Box::pin(async move {
            open_checked(address, shared, &name).await.inspect_err(|error| {
                let text = error_text(error);
                if is_rate_refusal(error) {
                    tracing::warn!(error = ?text, "pinned endpoint refused on rate, no hold-down");
                } else {
                    tracing::warn!(error = ?text, "pinned endpoint failed, the run ends");
                    tripwire.send_replace(true);
                }
            })
        })
    })
}


/// Waits until a pinned dialer trips the cancel; the sender must outlive the call, a dropped one counts as a trip.
pub async fn tripped(mut cancelled: watch::Receiver<bool>) {
    if let Err(error) = cancelled.wait_for(|trip| *trip).await {
        tracing::warn!(%error, "cancel sender dropped, the run ends");
    }
}


/// The relay bound as a future: a relay run stops at `cut`, the internal one never.
pub async fn stop_at(cut: Option<Instant>) {
    match cut {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending::<()>().await,
    }
}
