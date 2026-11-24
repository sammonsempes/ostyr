//! The PROXY protocol v2 header of the relay listener: read once, exactly, under one deadline, before any TLS work.
use crate::limits::bump;
use crate::model::{
    Counters, HeaderPermit, HeaderPhase, ProxyFamily, ProxyRefusal, PROXY_COMMAND_BYTE, PROXY_PREFIX_BYTES, PROXY_SIGNATURE, PROXY_TCP4_BYTE,
    PROXY_TCP4_LENGTH, PROXY_TCP4_SOURCE_BYTES, PROXY_TCP4_TAIL_BYTES, PROXY_TCP6_BYTE, PROXY_TCP6_LENGTH, PROXY_TCP6_SOURCE_BYTES,
    PROXY_TCP6_TAIL_BYTES,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;


/// Caps of the header phase: all relays together, then one relay address.
#[derive(Clone, Copy, Debug)]
pub struct HeaderCaps {
    pub total: usize,
    pub per_relay: usize,
}


/// No code holding the lock can panic, so a poisoned lock still guards consistent data.
pub fn lock_phase(phase: &Mutex<HeaderPhase>) -> MutexGuard<'_, HeaderPhase> {
    phase.lock().unwrap_or_else(PoisonError::into_inner)
}


/// Takes a place in the header phase of `relay`, or `None` when the relay or all relays together are at their cap.
pub fn take_header_permit(phase: &Arc<Mutex<HeaderPhase>>, relay: IpAddr, caps: HeaderCaps) -> Option<HeaderPermit> {
    let admitted = {
        let mut held = lock_phase(phase);
        let used = held.per_relay.get(&relay).copied().unwrap_or(0);
        let free = held.total < caps.total && used < caps.per_relay;
        held.total = held.total.saturating_add(usize::from(free));
        *held.per_relay.entry(relay).or_insert(0) += usize::from(free);
        held.per_relay.retain(|_, count| *count > 0);
        free
    };
    admitted.then(|| HeaderPermit {
        phase: Arc::clone(phase),
        relay,
    })
}


impl Drop for HeaderPermit {
    fn drop(&mut self) {
        let mut held = lock_phase(&self.phase);
        held.total = held.total.saturating_sub(1);
        held.per_relay.entry(self.relay).and_modify(|count| *count = count.saturating_sub(1));
        held.per_relay.retain(|_, count| *count > 0);
    }
}


/// The family a 16-byte prefix announces, after checking signature, command and the exact length of its block (no TLV is accepted).
pub fn prefix_family(prefix: &[u8; PROXY_PREFIX_BYTES]) -> Result<ProxyFamily, ProxyRefusal> {
    let [_, _, _, _, _, _, _, _, _, _, _, _, command, family, high, low] = *prefix;
    let announced = usize::from(u16::from_be_bytes([high, low]));
    if !prefix.starts_with(&PROXY_SIGNATURE) {
        Err(ProxyRefusal::Signature)
    } else if command != PROXY_COMMAND_BYTE {
        Err(ProxyRefusal::Command)
    } else {
        match family {
            PROXY_TCP4_BYTE => exact_length(announced, PROXY_TCP4_LENGTH).map(|()| ProxyFamily::Tcp4),
            PROXY_TCP6_BYTE => exact_length(announced, PROXY_TCP6_LENGTH).map(|()| ProxyFamily::Tcp6),
            _ => Err(ProxyRefusal::Family),
        }
    }
}


pub fn exact_length(announced: usize, wanted: usize) -> Result<(), ProxyRefusal> {
    if announced == wanted {
        Ok(())
    } else {
        Err(ProxyRefusal::Length)
    }
}


/// The source of a header in its canonical form; an unspecified or multicast one is refused.
pub fn usable_source(address: IpAddr) -> Result<IpAddr, ProxyRefusal> {
    let canonical = address.to_canonical();
    if canonical.is_unspecified() || canonical.is_multicast() {
        Err(ProxyRefusal::Source)
    } else {
        Ok(canonical)
    }
}


/// The source address of the PROXY header at the start of `stream`: exactly the prefix and the block are read, never a byte more.
pub async fn read_proxy_header(stream: &mut TcpStream, limit: Duration) -> Result<IpAddr, ProxyRefusal> {
    let announced = timeout(limit, read_header(stream)).await.map_err(|_elapsed| ProxyRefusal::Timeout)?;
    announced.and_then(usable_source)
}


pub async fn read_header(stream: &mut TcpStream) -> Result<IpAddr, ProxyRefusal> {
    let mut prefix = [u8::MIN; PROXY_PREFIX_BYTES];
    stream.read_exact(&mut prefix).await.map_err(|_failed| ProxyRefusal::Io)?;
    match prefix_family(&prefix)? {
        ProxyFamily::Tcp4 => {
            let mut source = [u8::MIN; PROXY_TCP4_SOURCE_BYTES];
            let mut tail = [u8::MIN; PROXY_TCP4_TAIL_BYTES];
            stream.read_exact(&mut source).await.map_err(|_failed| ProxyRefusal::Io)?;
            stream.read_exact(&mut tail).await.map_err(|_failed| ProxyRefusal::Io)?;
            Ok(IpAddr::V4(Ipv4Addr::from(source)))
        }
        ProxyFamily::Tcp6 => {
            let mut source = [u8::MIN; PROXY_TCP6_SOURCE_BYTES];
            let mut tail = [u8::MIN; PROXY_TCP6_TAIL_BYTES];
            stream.read_exact(&mut source).await.map_err(|_failed| ProxyRefusal::Io)?;
            stream.read_exact(&mut tail).await.map_err(|_failed| ProxyRefusal::Io)?;
            Ok(IpAddr::V6(Ipv6Addr::from(source)))
        }
    }
}


pub fn refusal_counter(counters: &Counters, refusal: ProxyRefusal) -> &AtomicU64 {
    match refusal {
        ProxyRefusal::Signature => &counters.proxy_bad_signature,
        ProxyRefusal::Command => &counters.proxy_bad_command,
        ProxyRefusal::Family => &counters.proxy_bad_family,
        ProxyRefusal::Length => &counters.proxy_bad_length,
        ProxyRefusal::Source => &counters.proxy_bad_source,
        ProxyRefusal::Io => &counters.proxy_header_io,
        ProxyRefusal::Timeout => &counters.proxy_header_timeout,
    }
}


/// Fixed text of each refusal: no header byte, port or destination ever reaches a log.
pub fn refusal_reason(refusal: ProxyRefusal) -> &'static str {
    match refusal {
        ProxyRefusal::Signature => "PROXY header signature wrong",
        ProxyRefusal::Command => "PROXY header command is not PROXY",
        ProxyRefusal::Family => "PROXY header family is not TCP over IPv4 or IPv6",
        ProxyRefusal::Length => "PROXY header length is not exactly the address block",
        ProxyRefusal::Source => "PROXY header source address unusable",
        ProxyRefusal::Io => "PROXY header cut short",
        ProxyRefusal::Timeout => "PROXY header not complete before its deadline",
    }
}


/// Counts the refusal and logs its fixed text at debug; returns the text.
pub fn count_refusal(counters: &Counters, refusal: ProxyRefusal) -> &'static str {
    bump(refusal_counter(counters, refusal));
    let reason = refusal_reason(refusal);
    tracing::debug!(reason, "relayed connection refused before TLS");
    reason
}
