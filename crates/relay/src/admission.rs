use crate::model::{Admission, AdmissionState, Permit, Refusal, IPV6_HOST_BITS};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, PoisonError};
use tokio::sync::watch;


pub fn new_admission() -> Arc<Admission> {
    let (live, _receiver) = watch::channel(0);
    Arc::new(Admission {
        state: std::sync::Mutex::new(AdmissionState::default()),
        live,
    })
}


/// The address a cap is counted on: an IPv4-mapped address as IPv4, an IPv6 address as its /64.
pub fn source_of(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << IPV6_HOST_BITS))),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}


/// Checks both caps and takes the slot under one lock; a lowered cap never cuts live connections, it only refuses new ones.
pub fn admit(admission: &Arc<Admission>, peer: IpAddr, max_total: usize, max_source: usize) -> Result<Permit, Refusal> {
    let source = source_of(peer);
    let mut state = admission.state.lock().unwrap_or_else(PoisonError::into_inner);
    let held = state.sources.get(&source).copied().unwrap_or(0);
    if state.total >= max_total {
        Err(Refusal::Total)
    } else if held >= max_source {
        Err(Refusal::Source)
    } else {
        state.total += 1;
        state.sources.insert(source, held + 1);
        admission.live.send_replace(state.total);
        Ok(Permit {
            admission: Arc::clone(admission),
            source,
        })
    }
}


/// Connections and distinct sources held now.
pub fn gauges(admission: &Admission) -> (usize, usize) {
    let state = admission.state.lock().unwrap_or_else(PoisonError::into_inner);
    (state.total, state.sources.len())
}


impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.admission.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.total = state.total.saturating_sub(1);
        let remaining = state.sources.get(&self.source).copied().unwrap_or(0).saturating_sub(1);
        if remaining == 0 {
            state.sources.remove(&self.source);
        } else {
            state.sources.insert(self.source, remaining);
        }
        self.admission.live.send_replace(state.total);
    }
}
