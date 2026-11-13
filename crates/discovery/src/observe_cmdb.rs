use crate::error::DiscoveryError;
use crate::model::{
    Candidate, Lease, LeaseHints, ObserveCounters, ObserveLimits, ServiceRef, MILLIS_PER_SECOND, NANOS_PER_MILLI, OBSERVATION_SOURCE,
};
use cmdb::model::{Asset, IdentityKey, Observation};
use cmdb::reconcile::check_observation;
use cmdb::types::{KeyMap, ObservedMap};
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::warn;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint {
    Valid,
    Expired,
    Released,
}


pub const PROTOCOL_TCP: u8 = 6;


pub const PROTOCOL_UDP: u8 = 17;


pub const PROTOCOL_SCTP: u8 = 132;


pub fn service_text(service: &ServiceRef) -> String {
    let name = match service.protocol {
        PROTOCOL_TCP => "tcp".to_string(),
        PROTOCOL_UDP => "udp".to_string(),
        PROTOCOL_SCTP => "sctp".to_string(),
        other => other.to_string(),
    };
    format!("{}/{name}", service.port)
}


pub fn rfc3339_of(millis: i64) -> Result<String, DiscoveryError> {
    Ok(OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * NANOS_PER_MILLI)?.format(&Rfc3339)?)
}


fn attributes_of(candidate: &Candidate, lease: &Lease) -> Result<ObservedMap, DiscoveryError> {
    let services: Vec<String> = candidate.services.iter().map(service_text).collect();
    let omitted = (candidate.services_omitted > 0).then(|| ("discovery.services_omitted".to_string(), candidate.services_omitted.to_string()));
    let hostname = lease.hostname.as_ref().map(|name| ("discovery.hostname".to_string(), name.clone()));
    let listed = (!services.is_empty()).then(|| ("discovery.services".to_string(), services.join(",")));
    let always = [
        ("discovery.ip".to_string(), candidate.address.to_string()),
        ("discovery.last_seen".to_string(), rfc3339_of(candidate.last_seen_ms)?),
    ];
    Ok(always.into_iter().chain(listed).chain(omitted).chain(hostname).collect())
}


/// The observation of one candidate for the asset its lease MAC names: the key is the MAC only, never the hostname.
pub fn observation_of(candidate: &Candidate, lease: &Lease, asset: &Asset) -> Result<Observation, DiscoveryError> {
    let observation = Observation {
        source: OBSERVATION_SOURCE.to_string(),
        kind: asset.kind,
        keys: KeyMap::from([(IdentityKey::Mac, lease.mac.clone())]),
        attributes: attributes_of(candidate, lease)?,
    };
    check_observation(&observation)?;
    Ok(observation)
}


/// A lease explains a flow only while it is neither released nor expired: the candidate's last seen time must be at or before the expiry.
pub fn hint_state(lease: &Lease, candidate: &Candidate) -> Hint {
    if lease.released {
        Hint::Released
    } else if candidate.last_seen_ms > lease.expires.saturating_mul(MILLIS_PER_SECOND) {
        Hint::Expired
    } else {
        Hint::Valid
    }
}


fn step(found: &mut Vec<Observation>, counters: &mut ObserveCounters, candidate: &Candidate, matched: Option<(&Lease, &Asset)>, cap: usize) {
    let state = matched.map(|(lease, _)| hint_state(lease, candidate));
    match (matched, state) {
        (Some(_), Some(Hint::Released)) => counters.released += 1,
        (Some(_), Some(Hint::Expired)) => counters.expired += 1,
        (Some(_), _) if found.len() >= cap => counters.beyond_cap += 1,
        (Some((lease, asset)), _) => match observation_of(candidate, lease, asset) {
            Ok(observation) => {
                counters.observed += 1;
                found.push(observation);
            }
            Err(error) => {
                let reason = error.to_string();
                warn!("a discovery observation was refused: {reason}");
                counters.rejected += 1;
            }
        },
        (None, _) => counters.unmatched += 1,
    }
}


/// Observations for candidates whose lease MAC keys an asset of `inventory`; hints of another tenant are refused (`wrong_tenant`).
pub fn observations(
    tenant: &str,
    candidates: &[Candidate],
    hints: &LeaseHints,
    inventory: &[Asset],
    limits: &ObserveLimits,
) -> (Vec<Observation>, ObserveCounters) {
    let by_mac: BTreeMap<&str, &Asset> = inventory
        .iter()
        .rev()
        .filter_map(|asset| asset.keys.get(&IdentityKey::Mac).map(|mac| (mac.as_str(), asset)))
        .collect();
    let mut found = Vec::new();
    let mut counters = ObserveCounters::default();
    let same_tenant = hints.tenant == tenant;
    candidates.iter().for_each(|candidate| {
        let matched = hints
            .leases
            .get(&candidate.address)
            .and_then(|lease| by_mac.get(lease.mac.as_str()).map(|asset| (lease, *asset)));
        if same_tenant {
            step(&mut found, &mut counters, candidate, matched, limits.max_observations);
        } else {
            counters.wrong_tenant += 1;
        }
    });
    (found, counters)
}
