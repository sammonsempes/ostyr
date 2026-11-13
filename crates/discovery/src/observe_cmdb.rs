use crate::error::DiscoveryError;
use crate::model::{Candidate, Lease, LeaseHints, ObserveCounters, ObserveLimits, ServiceRef, NANOS_PER_MILLI, OBSERVATION_SOURCE};
use cmdb::model::{Asset, IdentityKey, Observation};
use cmdb::reconcile::check_observation;
use cmdb::types::{KeyMap, ObservedMap};
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::warn;


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
    let always = [
        ("discovery.ip".to_string(), candidate.address.to_string()),
        ("discovery.services".to_string(), services.join(",")),
        ("discovery.last_seen".to_string(), rfc3339_of(candidate.last_seen_ms)?),
    ];
    Ok(always.into_iter().chain(omitted).chain(hostname).collect())
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


fn step(found: &mut Vec<Observation>, counters: &mut ObserveCounters, candidate: &Candidate, matched: Option<(&Lease, &Asset)>, cap: usize) {
    match matched {
        None => counters.unmatched += 1,
        Some(_) if found.len() >= cap => counters.beyond_cap += 1,
        Some((lease, asset)) => match observation_of(candidate, lease, asset) {
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
    }
}


/// Observations for the candidates whose lease MAC is the Mac key of an asset of `inventory`; discovery never creates an asset.
pub fn observations(
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
    candidates.iter().for_each(|candidate| {
        let matched = hints
            .leases
            .get(&candidate.address)
            .and_then(|lease| by_mac.get(lease.mac.as_str()).map(|asset| (lease, *asset)));
        step(&mut found, &mut counters, candidate, matched, limits.max_observations);
    });
    (found, counters)
}
