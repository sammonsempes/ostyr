use crate::map::{edges, scope_of};
use crate::model::{Candidate, Gathered, KnownDevices, ServiceMap, ServiceRef, MAX_SERVICES_PER_CANDIDATE};
use crate::scope::in_scope;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;


/// The known set from addresses, each in canonical form.
pub fn known_devices(addresses: impl IntoIterator<Item = IpAddr>) -> KnownDevices {
    KnownDevices {
        addresses: addresses.into_iter().map(|address| address.to_canonical()).collect(),
    }
}


fn gather(found: &mut BTreeMap<IpAddr, Gathered>, address: IpAddr, first_ms: i64, last_ms: i64, service: Option<ServiceRef>) {
    let entry = found.entry(address).or_insert(Gathered {
        first_seen_ms: first_ms,
        last_seen_ms: last_ms,
        services: BTreeSet::new(),
    });
    entry.first_seen_ms = entry.first_seen_ms.min(first_ms);
    entry.last_seen_ms = entry.last_seen_ms.max(last_ms);
    entry.services.extend(service);
}


fn candidate_of(address: IpAddr, gathered: Gathered) -> Candidate {
    Candidate {
        address,
        first_seen_ms: gathered.first_seen_ms,
        last_seen_ms: gathered.last_seen_ms,
        services_omitted: gathered.services.len().saturating_sub(MAX_SERVICES_PER_CANDIDATE),
        services: gathered.services.into_iter().take(MAX_SERVICES_PER_CANDIDATE).collect(),
    }
}


/// The owned addresses seen in an edge and not in `known`, by address; services are cut at the cap and counted.
pub fn candidates(map: &ServiceMap, known: &KnownDevices) -> Vec<Candidate> {
    let mut found: BTreeMap<IpAddr, Gathered> = BTreeMap::new();
    edges(map).for_each(|(key, stats)| {
        let service = ServiceRef {
            port: key.port,
            protocol: key.protocol,
        };
        [(key.source, None), (key.destination, Some(service))]
            .into_iter()
            .filter(|(address, _)| in_scope(scope_of(map), *address) && !known.addresses.contains(address))
            .for_each(|(address, offered)| gather(&mut found, address, stats.first_seen_ms, stats.last_seen_ms, offered));
    });
    found.into_iter().map(|(address, gathered)| candidate_of(address, gathered)).collect()
}
