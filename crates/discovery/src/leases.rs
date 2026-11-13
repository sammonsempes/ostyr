use crate::model::{HintCounters, Lease, LeaseHints, LeaseLimits, TenantEvent, LEASE_ASSIGNED, LEASE_DECLINED, LEASE_RECLAIMED};
use crate::types::LeaseMap;
use core_export::ecs::EcsEvent;
use dhcp_kea::row::{normalise_mac, valid_hostname, DATASET};
use std::net::IpAddr;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    NotLease,
    NotAssigned,
    BadAddress,
    NoMac,
    NoExpiry,
}


/// The address and lease of a dhcp-kea assigned, declined or reclaimed event, or why the event is none of these.
pub fn lease_of(event: &EcsEvent) -> Result<(IpAddr, Lease), Skip> {
    let source = event.source.as_ref();
    let cltt = event.event.start.map(|start| start.unix_timestamp());
    let is_lease = event.event.dataset.as_deref() == Some(DATASET);
    let expires = event.event.end.map(|end| end.unix_timestamp());
    let action = event.event.action.as_deref();
    let known = [LEASE_ASSIGNED, LEASE_DECLINED, LEASE_RECLAIMED].iter().any(|name| Some(*name) == action);
    let released = known && action != Some(LEASE_ASSIGNED);
    let address = source
        .and_then(|fields| fields.ip.as_deref())
        .and_then(|text| text.parse::<IpAddr>().ok());
    let mac = source.and_then(|fields| fields.mac.as_deref()).and_then(normalise_mac);
    let hostname = event.host.as_ref().and_then(|host| host.hostname.as_deref()).and_then(valid_hostname);
    match (is_lease, cltt, known, address, mac, expires) {
        (false, ..) | (_, None, ..) => Err(Skip::NotLease),
        (_, _, false, ..) => Err(Skip::NotAssigned),
        (_, _, _, None, ..) => Err(Skip::BadAddress),
        (_, _, _, _, None, _) => Err(Skip::NoMac),
        (_, _, _, _, _, None) => Err(Skip::NoExpiry),
        (_, Some(created), _, Some(found), Some(address_mac), Some(end)) => Ok((
            found.to_canonical(),
            Lease {
                mac: address_mac,
                hostname,
                cltt: created,
                expires: end,
                released,
            },
        )),
    }
}


fn count_skip(counters: &mut HintCounters, skip: Skip) {
    match skip {
        Skip::NotLease => counters.not_lease += 1,
        Skip::NotAssigned => counters.not_assigned += 1,
        Skip::BadAddress => counters.bad_address += 1,
        Skip::NoMac => counters.no_mac += 1,
        Skip::NoExpiry => counters.no_expiry += 1,
    }
}


fn store(leases: &mut LeaseMap, counters: &mut HintCounters, address: IpAddr, lease: Lease, limits: &LeaseLimits) {
    let newer = leases.get(&address).map(|held| held.cltt <= lease.cltt);
    match newer {
        Some(true) => {
            leases.insert(address, lease);
        }
        Some(false) => (),
        None if leases.len() >= limits.max_leases => counters.beyond_cap += 1,
        None => {
            leases.insert(address, lease);
        }
    }
}


fn take(hints: &mut LeaseHints, item: TenantEvent<'_>, limits: &LeaseLimits) {
    if item.tenant == hints.tenant {
        let raw_hostname = item.event.host.as_ref().and_then(|host| host.hostname.as_deref());
        match lease_of(item.event) {
            Ok((address, lease)) => {
                hints.counters.released += u64::from(lease.released);
                hints.counters.bad_hostname += u64::from(raw_hostname.is_some() && lease.hostname.is_none());
                store(&mut hints.leases, &mut hints.counters, address, lease, limits);
            }
            Err(skip) => count_skip(&mut hints.counters, skip),
        }
    } else {
        hints.counters.wrong_tenant += 1;
    }
}


/// The latest assigned, declined or reclaimed lease of each address of `tenant`, at most `max_leases` addresses; an event of another tenant is counted and ignored.
pub fn lease_hints<'a>(tenant: &str, events: impl IntoIterator<Item = TenantEvent<'a>>, limits: &LeaseLimits) -> LeaseHints {
    let mut hints = LeaseHints {
        tenant: tenant.to_string(),
        leases: LeaseMap::new(),
        counters: HintCounters::default(),
    };
    events.into_iter().for_each(|item| take(&mut hints, item, limits));
    hints
}
