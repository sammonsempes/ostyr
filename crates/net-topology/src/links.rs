use crate::error::LinkError;
use crate::model::{Link, Merged, Observation};
use crate::types::LinkKey;
use core_pg::scope::{tenant_of, tenant_scope};
use std::collections::{BTreeMap, BTreeSet};


pub const MAX_STALE_AFTER_SECONDS: i64 = 2_592_000;


pub fn link_key(link: &Link) -> LinkKey {
    (
        link.local_host.clone(),
        link.local_port.clone(),
        link.remote_chassis.clone(),
        link.remote_port.clone(),
    )
}


/// Turns observations into links of one validated tenant, first and last seen at the observation time.
pub fn build_links(tenant: &str, observations: Vec<Observation>) -> Result<Vec<Link>, LinkError> {
    let scope = tenant_scope(tenant).map_err(LinkError::Tenant)?;
    Ok(observations
        .into_iter()
        .map(|observation| Link {
            tenant: scope.clone(),
            local_host: observation.local_host,
            local_port: observation.local_port,
            remote_chassis: observation.remote_chassis,
            remote_port: observation.remote_port,
            remote_name: observation.remote_name,
            first_seen: observation.seen,
            last_seen: observation.seen,
        })
        .collect())
}


fn host_counts(links: &BTreeMap<LinkKey, Link>) -> BTreeMap<String, usize> {
    links.values().fold(BTreeMap::new(), |mut counts, link| {
        *counts.entry(link.local_host.clone()).or_insert(0) += 1;
        counts
    })
}


/// Known links get `last_seen = max(last_seen, now)`, unknown ones are added unless their host holds `max_links_per_host` links; nothing is removed.
pub fn merge_observations(previous: Vec<Link>, observed: Vec<Link>, now: i64, max_links_per_host: usize) -> Result<Merged, LinkError> {
    let tenants = previous
        .iter()
        .chain(observed.iter())
        .map(|link| tenant_of(&link.tenant))
        .collect::<BTreeSet<_>>();
    if tenants.len() > 1 {
        Err(LinkError::TenantMismatch)?;
    }
    let mut links = previous.into_iter().map(|link| (link_key(&link), link)).collect::<BTreeMap<_, _>>();
    let mut counts = host_counts(&links);
    let mut refused_new = 0;
    for link in observed {
        let key = link_key(&link);
        let host_count = counts.get(&link.local_host).copied().unwrap_or(0);
        match links.get_mut(&key) {
            Some(known) => {
                known.last_seen = known.last_seen.max(now);
                known.remote_name = link.remote_name;
            }
            None if host_count < max_links_per_host => {
                counts.insert(link.local_host.clone(), host_count + 1);
                links.insert(
                    key,
                    Link {
                        first_seen: now,
                        last_seen: now,
                        ..link
                    },
                );
            }
            None => refused_new += 1,
        }
    }
    if refused_new > 0 {
        tracing::warn!(refused_new, "new links refused at the per host cap");
    }
    Ok(Merged {
        links: links.into_values().collect(),
        refused_new,
    })
}


/// True when the link was last seen `stale_after_seconds` or more before `now`; the window is 1 second to 30 days.
pub fn is_stale(link: &Link, now: i64, stale_after_seconds: i64) -> Result<bool, LinkError> {
    if !(1..=MAX_STALE_AFTER_SECONDS).contains(&stale_after_seconds) {
        Err(LinkError::InvalidStaleAfter {
            value: stale_after_seconds,
            max: MAX_STALE_AFTER_SECONDS,
        })
    } else {
        Ok(now.saturating_sub(link.last_seen) >= stale_after_seconds)
    }
}
