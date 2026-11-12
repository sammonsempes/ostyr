use crate::model::{Declarations, Finding, FindingKind, Listing};
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;


/// The oldest snapshot time still present, per host.
pub fn oldest_per_host(listing: &Listing) -> BTreeMap<Option<&str>, OffsetDateTime> {
    listing.snapshots.iter().fold(BTreeMap::new(), |mut oldest, snapshot| {
        let slot = oldest.entry(snapshot.host.as_deref()).or_insert(snapshot.time);
        *slot = (*slot).min(snapshot.time);
        oldest
    })
}


/// A snapshot gone from `current` is deleted when it is newer than the oldest one its host still has; the oldest ones going is retention.
pub fn deleted(previous: &Listing, current: &Listing, declarations: &Declarations) -> Vec<Finding> {
    let present: BTreeSet<&str> = current.snapshots.iter().map(|snapshot| snapshot.id.as_str()).collect();
    let oldest = oldest_per_host(current);
    previous
        .snapshots
        .iter()
        .filter(|snapshot| !present.contains(snapshot.id.as_str()))
        .filter(|snapshot| oldest.get(&snapshot.host.as_deref()).is_none_or(|floor| snapshot.time > *floor))
        .map(|snapshot| Finding {
            tenant: declarations.tenant.clone(),
            repository: current.repository.clone(),
            kind: FindingKind::Deleted {
                id: snapshot.id.clone(),
                time: snapshot.time,
                host: snapshot.host.clone(),
            },
        })
        .collect()
}


pub fn below_floor(current: &Listing, declarations: &Declarations) -> Option<Finding> {
    let count = current.snapshots.len();
    declarations
        .repositories
        .iter()
        .find(|entry| entry.repository == current.repository && count < entry.expected_min_snapshots)
        .map(|entry| Finding {
            tenant: declarations.tenant.clone(),
            repository: current.repository.clone(),
            kind: FindingKind::RetentionBelowFloor {
                count,
                floor: entry.expected_min_snapshots,
            },
        })
}


/// Two repositories are never compared: a different id gives `RepositoryChanged` alone, besides the floor check of `current`.
pub fn compare(previous: &Listing, current: &Listing, declarations: &Declarations) -> Vec<Finding> {
    let comparison = if previous.repository == current.repository {
        deleted(previous, current, declarations)
    } else {
        vec![Finding {
            tenant: declarations.tenant.clone(),
            repository: current.repository.clone(),
            kind: FindingKind::RepositoryChanged {
                previous: previous.repository.clone(),
                current: current.repository.clone(),
            },
        }]
    };
    comparison.into_iter().chain(below_floor(current, declarations)).collect()
}
