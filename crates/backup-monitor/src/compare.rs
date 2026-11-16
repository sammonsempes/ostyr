use crate::model::{Declarations, Finding, FindingKind, Listing};
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;


/// The oldest snapshot still present, per host, as (time, id): the id breaks a tie inside one second.
pub fn oldest_per_host(listing: &Listing) -> BTreeMap<Option<&str>, (OffsetDateTime, &str)> {
    listing.snapshots.iter().fold(BTreeMap::new(), |mut oldest, snapshot| {
        let candidate = (snapshot.time, snapshot.id.as_str());
        let slot = oldest.entry(snapshot.host.as_deref()).or_insert(candidate);
        *slot = (*slot).min(candidate);
        oldest
    })
}


/// Deleted when (time, id) is above the oldest one its host still has (same-second: by id); the oldest ones going is retention.
pub fn deleted(previous: &Listing, current: &Listing, declarations: &Declarations) -> Vec<Finding> {
    let present: BTreeSet<&str> = current.snapshots.iter().map(|snapshot| snapshot.id.as_str()).collect();
    let oldest = oldest_per_host(current);
    previous
        .snapshots
        .iter()
        .filter(|snapshot| !present.contains(snapshot.id.as_str()))
        .filter(|snapshot| {
            oldest
                .get(&snapshot.host.as_deref())
                .is_none_or(|floor| (snapshot.time, snapshot.id.as_str()) > *floor)
        })
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
    below_floor_named(&current.repository, current.snapshots.len(), declarations)
}


/// The floor declared for `repository` against a snapshot `count`; a restic listing is keyed on its config id, its floor on the declared name.
pub fn below_floor_named(repository: &str, count: usize, declarations: &Declarations) -> Option<Finding> {
    declarations
        .repositories
        .iter()
        .find(|entry| entry.repository == repository && count < entry.expected_min_snapshots)
        .map(|entry| Finding {
            tenant: declarations.tenant.clone(),
            repository: repository.to_owned(),
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
