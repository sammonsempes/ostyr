use crate::model::{Ioc, Source};
use crate::types::IocIndex;
use std::collections::btree_map::Entry;
use time::OffsetDateTime;


/// No expiry on either side means the IOC never expires.
pub fn later_expiry(left: Option<OffsetDateTime>, right: Option<OffsetDateTime>) -> Option<OffsetDateTime> {
    left.zip(right).map(|(first, second)| first.max(second))
}


pub fn merge_sources(known: &mut Vec<Source>, incoming: Vec<Source>) {
    incoming.into_iter().for_each(|source| {
        if !known.contains(&source) {
            known.push(source);
        }
    });
}


pub fn merge_tags(known: &mut Vec<String>, incoming: Vec<String>) {
    incoming.into_iter().for_each(|tag| {
        if !known.contains(&tag) {
            known.push(tag);
        }
    });
}


/// Every source and tag is kept; highest confidence, most restrictive TLP, earliest first-seen, latest last-seen.
pub fn absorb(existing: &mut Ioc, incoming: Ioc) {
    existing.first_seen = existing.first_seen.min(incoming.first_seen);
    existing.last_seen = existing.last_seen.max(incoming.last_seen);
    existing.confidence = existing.confidence.max(incoming.confidence);
    existing.tlp = existing.tlp.max(incoming.tlp);
    existing.expires_at = later_expiry(existing.expires_at, incoming.expires_at);
    merge_sources(&mut existing.sources, incoming.sources);
    merge_tags(&mut existing.tags.malware, incoming.tags.malware);
    merge_tags(&mut existing.tags.actor, incoming.tags.actor);
    merge_tags(&mut existing.tags.campaign, incoming.tags.campaign);
}


/// One IOC per (type, value); returns `true` when `incoming` was merged into an existing one.
pub fn insert_ioc(index: &mut IocIndex, incoming: Ioc) -> bool {
    match index.entry((incoming.ioc_type, incoming.value.clone())) {
        Entry::Vacant(slot) => {
            slot.insert(incoming);
            false
        }
        Entry::Occupied(mut slot) => {
            absorb(slot.get_mut(), incoming);
            true
        }
    }
}


pub fn is_expired(ioc: &Ioc, now: OffsetDateTime) -> bool {
    ioc.expires_at.is_some_and(|expiry| expiry <= now)
}
