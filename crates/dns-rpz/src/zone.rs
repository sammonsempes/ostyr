use crate::limits::WILDCARD_PREFIX;
use crate::model::Entry;
use crate::policy::Policy;
use std::cmp::Reverse;
use std::io::{self, Write};


/// Resource records of one entry: the trigger, plus its wildcard.
pub fn record_count(entry: &Entry) -> usize {
    1 + usize::from(entry.wildcard)
}


/// Whole entries only, best confidence first, stopping at the first that does not fit; returns them in owner order and the dropped count.
pub fn apply_cap(entries: Vec<Entry>, max_records: usize) -> (Vec<Entry>, u64) {
    let total = entries.len();
    let mut ranked = entries;
    ranked.sort_by(|left, right| (Reverse(left.confidence), &left.owner).cmp(&(Reverse(right.confidence), &right.owner)));
    let mut kept: Vec<Entry> = ranked
        .into_iter()
        .scan(0, |used: &mut usize, entry| {
            *used += record_count(&entry);
            (*used <= max_records).then_some(entry)
        })
        .collect();
    kept.sort_by(|left, right| left.owner.cmp(&right.owner));
    let dropped = (total - kept.len()) as u64;
    (kept, dropped)
}


pub fn write_entry(entry: &Entry, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{} IN CNAME {}", entry.owner, entry.rdata)?;
    if entry.wildcard {
        writeln!(out, "{WILDCARD_PREFIX}{} IN CNAME {}", entry.owner, entry.rdata)
    } else {
        Ok(())
    }
}


/// RFC 1035 master file: origin, TTL, SOA, name servers, then the sorted triggers.
pub fn render_zone(policy: &Policy, serial: u32, entries: &[Entry], out: &mut dyn Write) -> io::Result<()> {
    let soa = &policy.soa;
    writeln!(out, "$ORIGIN {}.", policy.zone)?;
    writeln!(out, "$TTL {}", policy.ttl)?;
    writeln!(
        out,
        "@ IN SOA {}. {}. {serial} {} {} {} {}",
        soa.mname, soa.rname, soa.refresh, soa.retry, soa.expire, soa.minimum
    )?;
    policy.ns.iter().try_for_each(|host| writeln!(out, "@ IN NS {host}."))?;
    entries.iter().try_for_each(|entry| write_entry(entry, out))
}
