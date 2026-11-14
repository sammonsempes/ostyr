use crate::error::ParseError;
use crate::limits::{Limits, PageLimits, CEILING_PAGES, CEILING_TOTAL_ITEMS, PAGE_POD_BYTES};
use crate::model::{NodeItem, Page, Parsed, PodItem, Skipped};
use crate::parse::{drop_shadowed_refusals, node_uid, pod_uid};
use std::collections::HashSet;


/// The `limit` query value of one page: `max_bytes` at 32 KiB per pod, at most `max_items`, at least 1.
pub fn page_size(limits: &Limits) -> usize {
    let by_bytes = usize::try_from(limits.max_bytes / PAGE_POD_BYTES).unwrap_or(usize::MAX);
    by_bytes.min(limits.max_items).max(1)
}


pub fn check_page_limits(page_limits: &PageLimits) -> Result<(), ParseError> {
    if page_limits.max_pages > CEILING_PAGES || page_limits.max_total_items > CEILING_TOTAL_ITEMS {
        Err(ParseError::BadPageLimits)
    } else {
        Ok(())
    }
}


/// The raw elements of the pages already read.
pub fn items_read<Item>(pages: &[Page<Item>]) -> usize {
    pages.iter().fold(0, |total: usize, page| total.saturating_add(page.raw_count))
}


/// The element budget the next page may use: `max_total_items` minus the raw elements of the pages already read.
pub fn remaining_budget<Item>(pages: &[Page<Item>], page_limits: &PageLimits) -> usize {
    page_limits.max_total_items.saturating_sub(items_read(pages))
}


/// Complete means: within `max_pages`, a token on every page but the last, and none on the last.
pub fn is_complete<Item>(pages: &[Page<Item>], page_limits: &PageLimits) -> bool {
    pages.len() <= page_limits.max_pages
        && pages
            .split_last()
            .is_some_and(|(last, earlier)| last.next.is_none() && earlier.iter().all(|page| page.next.is_some()))
}


pub fn merge_page<Item>(merged: &mut Parsed<Item>, seen: &mut HashSet<String>, page: Parsed<Item>, uid_of: fn(&Item) -> &str) {
    merged.skipped.unparsable += page.skipped.unparsable;
    merged.skipped.bad_field += page.skipped.bad_field;
    merged.skipped.duplicate += page.skipped.duplicate;
    merged.skipped.uid_lost += page.skipped.uid_lost;
    merged.skipped.refused_uids.extend(page.skipped.refused_uids);
    for item in page.items {
        if seen.insert(uid_of(&item).to_owned()) {
            merged.items.push(item);
        } else {
            merged.skipped.duplicate += 1;
        }
    }
}


/// Merges a complete run of pages into one `Parsed`: the first copy of a uid wins, a refused uid kept on another page leaves the refused set, a partial run is `Incomplete`.
pub fn merge_pages<Item>(pages: Vec<Page<Item>>, page_limits: &PageLimits, uid_of: fn(&Item) -> &str) -> Result<Parsed<Item>, ParseError> {
    check_page_limits(page_limits)?;
    if !is_complete(&pages, page_limits) {
        Err(ParseError::Incomplete)?;
    }
    let read = items_read(&pages);
    if read > page_limits.max_total_items {
        Err(ParseError::TooManyItems {
            count: read,
            max: page_limits.max_total_items,
        })?;
    }
    let mut merged = Parsed {
        items: Vec::new(),
        skipped: Skipped::default(),
    };
    let mut seen = HashSet::new();
    pages.into_iter().for_each(|page| merge_page(&mut merged, &mut seen, page.parsed, uid_of));
    let mut unique = HashSet::new();
    merged.skipped.refused_uids.retain(|uid| unique.insert(uid.clone()));
    drop_shadowed_refusals(&mut merged.skipped, &seen);
    let skipped_total = merged.skipped.unparsable + merged.skipped.bad_field + merged.skipped.duplicate;
    if skipped_total > 0 {
        tracing::warn!(skipped_total, "page run merged with skipped elements");
    }
    Ok(merged)
}


pub fn merge_pod_pages(pages: Vec<Page<PodItem>>, page_limits: &PageLimits) -> Result<Parsed<PodItem>, ParseError> {
    merge_pages(pages, page_limits, pod_uid)
}


pub fn merge_node_pages(pages: Vec<Page<NodeItem>>, page_limits: &PageLimits) -> Result<Parsed<NodeItem>, ParseError> {
    merge_pages(pages, page_limits, node_uid)
}
