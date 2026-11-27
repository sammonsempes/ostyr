//! One service round: every feed is read or polled, a failed feed is named and never stops the others, then one load.

use crate::budget::Stored;
use crate::config::{FeedConfig, FeedFormat, FeedsFile};
use crate::limits::MAX_LOGGED_FEED_NAMES;
use crate::load::{summarise, LoadSummary};
use crate::model::{Collector, FeedSummary, Ioc};
use crate::read::ReadError;
use crate::run::{ingest, merge_collected};
use crate::sample::bounded_text;
use crate::taxii::PollOutcome;
use crate::types::{ClockFn, CursorKey, Cursors, IocIndex, LoadFn, OpenFn, PollFn, StoredFn};
use std::collections::BTreeSet;
use time::OffsetDateTime;
use tracing::{info, warn};


pub const NO_CLICKHOUSE: &str = "the feeds file has no clickhouse section";


/// The injected edges of a round: clock, file reader, TAXII poll and ClickHouse load.
pub struct RoundHooks<'a> {
    pub clock: &'a ClockFn<'a>,
    pub open: &'a OpenFn<'a>,
    pub poll: &'a PollFn<'a>,
    pub load: &'a LoadFn<'a>,
    pub stored: &'a StoredFn<'a>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundReport {
    pub feeds: usize,
    pub failed_feeds: Vec<String>,
    pub iocs: usize,
    pub warned: usize,
    pub load: Option<LoadSummary>,
    pub load_error: Option<String>,
}


/// A failed poll is reported in the feed's summary; the cursor advances only through `advanced`, applied after a stored load.
pub fn poll_into(
    feed: &FeedConfig,
    now: OffsetDateTime,
    hooks: &RoundHooks,
    cursors: &Cursors,
    index: &mut IocIndex,
    advanced: &mut Cursors,
    stored: &Stored,
) -> FeedSummary {
    let key = cursor_key(feed);
    let cursor = key.as_ref().and_then(|identity| cursors.get(identity)).copied();
    log_new_identity(feed, cursor, cursors);
    match (hooks.poll)(feed, cursor, now) {
        Ok(outcome) => {
            log_early_stop(feed, &outcome);
            let next = outcome.next_added_after;
            let summary = merge_collected(
                Collector {
                    iocs: outcome.iocs,
                    summary: outcome.summary,
                },
                now,
                index,
                stored,
            );
            if summary.failed.is_none() {
                key.iter().zip(next.iter()).for_each(|(identity, moved)| {
                    advanced.insert(identity.clone(), *moved);
                });
            }
            summary
        }
        Err(failure) => FeedSummary {
            feed: feed.name.clone(),
            failed: Some(failure.to_string()),
            ..FeedSummary::default()
        },
    }
}


/// The whole parsed configuration of a TAXII feed (rendered once), so any reload change to it, the TLP or the TTL included, polls from scratch.
pub fn cursor_key(feed: &FeedConfig) -> Option<CursorKey> {
    feed.taxii.as_ref().map(|_| (feed.name.clone(), format!("{feed:?}")))
}


/// A feed name known under another identity is polled in full, and the log says so.
pub fn log_new_identity(feed: &FeedConfig, cursor: Option<OffsetDateTime>, cursors: &Cursors) {
    let renamed = cursor.is_none() && cursors.keys().any(|(name, ..)| *name == feed.name);
    let name = feed.name.as_str();
    if renamed {
        warn!(name, "intel taxii feed settings changed, polled from scratch");
    }
}


/// A poll cut by `max_pages`, the IOC cap or a refused `next` is named, never silent.
pub fn log_early_stop(feed: &FeedConfig, outcome: &PollOutcome) {
    let (name, pages, more_left, next_refused) = (feed.name.as_str(), outcome.pages, outcome.more_left, outcome.next_refused);
    if more_left || next_refused {
        warn!(name, pages, more_left, next_refused, "intel taxii poll stopped early");
    }
}


pub fn log_feed(summary: &FeedSummary) {
    let skipped: u64 = summary.skipped.values().sum();
    let (feed, parsed, expired, duplicates) = (summary.feed.as_str(), summary.parsed, summary.expired, summary.duplicates);
    match summary.failed.as_deref() {
        Some(reason) => warn!(feed, reason, "intel feed failed"),
        None => info!(feed, parsed, skipped, expired, duplicates, "intel feed read"),
    }
    if let Some(warning) = summary.warning {
        warn!(feed, warning, "intel feed warning");
    }
}


/// One line per round: counts, the first failed feed names and the load result; `warn` when anything failed.
pub fn log_round(report: &RoundReport) {
    let (feeds, iocs) = (report.feeds, report.iocs);
    let failed = report.failed_feeds.len();
    let names = report
        .failed_feeds
        .iter()
        .take(MAX_LOGGED_FEED_NAMES)
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    let load_error = report.load_error.as_deref().unwrap_or("none");
    let (rows, stored, refused, not_canonical) = report.load.as_ref().map_or((0, 0, 0, 0), |load| {
        (
            load.clickhouse_rows_sent,
            load.clickhouse_batches_stored,
            load.clickhouse_batches_failed,
            load.clickhouse_rows_not_canonical,
        )
    });
    let warned = report.warned;
    let counts = format!("feeds={feeds} iocs={iocs} rows={rows} stored={stored} refused={refused} not_canonical={not_canonical}");
    if failed == 0 && report.load_error.is_none() {
        info!(feeds, iocs, rows, stored, warned, "intel round done");
    } else {
        warn!(failed, warned, names, load_error, counts, "intel round failed");
    }
}


pub const STORED_PREFIX: &str = "stored_ioc_";


pub const NO_STORED: Stored = Stored {
    keys: BTreeSet::new(),
    live: 0,
    bytes: 0,
    exceeded: false,
    top: Vec::new(),
};


/// The feeds left out for the stored bound and the feeds holding the most live rows (any feed of the tenant, the settings' or not), each name bounded.
pub fn log_stored_cap(summaries: &[FeedSummary], stored: &Stored) {
    let left_out = summaries
        .iter()
        .filter(|summary| summary.failed.as_deref().is_some_and(|reason| reason.starts_with(STORED_PREFIX)))
        .take(MAX_LOGGED_FEED_NAMES)
        .map(|summary| bounded_text(&summary.feed))
        .collect::<Vec<_>>();
    let holding = stored
        .top
        .iter()
        .take(MAX_LOGGED_FEED_NAMES)
        .map(|(feed, live)| format!("{}={live}", bounded_text(feed)))
        .collect::<Vec<_>>();
    let (live, bytes, exceeded) = (stored.live, stored.bytes, stored.exceeded);
    if !left_out.is_empty() {
        let names = left_out.join(",");
        let largest = holding.join(",");
        warn!(live, bytes, exceeded, names, largest, "intel feeds left out: stored bound");
    }
}


/// A round whose stored rows cannot be read touches nothing: no feed is read or polled, nothing is loaded, every cursor stays.
pub fn unreadable_round(config: &FeedsFile, failure: &ReadError) -> RoundReport {
    let report = RoundReport {
        feeds: config.feeds.len(),
        failed_feeds: Vec::new(),
        iocs: 0,
        warned: 0,
        load: None,
        load_error: Some(format!("stored_count_unreadable: {failure}")),
    };
    log_round(&report);
    report
}


/// The stored budget first (under the caller's gate), then the round; without a `clickhouse` section the budget is empty and the load is the named failure.
pub fn run_round(config: &FeedsFile, cursors: &mut Cursors, hooks: &RoundHooks) -> RoundReport {
    let now = (hooks.clock)();
    let stored = config.clickhouse.as_ref().map(|clickhouse| (hooks.stored)(clickhouse, now)).transpose();
    match stored {
        Ok(budget) => run_with(config, cursors, hooks, now, budget.as_ref().unwrap_or(&NO_STORED)),
        Err(failure) => unreadable_round(config, &failure),
    }
}


/// Every feed runs whatever the others did, then one load of the merged IOCs; the TAXII cursors move only when the load stored every batch.
pub fn run_with(config: &FeedsFile, cursors: &mut Cursors, hooks: &RoundHooks, now: OffsetDateTime, stored: &Stored) -> RoundReport {
    let mut index = IocIndex::new();
    let mut advanced = Cursors::new();
    let summaries: Vec<FeedSummary> = config
        .feeds
        .iter()
        .map(|feed| {
            if feed.format == FeedFormat::Taxii21 {
                poll_into(feed, now, hooks, cursors, &mut index, &mut advanced, stored)
            } else {
                ingest(feed, now, hooks.open, &mut index, stored)
            }
        })
        .collect();
    summaries.iter().for_each(log_feed);
    log_stored_cap(&summaries, stored);
    let iocs: Vec<Ioc> = index.into_values().collect();
    let load = config
        .clickhouse
        .as_ref()
        .map(|clickhouse| summarise(&(hooks.load)(clickhouse, &iocs, &config.feeds, now)));
    let load_error = load
        .as_ref()
        .map_or_else(|| Some(NO_CLICKHOUSE.to_owned()), |summary| summary.error.clone());
    if load_error.is_none() {
        cursors.extend(advanced);
        let current: Vec<CursorKey> = config.feeds.iter().filter_map(cursor_key).collect();
        cursors.retain(|identity, _| current.contains(identity));
    }
    let report = RoundReport {
        feeds: summaries.len(),
        failed_feeds: summaries
            .iter()
            .filter(|summary| summary.failed.is_some())
            .map(|summary| summary.feed.clone())
            .collect(),
        iocs: iocs.len(),
        warned: summaries.iter().filter(|summary| summary.warning.is_some()).count(),
        load,
        load_error,
    };
    log_round(&report);
    report
}
