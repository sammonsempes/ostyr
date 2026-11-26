//! One service round: every feed is read or polled, a failed feed is named and never stops the others, then one load.

use crate::config::{FeedConfig, FeedFormat, FeedsFile};
use crate::limits::MAX_LOGGED_FEED_NAMES;
use crate::load::{summarise, LoadSummary};
use crate::model::{Collector, FeedSummary, Ioc};
use crate::run::{ingest, merge_collected};
use crate::taxii::PollOutcome;
use crate::types::{ClockFn, Cursors, IocIndex, LoadFn, OpenFn, PollFn};
use time::OffsetDateTime;
use tracing::{info, warn};


pub const NO_CLICKHOUSE: &str = "the feeds file has no clickhouse section";


/// The injected edges of a round: clock, file reader, TAXII poll and ClickHouse load.
pub struct RoundHooks<'a> {
    pub clock: &'a ClockFn<'a>,
    pub open: &'a OpenFn<'a>,
    pub poll: &'a PollFn<'a>,
    pub load: &'a LoadFn<'a>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundReport {
    pub feeds: usize,
    pub failed_feeds: Vec<String>,
    pub iocs: usize,
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
) -> FeedSummary {
    match (hooks.poll)(feed, cursors.get(&feed.name).copied(), now) {
        Ok(outcome) => {
            log_early_stop(feed, &outcome);
            outcome.next_added_after.iter().for_each(|next| {
                advanced.insert(feed.name.clone(), *next);
            });
            merge_collected(
                Collector {
                    iocs: outcome.iocs,
                    summary: outcome.summary,
                },
                now,
                index,
            )
        }
        Err(failure) => FeedSummary {
            feed: feed.name.clone(),
            failed: Some(failure.to_string()),
            ..FeedSummary::default()
        },
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
    let counts = format!("feeds={feeds} iocs={iocs} rows={rows} stored={stored} refused={refused} not_canonical={not_canonical}");
    if failed == 0 && report.load_error.is_none() {
        info!(feeds, iocs, rows, stored, "intel round done");
    } else {
        warn!(failed, names, load_error, counts, "intel round failed");
    }
}


/// Every feed runs whatever the others did, then one load of the merged IOCs; the TAXII cursors move only when the load stored every batch.
pub fn run_round(config: &FeedsFile, cursors: &mut Cursors, hooks: &RoundHooks) -> RoundReport {
    let now = (hooks.clock)();
    let mut index = IocIndex::new();
    let mut advanced = Cursors::new();
    let summaries: Vec<FeedSummary> = config
        .feeds
        .iter()
        .map(|feed| {
            if feed.format == FeedFormat::Taxii21 {
                poll_into(feed, now, hooks, cursors, &mut index, &mut advanced)
            } else {
                ingest(feed, now, hooks.open, &mut index)
            }
        })
        .collect();
    summaries.iter().for_each(log_feed);
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
    }
    let report = RoundReport {
        feeds: summaries.len(),
        failed_feeds: summaries
            .iter()
            .filter(|summary| summary.failed.is_some())
            .map(|summary| summary.feed.clone())
            .collect(),
        iocs: iocs.len(),
        load,
        load_error,
    };
    log_round(&report);
    report
}
