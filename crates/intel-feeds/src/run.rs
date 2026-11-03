use crate::config::{FeedConfig, FeedsFile};
use crate::dedup::{insert_ioc, is_expired};
use crate::error::FeedError;
use crate::formats::parse_feed;
use crate::model::{Collector, FeedSummary};
use crate::types::{IocIndex, OpenFn};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use time::OffsetDateTime;
use tracing::error;


pub fn open_file(path: &Path) -> io::Result<Box<dyn BufRead>> {
    Ok(Box::new(BufReader::new(File::open(path)?)))
}


/// Drops expired IOCs and counts them, merges the rest into `index` and counts the duplicates.
pub fn merge_collected(collector: Collector, now: OffsetDateTime, index: &mut IocIndex) -> FeedSummary {
    let Collector { iocs, mut summary } = collector;
    iocs.into_iter().for_each(|ioc| {
        if is_expired(&ioc, now) {
            summary.expired += 1;
        } else if insert_ioc(index, ioc) {
            summary.duplicates += 1;
        }
    });
    summary
}


/// A feed that cannot be read is reported in its summary and does not stop the others.
pub fn ingest(feed: &FeedConfig, now: OffsetDateTime, open: &OpenFn, index: &mut IocIndex) -> FeedSummary {
    match open(&feed.path)
        .map_err(FeedError::Io)
        .and_then(|mut reader| parse_feed(feed, &mut reader, now))
    {
        Ok(collector) => merge_collected(collector, now, index),
        Err(failure) => {
            error!(feed = feed.name, %failure, "feed skipped");
            FeedSummary {
                feed: feed.name.clone(),
                failed: Some(failure.to_string()),
                ..FeedSummary::default()
            }
        }
    }
}


/// One JSON object per line, in (type, value) order.
pub fn write_iocs(index: &IocIndex, out: &mut dyn Write) -> io::Result<()> {
    index.values().try_for_each(|ioc| {
        serde_json::to_writer(&mut *out, ioc)?;
        writeln!(out)
    })
}


/// Parses every feed, deduplicates across feeds, then streams the normalised IOCs to `out`.
pub fn run_feeds(config: &FeedsFile, now: OffsetDateTime, open: &OpenFn, out: &mut dyn Write) -> io::Result<Vec<FeedSummary>> {
    let mut index = IocIndex::new();
    let summaries = config.feeds.iter().map(|feed| ingest(feed, now, open, &mut index)).collect();
    write_iocs(&index, out)?;
    Ok(summaries)
}
