use crate::config::{FeedConfig, FeedsFile};
use crate::dedup::{insert_ioc, is_expired};
use crate::error::FeedError;
use crate::export::export_bundle;
use crate::formats::parse_feed;
use crate::limits::MAX_FEED_FILE_BYTES;
use crate::model::{Collector, FeedSummary};
use crate::types::{ExportRun, IocIndex, OpenFn};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, BufRead, Cursor, ErrorKind, Read, Write};
use std::path::Path;
use time::OffsetDateTime;
use tracing::error;


pub const NOT_REGULAR: &str = "the feed file is not a regular file";


pub const TOO_LARGE: &str = "the feed file is larger than the byte cap";


pub const SYMLINK: &str = "the feed file is a symlink";


/// A feed file opened without blocking, judged on the handle: a regular file, read through that handle only; more than the byte cap read is `TOO_LARGE`.
pub fn open_file(path: &Path) -> io::Result<Box<dyn BufRead>> {
    open_file_with(path, File::metadata)
}


/// `inspect` is injected so that a failing inspection can be tested.
pub fn open_file_with(path: &Path, inspect: fn(&File) -> io::Result<Metadata>) -> io::Result<Box<dyn BufRead>> {
    let handle = open_handle(path)?;
    let metadata = inspect(&handle)?;
    if !metadata.is_file() {
        Err(io::Error::new(ErrorKind::InvalidInput, NOT_REGULAR))
    } else if metadata.len() > MAX_FEED_FILE_BYTES {
        Err(io::Error::new(ErrorKind::InvalidInput, TOO_LARGE))
    } else {
        read_within_cap(handle)
    }
}


/// Reads one byte past the cap so a file grown after the check is refused, never cut inside its last line.
pub fn read_within_cap(handle: File) -> io::Result<Box<dyn BufRead>> {
    let mut bytes = Vec::new();
    handle.take(MAX_FEED_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FEED_FILE_BYTES {
        Err(io::Error::new(ErrorKind::InvalidInput, TOO_LARGE))
    } else {
        Ok(Box::new(Cursor::new(bytes)))
    }
}


/// `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY`: a symlink is refused by name and a FIFO or device cannot stall the open.
#[cfg(unix)]
pub fn open_handle(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_NOCTTY);
    options.open(path).map_err(|source| {
        if source.raw_os_error() == Some(libc::ELOOP) {
            io::Error::new(ErrorKind::InvalidInput, SYMLINK)
        } else {
            source
        }
    })
}


#[cfg(not(unix))]
pub fn open_handle(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
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


/// Parses every feed and deduplicates across feeds.
pub fn collect_feeds(config: &FeedsFile, now: OffsetDateTime, open: &OpenFn) -> (IocIndex, Vec<FeedSummary>) {
    let mut index = IocIndex::new();
    let summaries = config.feeds.iter().map(|feed| ingest(feed, now, open, &mut index)).collect();
    (index, summaries)
}


/// Parses every feed, deduplicates across feeds, then streams the normalised IOCs to `out`.
pub fn run_feeds(config: &FeedsFile, now: OffsetDateTime, open: &OpenFn, out: &mut dyn Write) -> io::Result<Vec<FeedSummary>> {
    let (index, summaries) = collect_feeds(config, now, open);
    write_iocs(&index, out)?;
    Ok(summaries)
}


/// The normalised IOCs as a STIX 2.1 bundle under the configured export policy.
pub fn export_feeds(config: &FeedsFile, now: OffsetDateTime, open: &OpenFn, out: &mut dyn Write) -> io::Result<ExportRun> {
    let (index, summaries) = collect_feeds(config, now, open);
    let exported = export_bundle(&index, &config.export, out)?;
    Ok((summaries, exported))
}
