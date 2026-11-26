use crate::config::{FeedConfig, FeedsFile};
use crate::dedup::{insert_ioc, is_expired};
use crate::error::FeedError;
use crate::export::export_bundle;
use crate::formats::parse_feed;
use crate::limits::{MAX_FEED_FILE_BYTES, MAX_ROUND_IOCS};
use crate::model::{Collector, FeedSummary, Ioc};
use crate::types::{ExportRun, IocIndex, IocKey, OpenFn};
use std::collections::BTreeSet;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, BufRead, Cursor, ErrorKind, Read, Write};
use std::path::Path;
use time::OffsetDateTime;
use tracing::error;


pub const NOT_REGULAR: &str = "the feed file is not a regular file";


pub const TOO_LARGE: &str = "the feed file is larger than the byte cap";


pub const SYMLINK: &str = "the feed file is a symlink";


pub const PROC_SELF_FD: &str = "/proc/self/fd";


/// A feed file opened without blocking, judged on the handle: a regular file, read through that handle only; more than the byte cap read is `TOO_LARGE`.
pub fn open_file(path: &Path) -> io::Result<Box<dyn BufRead>> {
    open_file_with(path, File::metadata)
}


/// `inspect` is injected so that a failing inspection can be tested; the size is judged on the handle that is read.
pub fn open_file_with(path: &Path, inspect: fn(&File) -> io::Result<Metadata>) -> io::Result<Box<dyn BufRead>> {
    let handle = open_handle(path, inspect)?;
    let metadata = inspect(&handle)?;
    if metadata.len() > MAX_FEED_FILE_BYTES {
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


/// The path is opened `O_PATH | O_NOFOLLOW` through rustix (Rust's musl build drops `O_PATH` from `custom_flags`: `O_ACCMODE` includes it there), its type judged on that handle, then reopened through `/proc/self/fd`.
#[cfg(unix)]
pub fn open_handle(path: &Path, inspect: fn(&File) -> io::Result<Metadata>) -> io::Result<File> {
    let flags = rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    let anchor = File::from(rustix::fs::open(path, flags, rustix::fs::Mode::empty()).map_err(io::Error::from)?);
    let kind = inspect(&anchor)?.file_type();
    if kind.is_symlink() {
        Err(io::Error::new(ErrorKind::InvalidInput, SYMLINK))
    } else if !kind.is_file() {
        Err(io::Error::new(ErrorKind::InvalidInput, NOT_REGULAR))
    } else {
        let mut options = OpenOptions::new();
        options.read(true);
        std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK | libc::O_NOCTTY);
        options.open(Path::new(PROC_SELF_FD).join(std::os::fd::AsRawFd::as_raw_fd(&anchor).to_string()))
    }
}


#[cfg(not(unix))]
pub fn open_handle(path: &Path, inspect: fn(&File) -> io::Result<Metadata>) -> io::Result<File> {
    let handle = OpenOptions::new().read(true).open(path)?;
    if inspect(&handle)?.is_file() {
        Ok(handle)
    } else {
        Err(io::Error::new(ErrorKind::InvalidInput, NOT_REGULAR))
    }
}


/// The keys `iocs` would add to `index`: not expired, not yet there, counted once.
pub fn fresh_keys(iocs: &[Ioc], now: OffsetDateTime, index: &IocIndex) -> BTreeSet<IocKey> {
    iocs.iter()
        .filter(|ioc| !is_expired(ioc, now))
        .map(|ioc| (ioc.ioc_type, ioc.value.clone()))
        .filter(|key| !index.contains_key(key))
        .collect()
}


/// A feed that would take the round over `MAX_ROUND_IOCS` merged IOCs is left out whole and named; the index never exceeds the total.
pub fn left_out(feed: &str, reason: &str) -> FeedSummary {
    FeedSummary {
        feed: feed.to_owned(),
        failed: Some(reason.to_owned()),
        ..FeedSummary::default()
    }
}


/// Drops expired IOCs and counts them, merges the rest into `index` and counts the duplicates; over the round total the feed is left out.
pub fn merge_collected(collector: Collector, now: OffsetDateTime, index: &mut IocIndex) -> FeedSummary {
    let Collector { iocs, mut summary } = collector;
    if index.len().saturating_add(fresh_keys(&iocs, now, index).len()) > MAX_ROUND_IOCS {
        left_out(
            &summary.feed,
            &format!("round_ioc_cap: the round would hold more than {MAX_ROUND_IOCS} IOCs, feed left out"),
        )
    } else {
        iocs.into_iter().for_each(|ioc| {
            if is_expired(&ioc, now) {
                summary.expired += 1;
            } else if insert_ioc(index, ioc) {
                summary.duplicates += 1;
            }
        });
        summary
    }
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
