use crate::error::SourceError;
use crate::limits::{CLICKHOUSE_PREFIX, SOURCE_FAILED};
use crate::run::open_file;
use crate::types::{ClockFn, OpenFn};
use core_config::load::load_file;
use intel_feeds::config::{validate_feeds, FeedsFile};
use intel_feeds::read::{read_iocs, total_bad};
use std::io::{self, BufRead, Cursor};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use time::OffsetDateTime;
use tracing::warn;


/// The IOC lines of the feeds file's tenant and the count of rows left out; a read that is not complete is an error, never a partial list.
pub fn read_buffer(feeds_file: &Path, now: OffsetDateTime) -> Result<(Vec<u8>, u64), SourceError> {
    let feeds = load_file::<FeedsFile>(feeds_file)?;
    validate_feeds(&feeds)?;
    let config = feeds.clickhouse.ok_or(SourceError::Missing)?;
    let mut lines = Vec::new();
    let summary = read_iocs(&config, now, &mut lines)?;
    Ok((lines, total_bad(&summary.bad)))
}


/// Any failure is an `io::Error` with fixed text, so the run ends before the counter or the zone is touched.
pub fn clickhouse_open<'a>(feeds_file: &'a Path, clock: &'a ClockFn<'a>, rejected: &'a AtomicU64) -> impl Fn() -> io::Result<Box<dyn BufRead>> + 'a {
    move || {
        read_buffer(feeds_file, clock())
            .map(|(lines, bad_rows)| {
                rejected.store(bad_rows, Ordering::Relaxed);
                Box::new(Cursor::new(lines)) as Box<dyn BufRead>
            })
            .map_err(|error| {
                warn!(%error, "ClickHouse IOC source failed");
                io::Error::other(SOURCE_FAILED)
            })
    }
}


/// `clickhouse:<feeds.yaml>` reads the IOC table, anything else is a JSON-lines file.
pub fn open_source<'a>(spec: &'a str, clock: &'a ClockFn<'a>, rejected: &'a AtomicU64) -> Box<OpenFn<'a>> {
    match spec.strip_prefix(CLICKHOUSE_PREFIX) {
        Some(feeds_file) => Box::new(clickhouse_open(Path::new(feeds_file), clock, rejected)),
        None => Box::new(move || open_file(Path::new(spec))),
    }
}
