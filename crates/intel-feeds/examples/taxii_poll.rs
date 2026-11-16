use core_config::load::load_file;
use intel_feeds::config::{validate_feeds, FeedsFile};
use intel_feeds::taxii::poll_feed;
use serde_json::json;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::time::Instant;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const NO_CURSOR: &str = "none";


fn start(feeds_file: &str, feed_name: &str, added_after: &str) -> Result<(), Box<dyn Error>> {
    let feeds: FeedsFile = load_file(Path::new(feeds_file))?;
    validate_feeds(&feeds)?;
    let feed = feeds.feeds.iter().find(|candidate| candidate.name == feed_name).ok_or("no such feed")?;
    let cursor = (added_after != NO_CURSOR)
        .then(|| OffsetDateTime::parse(added_after, &Rfc3339))
        .transpose()?;
    let started = Instant::now();
    let outcome = poll_feed(feed, cursor, OffsetDateTime::now_utc(), &|| started.elapsed())?;
    let mut out = stdout();
    outcome.iocs.iter().try_for_each(|ioc| -> Result<(), Box<dyn Error>> {
        serde_json::to_writer(&mut out, ioc)?;
        Ok(writeln!(out)?)
    })?;
    let next_added_after = outcome.next_added_after.map(|next| next.format(&Rfc3339)).transpose()?;
    let report = json!({
        "pages": outcome.pages,
        "more_left": outcome.more_left,
        "next_refused": outcome.next_refused,
        "cursor": format!("{:?}", outcome.cursor),
        "next_added_after": next_added_after,
        "summary": outcome.summary,
    });
    Ok(writeln!(stderr(), "{report}")?)
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [feeds_file, feed_name, added_after] => start(feeds_file, feed_name, added_after),
        _ => Err("usage: taxii_poll <feeds.yaml> <feed> <added_after|none>".into()),
    }
}
