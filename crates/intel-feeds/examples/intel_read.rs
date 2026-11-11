use core_config::load::load_file;
use intel_feeds::config::FeedsFile;
use intel_feeds::read::read_iocs;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


fn start(feeds_file: &str, fixed_now: Option<&String>) -> Result<(), Box<dyn Error>> {
    let feeds: FeedsFile = load_file(Path::new(feeds_file))?;
    let config = feeds.clickhouse.ok_or("the feeds file has no clickhouse section")?;
    let now = fixed_now.map_or(Ok(OffsetDateTime::now_utc()), |text| OffsetDateTime::parse(text, &Rfc3339))?;
    let summary = read_iocs(&config, now, &mut stdout())?;
    writeln!(stderr(), "rows={} bad_rows={}", summary.rows, summary.bad_rows)?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [feeds_file] => start(feeds_file, None),
        [feeds_file, fixed_now] => start(feeds_file, Some(fixed_now)),
        _ => Err("usage: intel_read <feeds-file> [fixed-now-rfc3339]".into()),
    }
}
