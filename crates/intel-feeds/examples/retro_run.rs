use core_config::load::load_file;
use intel_feeds::config::FeedsFile;
use intel_feeds::limits::{MAX_RETRO_MATCHES, MAX_RETRO_ROWS_TO_GROUP, MAX_RETRO_ROWS_TO_READ, MAX_RETRO_SECONDS};
use intel_feeds::retro::{run_retro, RetroSettings};
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;
use std::time::Instant;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const USAGE: &str = "usage: retro_run <feeds-file> <events-database> <events-table> <start-rfc3339> <end-rfc3339> [max_matches=N] [seconds=N] [rows_to_read=N] [rows_to_group=N] [previous_end=RFC3339]";


fn option<'a>(rest: &'a [String], name: &str) -> Option<&'a str> {
    rest.iter()
        .find_map(|text| text.strip_prefix(name).and_then(|tail| tail.strip_prefix('=')))
}


fn run(feeds_file: &str, database: &str, table: &str, start: &str, end: &str, rest: &[String]) -> Result<(), Box<dyn Error>> {
    let feeds: FeedsFile = load_file(Path::new(feeds_file))?;
    let reader = feeds.clickhouse.ok_or("the feeds file has no clickhouse section")?;
    let settings = RetroSettings {
        reader,
        events_database: database.to_owned(),
        events_table: table.to_owned(),
        max_matches: option(rest, "max_matches").map_or(Ok(MAX_RETRO_MATCHES), str::parse)?,
        max_execution_seconds: option(rest, "seconds").map_or(Ok(MAX_RETRO_SECONDS), str::parse)?,
        max_rows_to_read: option(rest, "rows_to_read").map_or(Ok(MAX_RETRO_ROWS_TO_READ), str::parse)?,
        max_rows_to_group_by: option(rest, "rows_to_group").map_or(Ok(MAX_RETRO_ROWS_TO_GROUP), str::parse)?,
    };
    let previous_end = option(rest, "previous_end")
        .map(|text| OffsetDateTime::parse(text, &Rfc3339))
        .transpose()?;
    let started = Instant::now();
    let outcome = run_retro(
        &settings,
        OffsetDateTime::parse(start, &Rfc3339)?,
        OffsetDateTime::parse(end, &Rfc3339)?,
        previous_end,
        &|| started.elapsed(),
    )?;
    writeln!(stdout(), "{}", serde_json::to_string_pretty(&outcome)?)?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [feeds_file, database, table, start, end, rest @ ..] => run(feeds_file, database, table, start, end, rest),
        _ => Err(USAGE.into()),
    }
}
