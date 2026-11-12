use core_config::load::load_file;
use intel_feeds::config::FeedsFile;
use intel_feeds::load::load_iocs;
use intel_feeds::model::Ioc;
use std::error::Error;
use std::fs::File;
use std::io::{stderr, BufRead, BufReader, Write};
use std::path::Path;
use std::time::Instant;
use time::OffsetDateTime;


fn start(feeds_file: &str, ioc_file: &str) -> Result<(), Box<dyn Error>> {
    let feeds: FeedsFile = load_file(Path::new(feeds_file))?;
    let config = feeds.clickhouse.as_ref().ok_or("the feeds file has no clickhouse section")?;
    let iocs: Vec<Ioc> = BufReader::new(File::open(ioc_file)?)
        .lines()
        .map(|line| Ok(serde_json::from_str(&line?)?))
        .collect::<Result<_, Box<dyn Error>>>()?;
    let started = Instant::now();
    let outcome = load_iocs(config, &iocs, &feeds.feeds, OffsetDateTime::now_utc(), &|| started.elapsed())?;
    writeln!(stderr(), "{outcome:?}")?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [feeds_file, ioc_file] => start(feeds_file, ioc_file),
        _ => Err("usage: intel_load <feeds-file> <iocs.jsonl>".into()),
    }
}
