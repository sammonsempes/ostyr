//! Usage: `ad_posture <snapshot.json> <thresholds.yaml> [now-unix-seconds]`.
use ad_posture::checks::assess;
use ad_posture::limits::Limits;
use ad_posture::report::report_lines;
use ad_posture::snapshot::read_snapshot;
use ad_posture::thresholds::load_thresholds;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};


const SNAPSHOT_ARGUMENT: usize = 1;


const THRESHOLDS_ARGUMENT: usize = 2;


const NOW_ARGUMENT: usize = 3;


fn now_of(arguments: &[String]) -> Result<i64, Box<dyn Error + Send + Sync>> {
    match arguments.get(NOW_ARGUMENT) {
        Some(text) => Ok(text.parse()?),
        None => Ok(i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?),
    }
}


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments: Vec<String> = std::env::args().collect();
    let snapshot = read_snapshot(
        File::open(arguments.get(SNAPSHOT_ARGUMENT).ok_or("missing snapshot.json")?)?,
        &Limits::default(),
    )?;
    let thresholds = load_thresholds(Path::new(arguments.get(THRESHOLDS_ARGUMENT).ok_or("missing thresholds.yaml")?))?;
    let report = assess(&snapshot, &thresholds, now_of(&arguments)?);
    let mut out = stdout();
    report_lines(&report).try_for_each(|line| writeln!(out, "{line}"))?;
    Ok(())
}
