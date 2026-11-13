use crate::error::StatsError;
use crate::model::{BeaconScore, KeyReport};
use std::io::Write;


/// One line per key: entity count, key, example entities; then the dropped-row counter.
pub fn write_key_report(report: &KeyReport, writer: &mut dyn Write) -> Result<(), StatsError> {
    report
        .keys
        .iter()
        .try_for_each(|entry| writeln!(writer, "{}\t{}\t{}", entry.entities, entry.key, entry.examples.join(",")))?;
    writeln!(writer, "rows_dropped={}", report.rows_dropped)?;
    Ok(())
}


/// The score, or `none` when it is undefined.
pub fn write_beacon(score: Option<&BeaconScore>, writer: &mut dyn Write) -> Result<(), StatsError> {
    match score {
        Some(found) => writeln!(
            writer,
            "events={} median_interval={} mad={} regularity_ppm={}",
            found.events, found.median_interval, found.mad, found.regularity_ppm
        )?,
        None => writeln!(writer, "none")?,
    }
    Ok(())
}
