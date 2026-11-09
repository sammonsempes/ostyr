use site_collector::spool::{append, open_spool, read_from, spool_stats};
use site_collector::spool_model::{Priority, SpoolConfig};
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;


const REPLAY_LIMIT: usize = 1_000_000;


const HIGH_EVERY: u64 = 10;


const PAIR: usize = 2;


const USAGE: &str = "usage: spool_proof fill <dir> <segment_bytes> <total_bytes> <payload_bytes> <count> | show <dir> <segment_bytes> <total_bytes>";


fn config(segment_bytes: &str, total_bytes: &str) -> Result<SpoolConfig, Box<dyn Error>> {
    Ok(SpoolConfig {
        segment_max_bytes: segment_bytes.parse()?,
        total_max_bytes: total_bytes.parse()?,
    })
}


fn fill(dir: &str, config: SpoolConfig, payload_bytes: usize, count: u64) -> Result<(), Box<dyn Error>> {
    let mut spool = open_spool(Path::new(dir), config)?;
    let payload = vec![b'x'; payload_bytes];
    for index in 0..count {
        let priority = if index % HIGH_EVERY == 0 { Priority::High } else { Priority::Low };
        append(&mut spool, priority, &payload)?;
    }
    writeln!(stdout(), "{:?}", spool_stats(&spool))?;
    Ok(())
}


fn show(dir: &str, config: SpoolConfig) -> Result<(), Box<dyn Error>> {
    let spool = open_spool(Path::new(dir), config)?;
    let records = read_from(&spool, 0, REPLAY_LIMIT)?;
    let in_order = records
        .windows(PAIR)
        .all(|pair| matches!(pair, [left, right] if right.sequence == left.sequence + 1));
    writeln!(stdout(), "{:?}", spool_stats(&spool))?;
    writeln!(
        stdout(),
        "replayed {} records, first {:?}, last {:?}, contiguous {}",
        records.len(),
        records.first().map(|record| record.sequence),
        records.last().map(|record| record.sequence),
        in_order
    )?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["fill", dir, segment, total, payload, count] => fill(dir, config(segment, total)?, payload.parse()?, count.parse()?),
        ["show", dir, segment, total] => show(dir, config(segment, total)?),
        _ => Err(USAGE.into()),
    }
}
