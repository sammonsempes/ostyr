use site_collector::spool::{append, open_spool, read_from, spool_stats};
use site_collector::spool_model::{Priority, SpoolConfig};
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;


const SEGMENT_BYTES: u64 = 8192;


const TOTAL_BYTES: u64 = 65536;


const PAYLOAD_BYTES: usize = 100;


const REPLAY_LIMIT: usize = 1_000_000;


const HIGH_EVERY: u64 = 10;


const PAIR: usize = 2;


const USAGE: &str = "usage: spool_proof fill <dir> <count> | show <dir>";


fn config() -> SpoolConfig {
    SpoolConfig {
        segment_max_bytes: SEGMENT_BYTES,
        total_max_bytes: TOTAL_BYTES,
    }
}


fn fill(dir: &str, count: u64) -> Result<(), Box<dyn Error>> {
    let mut spool = open_spool(Path::new(dir), config())?;
    for index in 0..count {
        let priority = if index % HIGH_EVERY == 0 { Priority::High } else { Priority::Low };
        append(&mut spool, priority, &[b'x'; PAYLOAD_BYTES])?;
    }
    writeln!(stdout(), "{:?}", spool_stats(&spool))?;
    Ok(())
}


fn show(dir: &str) -> Result<(), Box<dyn Error>> {
    let spool = open_spool(Path::new(dir), config())?;
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
        ["fill", dir, count] => fill(dir, count.parse()?),
        ["show", dir] => show(dir),
        _ => Err(USAGE.into()),
    }
}
