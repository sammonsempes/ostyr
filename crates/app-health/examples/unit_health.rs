//! Usage: unit_health <units.yaml> <unit> <show.txt> [<previous-show.txt>] [<journal.txt>]; prints the unit verdict and the bounded log excerpt.

use app_health::journal::log_excerpt;
use app_health::limits::DEFAULT_MAX_BYTES;
use app_health::units::{assess_unit, load_expectations, parse_unit_show};
use std::io::Write;


const EXCERPT_LINES: usize = 20;


const MAX_EXTRA_ARGS: usize = 2;


const EXCERPT_LINE_BYTES: usize = 512;


fn report(expectations_path: &str, unit: &str, show_path: &str, extra: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let expectations = load_expectations(&std::fs::read_to_string(expectations_path)?, expectations_path)?;
    let expectation = expectations
        .iter()
        .find(|item| item.unit == unit)
        .ok_or("unit not in the expectations file")?;
    let current = parse_unit_show(std::fs::File::open(show_path)?, DEFAULT_MAX_BYTES, unit)?;
    let previous = extra
        .first()
        .map(|path| parse_unit_show(std::fs::File::open(path)?, DEFAULT_MAX_BYTES, unit))
        .transpose()?;
    let mut out = std::io::stdout();
    writeln!(
        out,
        "verdict={:?} state={:?}",
        assess_unit(expectation, previous.as_ref(), &current),
        current
    )?;
    if let Some(journal_path) = extra.get(1) {
        let excerpt = log_excerpt(std::fs::File::open(journal_path)?, EXCERPT_LINES, EXCERPT_LINE_BYTES)?;
        writeln!(out, "omitted={} input_truncated={}", excerpt.omitted, excerpt.input_truncated)?;
        excerpt.lines.iter().try_for_each(|line| writeln!(out, "log: {line}"))?;
    }
    Ok(())
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [expectations_path, unit, show_path, extra @ ..] if extra.len() <= MAX_EXTRA_ARGS => report(expectations_path, unit, show_path, extra),
        _ => Err("usage: unit_health <units.yaml> <unit> <show.txt> [<previous-show.txt>] [<journal.txt>]".into()),
    }
}
