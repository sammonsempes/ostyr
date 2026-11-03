use crate::stream::normalise_stream;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;


/// Normalises `input` to `out`, then reports the counts (or the error) on `err`.
pub fn run_reporting<Input: BufRead, Output: Write, ErrorOutput: Write>(
    input: &mut Input,
    out: &mut Output,
    err: &mut ErrorOutput,
) -> io::Result<ExitCode> {
    match normalise_stream(input, out) {
        Ok(counts) => {
            writeln!(
                err,
                "processed={} malformed={} unknown={}",
                counts.processed, counts.malformed, counts.unknown
            )?;
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            writeln!(err, "{error}")?;
            Ok(ExitCode::FAILURE)
        }
    }
}
