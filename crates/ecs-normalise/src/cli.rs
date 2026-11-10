use crate::error::NormaliseError;
use crate::stream::{normalise_stream_format, Counts, Format};
use std::io::{self, BufRead, Write};
use std::process::ExitCode;


const FORMAT_FLAG: &str = "--format";


/// Reads the format from the arguments: none means Tetragon, `--format <name>` picks one.
pub fn parse_format(args: &[&str]) -> Result<Format, NormaliseError> {
    match args {
        [] => Ok(Format::default()),
        [FORMAT_FLAG, name] => name.parse(),
        _ => Err(NormaliseError::Usage),
    }
}


/// Writes the counts line (or the error) on `err`; the duplicate count is shown for Sysmon only.
pub fn report(result: Result<(Format, Counts), NormaliseError>, err: &mut dyn Write) -> io::Result<ExitCode> {
    match result {
        Ok((Format::Tetragon | Format::Suricata, counts)) => {
            writeln!(
                err,
                "processed={} malformed={} unknown={}",
                counts.processed, counts.malformed, counts.unknown
            )?;
            Ok(ExitCode::SUCCESS)
        }
        Ok((Format::Sysmon, counts)) => {
            writeln!(
                err,
                "processed={} malformed={} unknown={} duplicate={}",
                counts.processed, counts.malformed, counts.unknown, counts.duplicate
            )?;
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            writeln!(err, "{error}")?;
            Ok(ExitCode::FAILURE)
        }
    }
}


/// Normalises `input` to `out`, then reports the counts (or the error) on `err`.
pub fn run_reporting<Input: BufRead, Output: Write, ErrorOutput: Write>(
    args: &[&str],
    input: &mut Input,
    out: &mut Output,
    err: &mut ErrorOutput,
) -> io::Result<ExitCode> {
    let result = parse_format(args).and_then(|format| normalise_stream_format(input, out, format).map(|counts| (format, counts)));
    report(result, err)
}
