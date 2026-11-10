use crate::convert::{convert, Outcome};
use crate::error::{LineError, NormaliseError};
use crate::suricata::parse_eve;
use crate::sysmon::{normalise_sysmon, UNKNOWN_DATASET};
use crate::tetragon::Envelope;
use crate::types::{LineNumber, SeenIds};
use core_export::ecs::EcsEvent;
use serde_json::{from_str, from_value, to_writer, Value};
use std::io::{self, BufRead, Read, Write};
use std::iter::from_fn;
use std::str::FromStr;
use tracing::warn;


pub const MAX_LINE_BYTES: u64 = 1_048_576;


const LINE_END: u8 = b'\n';


/// What happened to every line read: converted, refused as malformed, or well formed but of an unmapped kind.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub processed: u64,
    pub malformed: u64,
    pub unknown: u64,
    pub duplicate: u64,
}


/// The kind of line a stream carries.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    #[default]
    Tetragon,
    Sysmon,
    Suricata,
}


impl FromStr for Format {
    type Err = NormaliseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "tetragon" => Ok(Format::Tetragon),
            "sysmon" => Ok(Format::Sysmon),
            "suricata" => Ok(Format::Suricata),
            other => Err(NormaliseError::UnknownFormat(other.to_string())),
        }
    }
}


/// How a Sysmon line was mapped: a known id, an unmapped id seen for the first time, or an unmapped id seen before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysmonClass {
    Known,
    Unmapped,
    Repeated,
}


#[derive(Debug, PartialEq, Eq)]
pub enum RawLine {
    Text(Vec<u8>),
    TooLong,
}


/// Reads at most `max_line` bytes of the next line; the rest of a longer line is skipped without being stored. `None` at end of input.
pub fn read_raw_line<Input: BufRead>(input: &mut Input, max_line: u64) -> io::Result<Option<RawLine>> {
    let mut buffer = Vec::new();
    let mut limited = input.by_ref().take(max_line + 1);
    let read = limited.read_until(LINE_END, &mut buffer)?;
    let exhausted = limited.limit() == 0;
    if read == 0 {
        Ok(None)
    } else if buffer.last() == Some(&LINE_END) {
        buffer.pop();
        Ok(Some(RawLine::Text(buffer)))
    } else if exhausted {
        input.skip_until(LINE_END)?;
        Ok(Some(RawLine::TooLong))
    } else {
        Ok(Some(RawLine::Text(buffer)))
    }
}


/// Parses one JSON line into an ECS event or an unknown-kind marker.
pub fn parse_line(text: &str) -> Result<Outcome, NormaliseError> {
    let value: Value = from_str(text).map_err(NormaliseError::Syntax)?;
    let envelope: Envelope = from_value(value).map_err(NormaliseError::Schema)?;
    convert(envelope)
}


/// Same as `parse_line` with the line number attached to the error.
pub fn normalise_line(line: LineNumber, text: &str) -> Result<Outcome, LineError> {
    parse_line(text).map_err(|error| LineError { line, error })
}


/// Turns one raw line into UTF-8 text, attaching the line number to every error.
pub fn line_text(line: LineNumber, raw: RawLine, max_line: u64) -> Result<String, LineError> {
    match raw {
        RawLine::TooLong => Err(LineError {
            line,
            error: NormaliseError::TooLong { max: max_line },
        }),
        RawLine::Text(bytes) => String::from_utf8(bytes).map_err(|error| LineError {
            line,
            error: NormaliseError::from(error.utf8_error()),
        }),
    }
}


/// Turns one raw line into an outcome, attaching the line number to every error.
pub fn decode(line: LineNumber, raw: RawLine, max_line: u64) -> Result<Outcome, LineError> {
    line_text(line, raw, max_line).and_then(|text| normalise_line(line, &text))
}


/// Turns one raw Suricata EVE line into an outcome, attaching the line number to every error.
pub fn decode_suricata(line: LineNumber, raw: RawLine, max_line: u64) -> Result<Outcome, LineError> {
    line_text(line, raw, max_line).and_then(|text| parse_eve(&text).map_err(|error| LineError { line, error }))
}


/// Turns one raw Sysmon line into an ECS event and its class; `seen` keeps the unmapped ids across the stream.
pub fn decode_sysmon(line: LineNumber, raw: RawLine, max_line: u64, seen: &mut SeenIds) -> Result<(EcsEvent, SysmonClass), LineError> {
    let text = line_text(line, raw, max_line)?;
    let seen_before = seen.len();
    let event = normalise_sysmon(&text, seen).map_err(|error| LineError {
        line,
        error: NormaliseError::Sysmon(error),
    })?;
    let class = match (event.event.dataset.as_deref() == Some(UNKNOWN_DATASET), seen.len() > seen_before) {
        (false, _) => SysmonClass::Known,
        (true, true) => SysmonClass::Unmapped,
        (true, false) => SysmonClass::Repeated,
    };
    Ok((event, class))
}


/// Writes one ECS event as a JSON line.
pub fn write_event<Output: Write>(output: &mut Output, event: &EcsEvent) -> Result<(), NormaliseError> {
    to_writer(&mut *output, event).map_err(NormaliseError::Serialize)?;
    writeln!(output).map_err(NormaliseError::from)
}


fn tally<Output: Write>(
    counts: Counts,
    line: LineNumber,
    outcome: Result<Outcome, LineError>,
    output: &mut Output,
) -> Result<Counts, NormaliseError> {
    match outcome {
        Ok(Outcome::Event(event)) => {
            write_event(output, &event)?;
            Ok(Counts {
                processed: counts.processed + 1,
                ..counts
            })
        }
        Ok(Outcome::Unknown(kind)) => {
            warn!(line, kind, "unknown event kind");
            Ok(Counts {
                unknown: counts.unknown + 1,
                ..counts
            })
        }
        Err(error) => {
            warn!(line, %error, "malformed line");
            Ok(Counts {
                malformed: counts.malformed + 1,
                ..counts
            })
        }
    }
}


fn tally_sysmon<Output: Write>(
    counts: Counts,
    line: LineNumber,
    outcome: Result<(EcsEvent, SysmonClass), LineError>,
    output: &mut Output,
) -> Result<Counts, NormaliseError> {
    match outcome {
        Ok((event, class)) => {
            write_event(output, &event)?;
            Ok(match class {
                SysmonClass::Known => Counts {
                    processed: counts.processed + 1,
                    ..counts
                },
                SysmonClass::Unmapped => Counts {
                    unknown: counts.unknown + 1,
                    ..counts
                },
                SysmonClass::Repeated => Counts {
                    duplicate: counts.duplicate + 1,
                    ..counts
                },
            })
        }
        Err(error) => {
            warn!(line, %error, "malformed line");
            Ok(Counts {
                malformed: counts.malformed + 1,
                ..counts
            })
        }
    }
}


/// Reads Tetragon or Sysmon lines and writes ECS JSON lines; a bad line is counted and logged, only an I/O error stops the stream.
pub fn normalise_stream_capped<Input: BufRead, Output: Write>(
    input: &mut Input,
    output: &mut Output,
    max_line: u64,
    format: Format,
) -> Result<Counts, NormaliseError> {
    normalise_dyn(input, output, max_line, format)
}


/// The stream loop on trait objects, so that one instantiation serves every caller.
pub fn normalise_dyn(mut input: &mut dyn BufRead, mut output: &mut dyn Write, max_line: u64, format: Format) -> Result<Counts, NormaliseError> {
    let mut seen = SeenIds::new();
    (1..)
        .zip(from_fn(|| read_raw_line(&mut input, max_line).transpose()))
        .try_fold(Counts::default(), |counts, (line, raw_line)| {
            let raw = raw_line?;
            match format {
                Format::Tetragon => tally(counts, line, decode(line, raw, max_line), &mut output),
                Format::Suricata => tally(counts, line, decode_suricata(line, raw, max_line), &mut output),
                Format::Sysmon => tally_sysmon(counts, line, decode_sysmon(line, raw, max_line, &mut seen), &mut output),
            }
        })
}


/// `normalise_stream_capped` with the production line cap.
pub fn normalise_stream_format<Input: BufRead, Output: Write>(
    input: &mut Input,
    output: &mut Output,
    format: Format,
) -> Result<Counts, NormaliseError> {
    normalise_stream_capped(input, output, MAX_LINE_BYTES, format)
}


/// `normalise_stream_format` for Tetragon lines.
pub fn normalise_stream<Input: BufRead, Output: Write>(input: &mut Input, output: &mut Output) -> Result<Counts, NormaliseError> {
    normalise_stream_format(input, output, Format::Tetragon)
}
