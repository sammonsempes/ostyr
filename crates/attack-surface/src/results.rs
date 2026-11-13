use crate::error::ResultsError;
use crate::model::{Counts, Found, Limits, Report, Scope, MAX_TIMESTAMP_BYTES, MIN_PORT};
use crate::scope::{in_ranges, port_allowed};
use crate::types::ReportResult;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;


pub enum Line {
    Eof,
    Overlong,
    Text(Vec<u8>),
}


pub enum Verdict {
    Keep(Found),
    OutOfScope,
    Malformed,
}


#[derive(Deserialize)]
pub struct NaabuLine {
    pub ip: String,
    pub port: u64,
    pub timestamp: Option<String>,
}


/// One line of at most `max_line_bytes` without its buffering more: an overlong line is skipped up to its newline and reported as `Overlong`.
pub fn read_line<Input: BufRead>(input: &mut Input, max_line_bytes: usize) -> Result<Line, ResultsError> {
    let mut buffer = Vec::new();
    let read = Read::take(input.by_ref(), max_line_bytes as u64 + 1).read_until(b'\n', &mut buffer)?;
    if read == 0 {
        Ok(Line::Eof)
    } else if buffer.last() != Some(&b'\n') && read > max_line_bytes {
        input.skip_until(b'\n')?;
        Ok(Line::Overlong)
    } else {
        Ok(Line::Text(buffer))
    }
}


pub fn place(scope: &Scope, ip: IpAddr, port: u16) -> Verdict {
    if port_allowed(scope, port) && in_ranges(scope, ip) {
        Verdict::Keep(Found { ip, port })
    } else {
        Verdict::OutOfScope
    }
}


/// Judges one parsed line (a `host` field is ignored, the address alone decides): a port outside 1 to 65535, an unparsable address or an overlong timestamp is `Malformed`.
pub fn judge(scope: &Scope, line: NaabuLine) -> Verdict {
    let timestamp_fits = line.timestamp.as_ref().is_none_or(|text| text.len() <= MAX_TIMESTAMP_BYTES);
    let parsed = line
        .ip
        .parse::<IpAddr>()
        .ok()
        .zip(u16::try_from(line.port).ok().filter(|port| *port >= MIN_PORT));
    match parsed {
        Some((ip, port)) if timestamp_fits => place(scope, ip.to_canonical(), port),
        _ => Verdict::Malformed,
    }
}


pub fn record(report: &mut Report, seen: &mut BTreeSet<(IpAddr, u16)>, verdict: Verdict) {
    match verdict {
        Verdict::Keep(found) if seen.insert((found.ip, found.port)) => report.found.push(found),
        Verdict::Keep(_) => report.counts.duplicate += 1,
        Verdict::OutOfScope => report.counts.out_of_scope += 1,
        Verdict::Malformed => report.counts.malformed += 1,
    }
}


pub fn handle_line(scope: &Scope, report: &mut Report, seen: &mut BTreeSet<(IpAddr, u16)>, line: Line) {
    match line {
        Line::Overlong => report.counts.oversize_lines += 1,
        Line::Text(bytes) => {
            let verdict = serde_json::from_slice::<NaabuLine>(&bytes).map_or(Verdict::Malformed, |parsed| judge(scope, parsed));
            record(report, seen, verdict);
        }
        Line::Eof => {}
    }
}


/// Reads naabu's JSON lines within `limits` and keeps what lies in `scope`; what is left over is counted, never stored.
pub fn parse_naabu(reader: &mut dyn Read, scope: &Scope, limits: &Limits) -> ReportResult {
    let mut input = BufReader::new(Read::take(reader, limits.max_bytes.saturating_add(1)));
    let mut report = Report::default();
    let mut seen = BTreeSet::new();
    std::iter::repeat_with(|| read_line(&mut input, limits.max_line_bytes))
        .take(limits.max_lines)
        .take_while(|line| !matches!(line, Ok(Line::Eof)))
        .try_for_each(|line| line.map(|next| handle_line(scope, &mut report, &mut seen, next)))?;
    let unread = !input.fill_buf()?.is_empty();
    let counts = Counts {
        truncated: unread || input.get_ref().limit() == 0,
        ..report.counts
    };
    Ok(Report { counts, ..report })
}
