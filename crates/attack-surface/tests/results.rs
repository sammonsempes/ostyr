use attack_surface::error::ResultsError;
use attack_surface::model::{Counts, Found, Limits, Report, Scope, MAX_TIMESTAMP_BYTES};
use attack_surface::results::{handle_line, parse_naabu, Line};
use attack_surface::scope::parse_scope;
use std::collections::BTreeSet;
use std::error::Error;
use std::io::{repeat, Cursor, Error as IoError, Read, Result as IoResult};
use std::net::IpAddr;
use types::TestResult;


#[path = "support/types.rs"]
mod types;


const SCOPE_TEXT: &str = "kind: external
rate_per_second: 100
ports: [22, 80, 443]
targets:
  - value: 8.8.8.0/24
    ownership: {method: dns_txt, reference: TICKET-1}
";


const FIVE: usize = 5;


const TWELVE: usize = 12;


const QUARTER: usize = 4;


const SSH: u16 = 22;


const HTTP: u16 = 80;


const HTTPS: u16 = 443;


const SMALL_LINES: usize = 2;


const THREE: usize = 3;


const SMALL_BYTES: u64 = 50;


const TINY_LINE: usize = 64;


const HUNDRED_MIB: u64 = 104_857_600;


const NESTING: usize = 200;


const ROOMY_LINE: usize = 4096;


fn scope() -> Result<Scope, Box<dyn Error>> {
    let mut bytes = SCOPE_TEXT.as_bytes();
    Ok(parse_scope(&mut bytes, "scope.yaml")?)
}


fn run(input: &str, limits: &Limits) -> Result<Report, Box<dyn Error>> {
    let mut bytes = input.as_bytes();
    Ok(parse_naabu(&mut bytes, &scope()?, limits)?)
}


fn found_of(report: &Report) -> Vec<(String, u16)> {
    report.found.iter().map(|item| (item.ip.to_string(), item.port)).collect()
}


fn counts(malformed: usize, out_of_scope: usize, duplicate: usize) -> Counts {
    Counts {
        malformed,
        out_of_scope,
        duplicate,
        oversize_lines: 0,
        truncated: false,
    }
}


struct Failing {
    data: Cursor<Vec<u8>>,
}


impl Read for Failing {
    fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        match self.data.read(buffer)? {
            0 => Err(IoError::other("device failure")),
            read => Ok(read),
        }
    }
}


fn failing(data: &[u8]) -> Failing {
    Failing {
        data: Cursor::new(data.to_vec()),
    }
}


#[test]
fn results_inside_the_scope_are_kept_in_order_with_a_timestamp() -> TestResult {
    let input = "{\"ip\":\"8.8.8.8\",\"port\":22,\"timestamp\":\"2026-11-13T10:00:00Z\"}\n{\"ip\":\"8.8.8.9\",\"port\":80}\n";
    let report = run(input, &Limits::default())?;
    assert_eq!(found_of(&report), vec![("8.8.8.8".to_string(), SSH), ("8.8.8.9".to_string(), HTTP)]);
    assert_eq!(report.counts, counts(0, 0, 0));
    Ok(())
}


#[test]
fn a_final_line_without_a_newline_is_read() -> TestResult {
    let report = run("{\"ip\":\"8.8.8.8\",\"port\":443}", &Limits::default())?;
    assert_eq!(found_of(&report), vec![("8.8.8.8".to_string(), HTTPS)]);
    Ok(())
}


#[test]
fn an_ip_or_a_port_outside_the_scope_is_dropped_and_counted() -> TestResult {
    let input = "{\"ip\":\"1.1.1.1\",\"port\":22}
{\"ip\":\"8.8.9.1\",\"port\":22}
{\"ip\":\"8.8.8.8\",\"port\":8080}
{\"ip\":\"8.8.8.8\",\"port\":21}
{\"ip\":\"::1\",\"port\":22}
";
    let report = run(input, &Limits::default())?;
    assert!(report.found.is_empty());
    assert_eq!(report.counts, counts(0, FIVE, 0));
    Ok(())
}


#[test]
fn a_port_outside_one_to_65535_and_other_bad_lines_are_malformed() -> TestResult {
    let input = "{\"ip\":\"8.8.8.8\",\"port\":0}
{\"ip\":\"8.8.8.8\",\"port\":70000}
{\"ip\":\"8.8.8.8\",\"port\":-1}
{\"ip\":\"8.8.8.8\"}
{\"port\":22}
{\"ip\":\"not-an-ip\",\"port\":22}
{\"ip\":null,\"port\":22}
{\"ip\":\"8.8.8.8\",\"port\":22,\"timestamp\":5}
not json
[1,2]

{\"ip\":\"8.8.8.8\",\"port\":22.5}
";
    let report = run(input, &Limits::default())?;
    assert!(report.found.is_empty());
    assert_eq!(report.counts, counts(TWELVE, 0, 0));
    let long_timestamp = format!(
        "{{\"ip\":\"8.8.8.8\",\"port\":22,\"timestamp\":\"{}\"}}\n",
        "t".repeat(MAX_TIMESTAMP_BYTES + 1)
    );
    assert_eq!(run(&long_timestamp, &Limits::default())?.counts, counts(1, 0, 0));
    let fitting_timestamp = format!(
        "{{\"ip\":\"8.8.8.8\",\"port\":22,\"timestamp\":\"{}\"}}\n",
        "t".repeat(MAX_TIMESTAMP_BYTES)
    );
    assert_eq!(run(&fitting_timestamp, &Limits::default())?.found.len(), 1);
    Ok(())
}


#[test]
fn duplicates_are_counted_and_mapped_addresses_are_canonical() -> TestResult {
    let input = "{\"ip\":\"8.8.8.8\",\"port\":22}
{\"ip\":\"8.8.8.8\",\"port\":22}
{\"ip\":\"::ffff:8.8.8.8\",\"port\":22}
{\"ip\":\"8.8.8.8\",\"port\":80}
";
    let report = run(input, &Limits::default())?;
    assert_eq!(found_of(&report).len(), SMALL_LINES);
    assert_eq!(report.counts, counts(0, 0, SMALL_LINES));
    Ok(())
}


#[test]
fn the_host_field_is_ignored_and_the_address_alone_decides() -> TestResult {
    let input = "{\"host\":\"app.example.org\",\"ip\":\"8.8.8.8\",\"port\":443}
{\"host\":\"app.example.org\",\"ip\":\"1.1.1.1\",\"port\":443}
{\"host\":\"8.8.8.8\",\"ip\":\"1.1.1.1\",\"port\":80}
{\"host\":\"app.example.org\",\"ip\":\"8.8.8.9\",\"port\":9999}
";
    let report = run(input, &Limits::default())?;
    assert_eq!(found_of(&report), vec![("8.8.8.8".to_string(), HTTPS)]);
    assert_eq!(report.counts, counts(0, THREE, 0));
    Ok(())
}


fn padded_line(total: usize) -> String {
    let base = "{\"ip\":\"8.8.8.8\",\"port\":22,\"pad\":\"\"}";
    format!("{{\"ip\":\"8.8.8.8\",\"port\":22,\"pad\":\"{}\"}}", "x".repeat(total - base.len()))
}


#[test]
fn an_overlong_line_is_skipped_counted_and_the_next_line_is_read() -> TestResult {
    let limits = Limits {
        max_line_bytes: TINY_LINE,
        ..Limits::default()
    };
    let fitting = padded_line(TINY_LINE);
    let overlong = padded_line(TINY_LINE + 1);
    let input = format!("{overlong}\n{{\"ip\":\"8.8.8.9\",\"port\":22}}\n{fitting}\n");
    let report = run(&input, &limits)?;
    assert_eq!(found_of(&report).len(), SMALL_LINES);
    assert_eq!(report.counts.oversize_lines, 1);
    assert!(!report.counts.truncated);
    let at_limit_without_newline = run(&fitting, &limits)?;
    assert_eq!(at_limit_without_newline.found.len(), 1);
    let over_without_newline = run(&overlong, &limits)?;
    assert_eq!((over_without_newline.found.len(), over_without_newline.counts.oversize_lines), (0, 1));
    let exact_with_newline = run(&format!("{fitting}\n"), &limits)?;
    assert_eq!(exact_with_newline.found.len(), 1);
    Ok(())
}


#[test]
fn more_lines_than_the_limit_are_left_unread_and_flagged() -> TestResult {
    let input = "{\"ip\":\"8.8.8.8\",\"port\":22}\n{\"ip\":\"8.8.8.8\",\"port\":80}\n{\"ip\":\"8.8.8.8\",\"port\":443}\n";
    let limits = Limits {
        max_lines: SMALL_LINES,
        ..Limits::default()
    };
    let cut = run(input, &limits)?;
    assert_eq!(cut.found.len(), SMALL_LINES);
    assert!(cut.counts.truncated);
    let exact = run(
        input,
        &Limits {
            max_lines: THREE,
            ..Limits::default()
        },
    )?;
    assert_eq!(exact.found.len(), THREE);
    assert!(!exact.counts.truncated);
    Ok(())
}


#[test]
fn more_bytes_than_the_limit_are_never_read_and_flagged() -> TestResult {
    let line = "{\"ip\":\"8.8.8.8\",\"port\":22}\n";
    let input = line.repeat(THREE);
    let cut = run(
        &input,
        &Limits {
            max_bytes: SMALL_BYTES,
            ..Limits::default()
        },
    )?;
    assert!(cut.counts.truncated);
    assert_eq!(cut.found.len(), 1);
    assert_eq!(cut.counts.malformed, 1);
    let exact = run(
        line,
        &Limits {
            max_bytes: line.len() as u64,
            ..Limits::default()
        },
    )?;
    assert!(!exact.counts.truncated);
    assert_eq!(exact.found.len(), 1);
    Ok(())
}


#[test]
fn a_hundred_mebibyte_line_is_bounded_by_the_line_and_byte_limits() -> TestResult {
    let mut input = repeat(b'a').take(HUNDRED_MIB);
    let report = parse_naabu(&mut input, &scope()?, &Limits::default())?;
    assert_eq!(report.counts.oversize_lines, 1);
    assert!(report.counts.truncated);
    assert!(report.found.is_empty());
    Ok(())
}


#[test]
fn an_endless_stream_of_short_lines_stops_at_the_line_limit() -> TestResult {
    let mut input = repeat(b'\n');
    let report = parse_naabu(&mut input, &scope()?, &Limits::default())?;
    assert_eq!(report.counts.malformed, Limits::default().max_lines);
    assert!(report.counts.truncated);
    Ok(())
}


#[test]
fn deeply_nested_json_never_overflows_the_stack() -> TestResult {
    let limits = Limits {
        max_line_bytes: ROOMY_LINE,
        ..Limits::default()
    };
    let deep = format!("{}{}", "[".repeat(NESTING), "]".repeat(NESTING));
    let unknown = run(&format!("{{\"ip\":\"8.8.8.8\",\"port\":22,\"x\":{deep}}}\n"), &limits)?;
    assert_eq!(unknown.found.len(), 1);
    let known = run(&format!("{{\"ip\":{deep},\"port\":22}}\n"), &limits)?;
    assert_eq!(known.counts, counts(1, 0, 0));
    let huge = Limits {
        max_line_bytes: NESTING * ROOMY_LINE,
        ..Limits::default()
    };
    let nested = format!(
        "{{\"x\":{}{}}}\n",
        "[".repeat(NESTING * ROOMY_LINE / QUARTER),
        "]".repeat(NESTING * ROOMY_LINE / QUARTER)
    );
    assert_eq!(run(&nested, &huge)?.counts, counts(1, 0, 0));
    Ok(())
}


#[test]
fn a_read_error_is_returned_wherever_it_happens() -> TestResult {
    let limits = Limits::default();
    let first = parse_naabu(&mut failing(b""), &scope()?, &limits).err().ok_or("no error")?;
    assert!(matches!(first, ResultsError::Read(_)));
    assert!(first.to_string().contains("cannot read"), "{first}");
    let tiny = Limits {
        max_line_bytes: TINY_LINE,
        ..limits
    };
    let skipping = parse_naabu(&mut failing("a".repeat(TINY_LINE * THREE).as_bytes()), &scope()?, &tiny);
    assert!(skipping.is_err());
    let one_line = Limits { max_lines: 1, ..limits };
    let after = parse_naabu(&mut failing(b"{\"ip\":\"8.8.8.8\",\"port\":22}\n"), &scope()?, &one_line);
    assert!(after.is_err());
    Ok(())
}


#[test]
fn an_end_of_input_line_changes_nothing() -> TestResult {
    let mut report = Report::default();
    let mut seen: BTreeSet<(IpAddr, u16)> = BTreeSet::new();
    handle_line(&scope()?, &mut report, &mut seen, Line::Eof);
    assert_eq!(report.counts, Counts::default());
    assert!(report.found.is_empty() && seen.is_empty());
    let found = Found {
        ip: "8.8.8.8".parse()?,
        port: SSH,
    };
    assert_eq!(found.clone(), found);
    Ok(())
}
