#[path = "common/types.rs"]
mod types;


use ecs_normalise::cli::{parse_format, run_reporting};
use ecs_normalise::error::NormaliseError;
use ecs_normalise::stream::{normalise_stream_capped, normalise_stream_format, Counts, Format};
use std::io::{self, Write};
use std::process::ExitCode;
use types::TestResult;


const CASES: [(&str, &str); 4] = [
    (include_str!("fixtures/sysmon_1.xml"), include_str!("snapshots/sysmon_1.json")),
    (include_str!("fixtures/sysmon_3.xml"), include_str!("snapshots/sysmon_3.json")),
    (include_str!("fixtures/sysmon_json.json"), include_str!("snapshots/sysmon_json.json")),
    (include_str!("fixtures/sysmon_unknown.xml"), include_str!("snapshots/sysmon_unknown.json")),
];


const UNKNOWN: &str = include_str!("fixtures/sysmon_unknown.xml");


const PROCESSED: u64 = 3;


const TWO: u64 = 2;


const SMALL_CAP: u64 = 64;


const WIDE_CAP: u64 = 65_536;


const LONG_LINE: usize = 200;


const NOT_UTF8: [u8; 3] = [0xff, 0xfe, b'\n'];


struct BrokenSink;


impl Write for BrokenSink {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("sink closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn one_line(text: &str) -> String {
    text.lines().map(str::trim).collect::<Vec<_>>().join("")
}


fn run(input: &[u8], cap: u64) -> Result<(String, Counts), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let mut reader = input;
    let counts = normalise_stream_capped(&mut reader, &mut out, cap, Format::Sysmon)?;
    Ok((String::from_utf8(out)?, counts))
}


#[test]
fn fixtures_one_per_line_give_their_snapshots() -> TestResult {
    let input: String = CASES.iter().map(|(fixture, _)| format!("{}\n", one_line(fixture))).collect();
    let mut out = Vec::new();
    let mut reader = input.as_bytes();
    let counts = normalise_stream_format(&mut reader, &mut out, Format::Sysmon)?;
    let expected: String = CASES.iter().map(|(_, snapshot)| snapshot.to_string()).collect();
    assert_eq!(String::from_utf8(out)?, expected);
    assert_eq!(
        counts,
        Counts {
            processed: PROCESSED,
            unknown: 1,
            ..Counts::default()
        }
    );
    Ok(())
}


#[test]
fn unknown_repeated_and_malformed_lines_are_counted() -> TestResult {
    let unknown = one_line(UNKNOWN);
    let input = format!("{unknown}\n{unknown}\nnot an event\n{unknown}\n");
    let (written, counted) = run(input.as_bytes(), WIDE_CAP)?;
    assert_eq!(written.lines().count(), PROCESSED as usize);
    assert_eq!(
        counted,
        Counts {
            unknown: 1,
            duplicate: TWO,
            malformed: 1,
            processed: 0
        }
    );
    Ok(())
}


#[test]
fn an_oversized_line_is_skipped_and_counted() -> TestResult {
    let input = format!("{}\n{}\n", "x".repeat(LONG_LINE), one_line(UNKNOWN));
    let (output, counts) = run(input.as_bytes(), SMALL_CAP)?;
    assert!(output.is_empty());
    assert_eq!(counts.malformed, TWO);
    let (kept, wide) = run(input.as_bytes(), WIDE_CAP)?;
    assert_eq!(kept.lines().count(), 1);
    assert_eq!(wide.malformed, 1);
    Ok(())
}


#[test]
fn invalid_utf8_is_malformed() -> TestResult {
    let (output, counts) = run(&NOT_UTF8, WIDE_CAP)?;
    assert!(output.is_empty());
    assert_eq!(counts.malformed, 1);
    Ok(())
}


#[test]
fn the_format_is_parsed() -> TestResult {
    assert_eq!(parse_format(&[])?, Format::Tetragon);
    assert_eq!(parse_format(&["--format", "sysmon"])?, Format::Sysmon);
    assert_eq!(parse_format(&["--format", "tetragon"])?, Format::Tetragon);
    assert!(matches!(parse_format(&["--format", "x"]), Err(NormaliseError::UnknownFormat(_))));
    assert!(matches!(parse_format(&["--bad"]), Err(NormaliseError::Usage)));
    Ok(())
}


#[test]
fn the_cli_reports_sysmon_counts_and_argument_errors() -> TestResult {
    let line = format!("{}\n", one_line(UNKNOWN));
    let input = format!("{line}{line}x\n");
    let mut reader = input.as_bytes();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_reporting(&["--format", "sysmon"], &mut reader, &mut out, &mut err)?;
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    assert_eq!(String::from_utf8(err)?, "processed=0 malformed=1 unknown=1 duplicate=1\n");
    let mut empty: &[u8] = b"";
    let mut bad_err = Vec::new();
    let failure = run_reporting(&["--oops"], &mut empty, &mut Vec::new(), &mut bad_err)?;
    assert_eq!(format!("{failure:?}"), format!("{:?}", ExitCode::FAILURE));
    assert!(String::from_utf8(bad_err)?.starts_with("usage:"));
    Ok(())
}


#[test]
fn a_write_failure_stops_the_sysmon_stream() -> TestResult {
    let input = format!("{}\n", one_line(UNKNOWN));
    let mut reader = input.as_bytes();
    let result = normalise_stream_capped(&mut reader, &mut BrokenSink, WIDE_CAP, Format::Sysmon);
    assert!(matches!(result, Err(NormaliseError::Serialize(_) | NormaliseError::Io(_))));
    Ok(())
}


#[test]
fn a_full_error_sink_is_an_io_error_in_every_report_arm() -> TestResult {
    let mut no_room: &mut [u8] = &mut [];
    let mut empty: &[u8] = b"";
    assert!(run_reporting(&["--format", "sysmon"], &mut empty, &mut Vec::new(), &mut no_room).is_err());
    let mut other_room: &mut [u8] = &mut [];
    assert!(run_reporting(&["--oops"], &mut empty, &mut Vec::new(), &mut other_room).is_err());
    Ok(())
}
