#[path = "common/types.rs"]
mod types;


use core_export::ecs::EcsEvent;
use ecs_normalise::cli::run_reporting;
use ecs_normalise::convert::Outcome;
use ecs_normalise::error::NormaliseError;
use ecs_normalise::stream::{
    decode, normalise_line, normalise_stream, normalise_stream_capped, parse_line, read_raw_line, write_event, Counts, Format, RawLine,
    MAX_LINE_BYTES,
};
use serde_json::Value;
use sigma_sql::compile::{compile_rule, SqlOptions};
use sigma_sql::mapping::parse_mapping;
use std::error::Error;
use std::io::{self, BufReader, Read};
use std::process::ExitCode;
use types::TestResult;


const EXEC: &str = include_str!("fixtures/exec.json");


const EXEC_MINIMAL: &str = include_str!("fixtures/exec_minimal.json");


const EXIT: &str = include_str!("fixtures/exit.json");


const FILE_OPEN: &str = include_str!("fixtures/file_open.json");


const FD_INSTALL: &str = include_str!("fixtures/fd_install.json");


const TCP_CONNECT: &str = include_str!("fixtures/tcp_connect.json");


const UNKNOWN_KPROBE: &str = include_str!("fixtures/unknown_kprobe.json");


const UNKNOWN_KIND: &str = include_str!("fixtures/unknown_kind.json");


const SNAPSHOT_EXEC: &str = include_str!("snapshots/exec.json");


const SNAPSHOT_EXEC_MINIMAL: &str = include_str!("snapshots/exec_minimal.json");


const SNAPSHOT_EXIT: &str = include_str!("snapshots/exit.json");


const SNAPSHOT_FILE_OPEN: &str = include_str!("snapshots/file_open.json");


const SNAPSHOT_FD_INSTALL: &str = include_str!("snapshots/fd_install.json");


const SNAPSHOT_TCP_CONNECT: &str = include_str!("snapshots/tcp_connect.json");


const MAPPING: &str = include_str!("../../sigma-sql/mappings/ecs.yaml");


const RULE: &str = include_str!("rules/linux_curl_download.yml");


const WINDOWS_ONLY_COLUMNS: [&str; 1] = ["process.pe.original_file_name"];


const NOT_IN_TETRAGON_COLUMNS: [&str; 2] = ["user.name", "destination.domain"];


const TIME: &str = r#""time":"2026-11-03T10:00:00Z""#;


const SMALL_CAP: u64 = 8;


const STREAM_CAP: u64 = 200;


const SEVEN: u64 = 7;


const ROOM: usize = 64;


const TWO: u64 = 2;


const THREE: u64 = 3;


const PAIR: usize = 2;


const INVALID_UTF8_FIRST: u8 = 0xff;


const INVALID_UTF8_SECOND: u8 = 0xfe;


const BUFFER_BYTES: usize = 16;


const TINY_CAP: u64 = 4;


fn run(input: &str) -> Result<(String, Counts), Box<dyn Error>> {
    let mut out = Vec::new();
    let mut reader = input.as_bytes();
    let counts = normalise_stream(&mut reader, &mut out)?;
    Ok((String::from_utf8(out)?, counts))
}


fn has_path(value: &Value, path: &str) -> bool {
    path.split('.').try_fold(value, |current, key| current.get(key)).is_some()
}


fn error_of(text: &str) -> Result<NormaliseError, Box<dyn Error>> {
    match parse_line(text) {
        Ok(_) => Err(format!("expected an error for {text}").into()),
        Err(error) => Ok(error),
    }
}


#[test]
fn every_event_kind_matches_its_snapshot() -> TestResult {
    let cases = [
        (EXEC, SNAPSHOT_EXEC),
        (EXEC_MINIMAL, SNAPSHOT_EXEC_MINIMAL),
        (EXIT, SNAPSHOT_EXIT),
        (FILE_OPEN, SNAPSHOT_FILE_OPEN),
        (FD_INSTALL, SNAPSHOT_FD_INSTALL),
        (TCP_CONNECT, SNAPSHOT_TCP_CONNECT),
    ];
    cases.iter().try_for_each(|(fixture, snapshot)| {
        let (output, counts) = run(fixture)?;
        assert_eq!(&output, snapshot);
        assert_eq!(
            counts,
            Counts {
                processed: 1,
                ..Counts::default()
            }
        );
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn unknown_kinds_are_counted_and_never_written() -> TestResult {
    let input = format!("{UNKNOWN_KPROBE}{UNKNOWN_KIND}{{{TIME}}}\n");
    let (output, counts) = run(&input)?;
    assert_eq!(output, "");
    assert_eq!(
        counts,
        Counts {
            unknown: THREE,
            duplicate: 0,
            ..Counts::default()
        }
    );
    assert_eq!(parse_line(UNKNOWN_KPROBE)?, Outcome::Unknown("process_kprobe:sys_ptrace".to_string()));
    assert_eq!(parse_line(UNKNOWN_KIND)?, Outcome::Unknown("process_loader".to_string()));
    assert_eq!(parse_line(&format!("{{{TIME}}}"))?, Outcome::Unknown("<none>".to_string()));
    Ok(())
}


#[test]
fn malformed_lines_are_typed_errors_and_the_stream_continues() -> TestResult {
    assert!(matches!(error_of("{")?, NormaliseError::Syntax(_)));
    assert!(matches!(error_of("[]")?, NormaliseError::Schema(_)));
    assert!(matches!(error_of(r#"{"process_exec":{}}"#)?, NormaliseError::Schema(_)));
    assert!(matches!(
        error_of(&format!(r#"{{"process_exec":{{"process":{{"pid":1}}}},{TIME}}}"#))?,
        NormaliseError::Schema(_)
    ));
    assert!(matches!(
        error_of(&format!(r#"{{"process_kprobe":{{"process":{{"pid":1,"binary":"/a"}}}},{TIME}}}"#))?,
        NormaliseError::Schema(_)
    ));
    let no_file = format!(r#"{{"process_kprobe":{{"process":{{"pid":1,"binary":"/a"}},"function_name":"security_file_open"}},{TIME}}}"#);
    assert!(matches!(error_of(&no_file)?, NormaliseError::MissingField("file_arg")));
    let no_socket = format!(r#"{{"process_kprobe":{{"process":{{"pid":1,"binary":"/a"}},"function_name":"tcp_connect"}},{TIME}}}"#);
    assert!(matches!(error_of(&no_socket)?, NormaliseError::MissingField("sock_arg")));
    let input = format!("{{\n{EXEC}\n{no_file}\n{EXIT}");
    let (output, counts) = run(&input)?;
    assert_eq!(output, format!("{SNAPSHOT_EXEC}{SNAPSHOT_EXIT}"));
    assert_eq!(
        counts,
        Counts {
            processed: TWO,
            malformed: THREE,
            unknown: 0,
            duplicate: 0
        }
    );
    Ok(())
}


#[test]
fn errors_carry_the_line_number() -> TestResult {
    let error = normalise_line(SEVEN, "{").err().ok_or("expected an error")?;
    assert_eq!(error.line, SEVEN);
    assert!(error.to_string().starts_with("line 7: invalid JSON"));
    assert!(error.source().is_some());
    let too_long = decode(SEVEN, RawLine::TooLong, SMALL_CAP).err().ok_or("expected an error")?;
    assert_eq!(too_long.to_string(), "line 7: the line is longer than 8 bytes");
    let bad_utf8 = decode(SEVEN, RawLine::Text(vec![INVALID_UTF8_FIRST, INVALID_UTF8_SECOND]), SMALL_CAP)
        .err()
        .ok_or("expected an error")?;
    assert!(matches!(bad_utf8.error, NormaliseError::Utf8(_)));
    assert!(decode(SEVEN, RawLine::Text(EXEC.trim().as_bytes().to_vec()), MAX_LINE_BYTES).is_ok());
    Ok(())
}


#[test]
fn raw_lines_are_bounded_and_the_excess_is_skipped() -> TestResult {
    let mut empty = "".as_bytes();
    assert_eq!(read_raw_line(&mut empty, SMALL_CAP)?, None);
    let mut exact = "12345678\nabc".as_bytes();
    assert_eq!(read_raw_line(&mut exact, SMALL_CAP)?, Some(RawLine::Text(b"12345678".to_vec())));
    assert_eq!(read_raw_line(&mut exact, SMALL_CAP)?, Some(RawLine::Text(b"abc".to_vec())));
    assert_eq!(read_raw_line(&mut exact, SMALL_CAP)?, None);
    let mut long = "123456789\nabc\n".as_bytes();
    assert_eq!(read_raw_line(&mut long, SMALL_CAP)?, Some(RawLine::TooLong));
    assert_eq!(read_raw_line(&mut long, SMALL_CAP)?, Some(RawLine::Text(b"abc".to_vec())));
    Ok(())
}


#[test]
fn an_oversized_line_is_counted_and_the_next_one_is_read() -> TestResult {
    let input = format!("{EXEC}{EXEC_MINIMAL}");
    let mut out = Vec::new();
    let mut reader = input.as_bytes();
    let counts = normalise_stream_capped(&mut reader, &mut out, STREAM_CAP, Format::Tetragon)?;
    assert_eq!(String::from_utf8(out)?, SNAPSHOT_EXEC_MINIMAL);
    assert_eq!(
        counts,
        Counts {
            processed: 1,
            malformed: 1,
            unknown: 0,
            duplicate: 0
        }
    );
    Ok(())
}


struct FailAfter {
    data: &'static [u8],
    served: bool,
    fails: bool,
}


impl Read for FailAfter {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.served && self.fails {
            Err(io::Error::other("read failed"))
        } else if self.served {
            Ok(0)
        } else {
            self.served = true;
            let length = self.data.len().min(buffer.len());
            buffer
                .get_mut(..length)
                .ok_or_else(|| io::Error::other("short buffer"))?
                .copy_from_slice(self.data.get(..length).ok_or_else(|| io::Error::other("short data"))?);
            Ok(length)
        }
    }
}


#[test]
fn read_errors_stop_the_stream() -> TestResult {
    let mut out = Vec::new();
    let mut failing = BufReader::with_capacity(
        BUFFER_BYTES,
        FailAfter {
            data: b"",
            served: true,
            fails: true,
        },
    );
    assert!(matches!(normalise_stream(&mut failing, &mut out), Err(NormaliseError::Io(_))));
    let mut skipping = BufReader::with_capacity(
        BUFFER_BYTES,
        FailAfter {
            data: b"aaaaa",
            served: false,
            fails: true,
        },
    );
    assert!(matches!(
        normalise_stream_capped(&mut skipping, &mut out, TINY_CAP, Format::Tetragon),
        Err(NormaliseError::Io(_))
    ));
    Ok(())
}


#[test]
fn write_errors_stop_the_stream() -> TestResult {
    let mut serialise_reader = EXEC_MINIMAL.as_bytes();
    let mut empty: [u8; 0] = [];
    let mut empty_sink = empty.as_mut_slice();
    assert!(matches!(
        normalise_stream(&mut serialise_reader, &mut empty_sink),
        Err(NormaliseError::Serialize(_))
    ));
    let mut newline_reader = EXEC_MINIMAL.as_bytes();
    let mut exact = vec![0; SNAPSHOT_EXEC_MINIMAL.len() - 1];
    let mut exact_sink = exact.as_mut_slice();
    assert!(matches!(
        normalise_stream(&mut newline_reader, &mut exact_sink),
        Err(NormaliseError::Io(_))
    ));
    let outcome = parse_line(EXEC_MINIMAL)?;
    let event: EcsEvent = match outcome {
        Outcome::Event(boxed) => *boxed,
        Outcome::Unknown(kind) => Err(kind)?,
    };
    let mut buffer = Vec::new();
    write_event(&mut buffer, &event)?;
    assert_eq!(String::from_utf8(buffer)?, SNAPSHOT_EXEC_MINIMAL);
    Ok(())
}


fn script(data: &'static [u8], fails: bool) -> BufReader<FailAfter> {
    BufReader::new(FailAfter { data, served: false, fails })
}


fn reporting(data: &'static [u8], fails: bool, room: usize) -> io::Result<(String, ExitCode)> {
    let mut input = script(data, fails);
    let mut out = Vec::new();
    let mut error_bytes = vec![0; room];
    let mut sink = error_bytes.as_mut_slice();
    let code = run_reporting(&[], &mut input, &mut out, &mut sink)?;
    Ok((String::from_utf8_lossy(&error_bytes).trim_end_matches('\0').to_string(), code))
}


#[test]
fn the_cli_reports_counts_and_errors() -> TestResult {
    let (counts_text, success) = reporting(EXEC_MINIMAL.as_bytes(), false, ROOM)?;
    assert_eq!(format!("{success:?}"), format!("{:?}", ExitCode::SUCCESS));
    assert_eq!(counts_text, "processed=1 malformed=0 unknown=0\n");
    let (error_text, failure) = reporting(b"x", true, ROOM)?;
    assert_eq!(format!("{failure:?}"), format!("{:?}", ExitCode::FAILURE));
    assert_eq!(error_text, "I/O error: read failed\n");
    assert!(reporting(EXEC_MINIMAL.as_bytes(), false, 0).is_err());
    assert!(reporting(b"x", true, 0).is_err());
    Ok(())
}


fn outputs() -> Result<Vec<Value>, Box<dyn Error>> {
    [EXEC, EXEC_MINIMAL, EXIT, FILE_OPEN, FD_INSTALL, TCP_CONNECT]
        .iter()
        .map(|fixture| Ok(serde_json::from_str(&run(fixture)?.0)?))
        .collect()
}


#[test]
fn every_linux_column_of_the_sigma_mapping_is_produced() -> TestResult {
    let mapping = parse_mapping(MAPPING)?;
    let produced = outputs()?;
    let columns: Vec<&String> = mapping.categories.values().flat_map(|category| category.fields.values()).collect();
    assert!(!columns.is_empty());
    columns.iter().try_for_each(|column| {
        let excluded = WINDOWS_ONLY_COLUMNS.contains(&column.as_str()) || NOT_IN_TETRAGON_COLUMNS.contains(&column.as_str());
        let found = produced.iter().any(|event| has_path(event, column));
        if found == excluded {
            Err(format!("column {column}: produced={found}, excluded={excluded}"))
        } else {
            Ok(())
        }
    })?;
    Ok(())
}


#[test]
fn the_category_filters_of_the_mapping_are_produced() -> TestResult {
    let mapping = parse_mapping(MAPPING)?;
    let produced = outputs()?;
    mapping.categories.values().try_for_each(|category| {
        let wanted = Value::String(category.event_category.clone());
        produced
            .iter()
            .any(|event| event.pointer("/event/category/0") == Some(&wanted))
            .then_some(())
            .ok_or_else(|| format!("no event of category {}", category.event_category))
    })?;
    assert_eq!(mapping.products.get("linux").map(String::as_str), Some("linux"));
    assert!(produced
        .iter()
        .all(|event| event.pointer("/host/os/type") == Some(&Value::String("linux".to_string()))));
    Ok(())
}


#[test]
fn a_normalised_exec_event_carries_every_field_a_sigma_rule_reads() -> TestResult {
    let mapping = parse_mapping(MAPPING)?;
    let sql = compile_rule(RULE, &mapping, &SqlOptions::default())?;
    let event: Value = serde_json::from_str(&run(EXEC)?.0)?;
    let columns: Vec<&str> = sql.split('`').skip(1).step_by(PAIR).collect();
    assert!(columns.contains(&"process.parent.command_line") || columns.contains(&"process.command_line"));
    columns
        .iter()
        .filter(|column| **column != "event.id" && **column != "events")
        .try_for_each(|column| {
            has_path(&event, column)
                .then_some(())
                .ok_or_else(|| format!("the normalised event lacks {column}"))
        })?;
    Ok(())
}
