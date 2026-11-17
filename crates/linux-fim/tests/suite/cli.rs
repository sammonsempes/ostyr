use crate::support::{DEFAULT_TABLE, FIXTURES, SMALL_CAP};
use crate::types::TestResult;
use linux_fim::cli::{classify_command, parse_planted, render_command, CaptureFiles};
use linux_fim::error::{CliError, PolicyError, TableError};
use linux_fim::limits::{default_limits, MAX_CAPTURE_BYTES};
use linux_fim::model::Limits;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tempfile::tempdir;


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn the_server_policy_is_written_to_the_output() -> TestResult {
    let mut out = Vec::new();
    render_command(Path::new(DEFAULT_TABLE), "server", &default_limits(), &mut out)?;
    assert_eq!(String::from_utf8(out)?, fs::read_to_string(format!("{FIXTURES}server.policy.yaml"))?);
    Ok(())
}


#[test]
fn a_missing_table_is_an_io_error() -> TestResult {
    let dir = tempdir()?;
    let result = render_command(&dir.path().join("none.yaml"), "server", &default_limits(), &mut Vec::new());
    assert!(matches!(result, Err(CliError::Io(_))));
    Ok(())
}


#[test]
fn a_table_over_the_cap_is_refused_after_a_bounded_read() -> TestResult {
    let limits = Limits {
        max_table_bytes: SMALL_CAP,
        ..default_limits()
    };
    let result = render_command(Path::new(DEFAULT_TABLE), "server", &limits, &mut Vec::new());
    assert!(matches!(result, Err(CliError::Table(TableError::TooLarge { bytes, .. })) if bytes == SMALL_CAP + 1));
    Ok(())
}


#[test]
fn an_unknown_role_is_refused() -> TestResult {
    let result = render_command(Path::new(DEFAULT_TABLE), "nobody", &default_limits(), &mut Vec::new());
    assert!(matches!(result, Err(CliError::NoRole(name)) if name == "nobody"));
    Ok(())
}


#[test]
fn an_empty_role_is_refused() -> TestResult {
    let dir = tempdir()?;
    let table = dir.path().join("roles.yaml");
    fs::write(&table, "version: 1\nroles:\n  - name: empty\n")?;
    let result = render_command(&table, "empty", &default_limits(), &mut Vec::new());
    assert!(matches!(result, Err(CliError::Policy(PolicyError::Empty))));
    Ok(())
}


#[test]
fn a_failing_output_is_reported() -> TestResult {
    let result = render_command(Path::new(DEFAULT_TABLE), "server", &default_limits(), &mut FailingWriter);
    assert!(matches!(result, Err(CliError::Io(_))));
    Ok(())
}


#[test]
fn the_failing_writer_flushes() -> TestResult {
    FailingWriter.flush()?;
    Ok(())
}


#[test]
fn a_table_that_is_not_text_is_an_io_error() -> TestResult {
    let dir = tempdir()?;
    let table = dir.path().join("roles.yaml");
    fs::write(&table, b"\xff\xfe")?;
    let result = render_command(&table, "server", &default_limits(), &mut Vec::new());
    assert!(matches!(result, Err(CliError::Io(_))));
    Ok(())
}


const KERNEL_DEVICE: u32 = 265_289_729;


const TOKEN_INODE: u64 = 4_708;


const PLANTED_COUNT: usize = 2;


const BAD_LINE_NUMBER: usize = 2;


const PLANTED_LINES: &str = "/root/passwords.txt\t64769\t4708\n\n/root\t64769\t2\n";


#[test]
fn planted_identities_are_read_with_the_kernel_device() -> TestResult {
    let planted = parse_planted(PLANTED_LINES)?;
    assert_eq!(planted.len(), PLANTED_COUNT);
    assert!(
        matches!(planted.first(), Some(found) if found.path == "/root/passwords.txt" && found.device == KERNEL_DEVICE && found.inode == TOKEN_INODE)
    );
    Ok(())
}


#[test]
fn a_bad_planted_line_is_refused_with_its_number() -> TestResult {
    ["a\t1", "a\tx\t1", "a\t1\tx", "a\t1\t2\t3"].iter().for_each(|bad| {
        assert!(matches!(parse_planted(&format!("ok\t1\t1\n{bad}")), Err(CliError::Planted { line }) if line == BAD_LINE_NUMBER));
    });
    Ok(())
}


fn capture_files<'a>(planted: &'a Path, capture: &'a Path, max_capture_bytes: usize) -> CaptureFiles<'a> {
    CaptureFiles {
        table: Path::new(DEFAULT_TABLE),
        planted,
        capture,
        max_capture_bytes,
    }
}


#[test]
fn a_capture_is_classified_with_the_planted_identities() -> TestResult {
    let dir = tempdir()?;
    let planted = dir.path().join("planted.tsv");
    let capture = dir.path().join("capture.jsonl");
    fs::write(&planted, PLANTED_LINES)?;
    fs::write(&capture, fs::read_to_string(format!("{FIXTURES}root-open.json"))?)?;
    let mut out = Vec::new();
    classify_command(
        &capture_files(&planted, &capture, MAX_CAPTURE_BYTES),
        "server",
        &default_limits(),
        &mut out,
    )?;
    assert!(String::from_utf8(out)?.starts_with("Honeytoken"));
    Ok(())
}


#[test]
fn a_capture_over_the_cap_or_a_failing_output_is_refused() -> TestResult {
    let dir = tempdir()?;
    let planted = dir.path().join("planted.tsv");
    let capture = dir.path().join("capture.jsonl");
    fs::write(&planted, PLANTED_LINES)?;
    fs::write(&capture, fs::read_to_string(format!("{FIXTURES}root-open.json"))?)?;
    let small = classify_command(
        &capture_files(&planted, &capture, SMALL_CAP),
        "server",
        &default_limits(),
        &mut Vec::new(),
    );
    assert!(matches!(small, Err(CliError::TooLarge { max }) if max == SMALL_CAP));
    let files = capture_files(&planted, &capture, MAX_CAPTURE_BYTES);
    let failing = classify_command(&files, "server", &default_limits(), &mut FailingWriter);
    assert!(matches!(failing, Err(CliError::Io(_))));
    let missing = classify_command(&files, "nobody", &default_limits(), &mut Vec::new());
    assert!(matches!(missing, Err(CliError::NoRole(_))));
    Ok(())
}


#[test]
fn a_missing_or_unreadable_planted_or_capture_file_is_an_io_error() -> TestResult {
    let dir = tempdir()?;
    let planted = dir.path().join("planted.tsv");
    let capture = dir.path().join("capture.jsonl");
    let files = capture_files(&planted, &capture, MAX_CAPTURE_BYTES);
    let absent = classify_command(&files, "server", &default_limits(), &mut Vec::new());
    assert!(matches!(absent, Err(CliError::Io(_))));
    fs::write(&planted, b"\xff\xfe")?;
    let binary = classify_command(&files, "server", &default_limits(), &mut Vec::new());
    assert!(matches!(binary, Err(CliError::Io(_))));
    fs::write(&planted, "a\t1")?;
    let bad = classify_command(&files, "server", &default_limits(), &mut Vec::new());
    assert!(matches!(bad, Err(CliError::Planted { line: 1 })));
    fs::write(&planted, PLANTED_LINES)?;
    let no_capture = classify_command(&files, "server", &default_limits(), &mut Vec::new());
    assert!(matches!(no_capture, Err(CliError::Io(_))));
    Ok(())
}
