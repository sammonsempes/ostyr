mod common;


use common::types::TestResult;
use remote_shell::recording::{Direction, RecordingError};
use remote_shell::recording_cli::{clock_at, direction_of, run_record_cli, RecordCliError};
use std::io::{self, Write};


const HALF: usize = 2;


const BAD_UTF8: [u8; 3] = [0xff, 0xfe, b'\n'];


const CLOCK_START: i64 = 1;


const CLOCK_STEP: i64 = 2;


const CLOCK_INDEX: usize = 3;


const CLOCK_EXPECTED: i64 = 7;


pub struct FailingWrite;


impl Write for FailingWrite {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("injected"))
    }
}


fn run(args: &[&str], input: &[u8], out: &mut dyn Write) -> Result<(), RecordCliError> {
    let arguments: Vec<String> = args.iter().map(|argument| argument.to_string()).collect();
    let mut reader = input;
    run_record_cli(&arguments, &mut reader, out)
}


#[test]
fn record_then_verify_then_tamper() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let file = directory.path().join("r.bin").display().to_string();
    run(&["record", &file, "100", "2"], b"ls\nfile-a\n\x1b]0;evil\x07\n", &mut Vec::new())?;
    let mut out = Vec::new();
    run(&["verify", &file], b"", &mut out)?;
    let shown = String::from_utf8(out)?;
    assert!(shown.starts_with("valid frames=5 final_hash="), "{shown}");
    assert!(!shown.contains('\x1b') && !shown.contains("evil"));
    let mut bytes = std::fs::read(&file)?;
    let middle = bytes.len() / HALF;
    let target = bytes.get_mut(middle).ok_or("middle")?;
    *target ^= 1;
    std::fs::write(&file, &bytes)?;
    assert!(matches!(run(&["verify", &file], b"", &mut Vec::new()), Err(RecordCliError::Recording(_))));
    bytes.truncate(bytes.len() - 1);
    std::fs::write(&file, &bytes)?;
    assert!(matches!(
        run(&["verify", &file], b"", &mut Vec::new()),
        Err(RecordCliError::Recording(RecordingError::Frame { .. }))
    ));
    Ok(())
}


#[test]
fn bad_arguments_and_files_are_reported() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let file = directory.path().join("r.bin").display().to_string();
    let missing = directory.path().join("missing").join("r.bin").display().to_string();
    assert!(matches!(run(&[], b"", &mut Vec::new()), Err(RecordCliError::Usage)));
    assert!(matches!(run(&["verify"], b"", &mut Vec::new()), Err(RecordCliError::Usage)));
    assert!(matches!(
        run(&["other", &file, "1", "1"], b"", &mut Vec::new()),
        Err(RecordCliError::Usage)
    ));
    assert!(matches!(run(&["other", &file], b"", &mut Vec::new()), Err(RecordCliError::Usage)));
    assert!(matches!(
        run(&["record", &file, "x", "1"], b"", &mut Vec::new()),
        Err(RecordCliError::Number(_))
    ));
    assert!(matches!(run(&["verify", &missing], b"", &mut Vec::new()), Err(RecordCliError::Io(_))));
    assert!(matches!(
        run(&["record", &missing, "1", "1"], b"", &mut Vec::new()),
        Err(RecordCliError::Io(_))
    ));
    let huge = i64::MAX.to_string();
    assert!(matches!(
        run(&["record", &file, "1", &huge], b"a\n", &mut Vec::new()),
        Err(RecordCliError::Clock)
    ));
    assert!(matches!(
        run(&["record", &file, &huge, "1"], b"", &mut Vec::new()),
        Err(RecordCliError::Clock)
    ));
    run(&["record", &file, "1", "1"], b"", &mut Vec::new())?;
    assert!(matches!(run(&["verify", &file], b"", &mut FailingWrite), Err(RecordCliError::Io(_))));
    Ok(())
}


#[test]
fn a_failing_input_stream_is_reported() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let file = directory.path().join("r.bin").display().to_string();
    assert!(matches!(
        run(&["record", &file, "1", "1"], &BAD_UTF8, &mut Vec::new()),
        Err(RecordCliError::Io(_))
    ));
    assert_eq!(clock_at(CLOCK_START, CLOCK_STEP, CLOCK_INDEX)?, CLOCK_EXPECTED);
    assert_eq!(direction_of(0), Direction::In);
    assert_eq!(direction_of(1), Direction::Out);
    Ok(())
}
