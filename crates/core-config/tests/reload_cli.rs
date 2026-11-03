#[path = "common/reload.rs"]
mod support;
#[path = "common/types.rs"]
mod types;


use core_config::reload::{reload, ReloadOutcome};
use core_config::reload_cli::{run_command, run_session, write_outcome};
use std::io::{self, BufReader, Cursor, Read};
use support::{engine_for, entries, module_text, recording_audit, replace_file, retention};
use tempfile::tempdir;
use types::TestResult;


struct BrokenInput;


impl Read for BrokenInput {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }
}


#[test]
fn session_shows_reloads_and_stops_at_quit() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, recorded) = recording_audit();
    let engine = engine_for(&path, audit, Vec::new())?;
    replace_file(&path, &module_text("90d"))?;
    let mut out = Vec::new();
    run_session(&engine, Cursor::new("show\nreload\nreload\nbogus\nquit\nshow\n"), &mut out)?;
    let text = String::from_utf8(out)?;
    assert!(text.contains("settings.retention=30d"), "{text}");
    assert!(text.contains("applied settings.retention"), "{text}");
    assert!(text.contains("unchanged"), "{text}");
    assert!(text.contains("unknown command `bogus`"), "{text}");
    assert_eq!(text.matches("settings.retention=").count(), 1);
    assert_eq!(retention(&engine).as_deref(), Some("90d"));
    assert_eq!(entries(&recorded)?.len(), 1);
    Ok(())
}


#[test]
fn refusals_are_written_and_input_errors_propagate() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, _recorded) = recording_audit();
    let engine = engine_for(&path, audit, Vec::new())?;
    replace_file(&path, "name: [\n")?;
    let mut out = Vec::new();
    run_command(&engine, "reload", &mut out)?;
    assert!(String::from_utf8(out)?.starts_with("refused "));
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    let mut sink = Vec::new();
    assert!(run_session(&engine, BufReader::new(BrokenInput), &mut sink).is_err());
    let mut refused = Vec::new();
    write_outcome(&ReloadOutcome::Unchanged, &mut refused)?;
    assert_eq!(refused, b"unchanged\n");
    Ok(())
}
