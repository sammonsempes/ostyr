use std::{error::Error, ffi::OsString, io, path::Path};


use custom_lint::{
    error::LintError,
    run::{read_file, run},
    scan::{lint_file, lint_root, lint_source},
};


use tempfile::tempdir;


mod support;


const ROOT: &str = "/ws";


const SOURCE_PATH: &str = "/ws/crates/x/src/lib.rs";


struct FailingWriter;


impl io::Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("disk full"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn unreadable(_path: &Path) -> io::Result<Vec<u8>> {
    Err(io::Error::other("unreadable"))
}


fn invalid_utf8(_path: &Path) -> io::Result<Vec<u8>> {
    Ok(b"\xff".to_vec())
}


fn unparsable(_path: &Path) -> io::Result<Vec<u8>> {
    Ok(b"fn (".to_vec())
}


fn clean(_path: &Path) -> io::Result<Vec<u8>> {
    Ok(b"fn a() {}\n".to_vec())
}


#[test]
pub fn unreadable_file_keeps_its_cause() -> anyhow::Result<()> {
    let error = lint_file(Path::new(ROOT), Path::new(SOURCE_PATH), unreadable)
        .err()
        .ok_or(anyhow::anyhow!("expected an error"))?;
    assert!(matches!(error, LintError::Read { .. }));
    assert_eq!(error.to_string(), "cannot read crates/x/src/lib.rs");
    assert_eq!(error.source().map(ToString::to_string), Some("unreadable".to_string()));
    Ok(())
}


#[test]
pub fn invalid_utf8_keeps_its_cause() -> anyhow::Result<()> {
    let error = lint_file(Path::new(ROOT), Path::new(SOURCE_PATH), invalid_utf8)
        .err()
        .ok_or(anyhow::anyhow!("expected an error"))?;
    assert!(matches!(error, LintError::Utf8 { .. }));
    assert_eq!(error.to_string(), "crates/x/src/lib.rs is not valid UTF-8");
    assert!(error.source().is_some());
    Ok(())
}


#[test]
pub fn unparsable_rust_keeps_its_cause() -> anyhow::Result<()> {
    let error = lint_file(Path::new(ROOT), Path::new(SOURCE_PATH), unparsable)
        .err()
        .ok_or(anyhow::anyhow!("expected an error"))?;
    assert!(matches!(error, LintError::Parse { .. }));
    assert_eq!(error.to_string(), "crates/x/src/lib.rs is not valid Rust");
    assert!(error.source().is_some());
    Ok(())
}


#[test]
pub fn parse_error_from_source_is_reported() -> anyhow::Result<()> {
    assert!(lint_source(Path::new(SOURCE_PATH), "fn (").is_err());
    Ok(())
}


#[test]
pub fn readable_file_is_linted() -> anyhow::Result<()> {
    assert!(lint_file(Path::new(ROOT), Path::new(SOURCE_PATH), clean)?.is_empty());
    Ok(())
}


#[test]
pub fn workspace_scan_skips_target_and_non_rust_files() -> anyhow::Result<()> {
    let workspace = tempdir()?;
    support::write_workspace(workspace.path())?;
    let found: Vec<String> = lint_root(workspace.path(), read_file)?.iter().map(ToString::to_string).collect();
    assert_eq!(found, vec![support::EXPECTED_REPORT.trim_end().to_string()]);
    Ok(())
}


#[test]
pub fn missing_scan_directory_is_a_walk_error() -> anyhow::Result<()> {
    let workspace = tempdir()?;
    let error = lint_root(workspace.path(), read_file).err().ok_or(anyhow::anyhow!("expected an error"))?;
    assert!(matches!(error, LintError::Walk(_)));
    assert_eq!(error.to_string(), "cannot walk the workspace");
    Ok(())
}


#[test]
pub fn run_prints_one_line_per_violation() -> anyhow::Result<()> {
    let workspace = tempdir()?;
    support::write_workspace(workspace.path())?;
    let mut output = Vec::new();
    let count = run(vec![workspace.path().as_os_str().to_owned()].into_iter(), &mut output, read_file)?;
    assert_eq!(count, 1);
    assert_eq!(String::from_utf8(output)?, support::EXPECTED_REPORT);
    Ok(())
}


#[test]
pub fn run_without_root_is_a_usage_error() -> anyhow::Result<()> {
    let error = run(Vec::<OsString>::new().into_iter(), &mut Vec::new(), read_file)
        .err()
        .ok_or(anyhow::anyhow!("expected an error"))?;
    assert!(matches!(error, LintError::Usage));
    Ok(())
}


#[test]
pub fn run_with_two_roots_is_a_usage_error() -> anyhow::Result<()> {
    let arguments = vec![OsString::from("a"), OsString::from("b")];
    assert!(matches!(run(arguments.into_iter(), &mut Vec::new(), read_file), Err(LintError::Usage)));
    Ok(())
}


#[test]
pub fn run_reports_write_failures() -> anyhow::Result<()> {
    let workspace = tempdir()?;
    support::write_workspace(workspace.path())?;
    let result = run(vec![workspace.path().as_os_str().to_owned()].into_iter(), &mut FailingWriter, read_file);
    assert!(matches!(result, Err(LintError::Output(_))));
    Ok(())
}


#[test]
pub fn failing_writer_flushes() -> anyhow::Result<()> {
    io::Write::flush(&mut FailingWriter)?;
    Ok(())
}
