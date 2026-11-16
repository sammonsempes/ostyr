use crate::support::{DEFAULT_TABLE, FIXTURES, SMALL_CAP};
use crate::types::TestResult;
use linux_fim::cli::render_command;
use linux_fim::error::{CliError, PolicyError, TableError};
use linux_fim::limits::default_limits;
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
