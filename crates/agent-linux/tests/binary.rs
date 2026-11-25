#![cfg(unix)]
use agent_linux::error::{ServeError, SourceError};
use agent_linux::model::Totals;
use agent_linux::serve::{exit_code, parse_args};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;
use tempfile::tempdir;


const WAIT_ATTEMPTS: u32 = 6_000;


const WAIT_STEP: Duration = Duration::from_millis(10);


struct Failing;


impl Write for Failing {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn write_files(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = dir.display();
    fs::write(
        dir.join("agent.yaml"),
        format!(
            "server: 127.0.0.1:1\nserver_name: server\ncertificate: {root}/absent.pem\nkey: {root}/absent.key\nplatform_ca: {root}/absent-ca.pem\ntenant: t1\nagent_id: a1\nkeys_file: {root}/keys\nstate_file: {root}/state\naudit_file: {root}/agent-audit\nspool_file: {root}/spool\nsequence_file: {root}/sequence\nexecuted_file: {root}/executed\n"
        ),
    )?;
    fs::write(dir.join("process-cred"), "true")?;
    let config = dir.join("linux.yaml");
    fs::write(
        &config,
        format!(
            "agent_file: {root}/agent.yaml\nexport_path: {root}/export.json\ncursor_file: {root}/cursor\naudit_file: {root}/linux-audit\ncredentials_path: {root}/process-cred\n"
        ),
    )?;
    Ok(config)
}


#[test]
fn one_argument_is_the_settings_path() -> Result<(), Box<dyn std::error::Error>> {
    let args = ["linux.yaml".to_string()];
    assert_eq!(parse_args(&args)?, PathBuf::from("linux.yaml"));
    assert!(matches!(parse_args(&[]), Err(ServeError::Usage)));
    assert!(matches!(parse_args(&["a".to_string(), "b".to_string()]), Err(ServeError::Usage)));
    Ok(())
}


#[test]
fn the_exit_code_follows_the_result_and_the_writes() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(exit_code(Ok(Totals::default()), &mut out, &mut err), ExitCode::SUCCESS);
    assert!(String::from_utf8(out)?.contains("Totals"));
    let mut quiet = Vec::new();
    let failed = exit_code(Err(ServeError::Run(SourceError::Settings("bad".to_string()))), &mut quiet, &mut err);
    assert_eq!(failed, ExitCode::FAILURE);
    assert!(String::from_utf8(err)?.starts_with("ostyr-agent-linux: "));
    assert!(quiet.is_empty());
    assert_eq!(exit_code(Ok(Totals::default()), &mut Failing, &mut Failing), ExitCode::FAILURE);
    assert_eq!(exit_code(Err(ServeError::Usage), &mut Failing, &mut Failing), ExitCode::FAILURE);
    Ok(())
}


#[test]
fn the_binary_refuses_a_missing_or_invalid_settings_file() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let none = Command::new(env!("CARGO_BIN_EXE_ostyr-agent-linux")).output()?;
    assert_eq!(none.status.code(), Some(1));
    assert!(String::from_utf8(none.stderr)?.contains("usage: ostyr-agent-linux <config.yaml>"));
    let absent = Command::new(env!("CARGO_BIN_EXE_ostyr-agent-linux"))
        .arg(dir.path().join("absent.yaml"))
        .output()?;
    assert_eq!(absent.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(absent.stderr)?
            .lines()
            .filter(|line| line.starts_with("ostyr-agent-linux: "))
            .count(),
        1
    );
    let invalid = dir.path().join("invalid.yaml");
    fs::write(&invalid, "not: [valid")?;
    let output = Command::new(env!("CARGO_BIN_EXE_ostyr-agent-linux")).arg(&invalid).output()?;
    assert_eq!(output.status.code(), Some(1));
    Ok(())
}


#[test]
fn the_binary_serves_until_sigterm_and_ends_cleanly() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    let child = Command::new(env!("CARGO_BIN_EXE_ostyr-agent-linux"))
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let spool = dir.path().join("spool");
    let announced = (0..WAIT_ATTEMPTS).any(|_| {
        std::thread::sleep(WAIT_STEP);
        fs::read_to_string(&spool).is_ok_and(|text| text.contains("agent.capabilities"))
    });
    assert!(announced);
    assert!(Command::new("kill").args(["-TERM", &child.id().to_string()]).status()?.success());
    let output = child.wait_with_output()?;
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)?.contains("Totals"));
    Ok(())
}
