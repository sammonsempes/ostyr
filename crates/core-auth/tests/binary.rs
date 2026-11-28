#![cfg(unix)]


#[path = "support/types.rs"]
mod types;


use std::error::Error;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use tempfile::{tempdir, TempDir};
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-auth");


const OWNER_ONLY: u32 = 0o600;


const KEY_BYTES: usize = 32;


const KEY_FILL: u8 = 5;


const PASSWORD: &str = "Lab-Admin-Pass-1";


fn site(dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let key = dir.join("store.key");
    fs::write(&key, [KEY_FILL; KEY_BYTES])?;
    fs::set_permissions(&key, fs::Permissions::from_mode(OWNER_ONLY))?;
    fs::write(dir.join("compromised.txt"), "passwordpassword\n")?;
    Ok([dir.join("accounts.json"), dir.join("audit.log"), key, dir.join("compromised.txt")]
        .iter()
        .map(|path| path.display().to_string())
        .collect())
}


fn run_with(arguments: &[String], input: &str) -> Result<Output, Box<dyn Error>> {
    let mut child = Command::new(PROGRAM)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().ok_or("no stdin")?.write_all(input.as_bytes())?;
    Ok(child.wait_with_output()?)
}


fn prepared() -> Result<(TempDir, Vec<String>), Box<dyn Error>> {
    let dir = tempdir()?;
    let arguments = site(dir.path())?;
    Ok((dir, arguments))
}


#[test]
fn no_argument_prints_the_usage_and_fails() -> TestResult {
    let output = run_with(&[], "")?;
    let text = String::from_utf8(output.stderr)?;
    assert!(!output.status.success());
    assert!(text.contains("usage: ostyr-auth <store>"), "{text}");
    Ok(())
}


#[test]
fn a_missing_key_file_is_a_named_failure() -> TestResult {
    let (dir, arguments) = prepared()?;
    fs::remove_file(dir.path().join("store.key"))?;
    let output = run_with(&arguments, "check x\n")?;
    let text = String::from_utf8(output.stderr)?;
    assert!(!output.status.success());
    assert!(text.contains("key file rejected"), "{text}");
    Ok(())
}


#[test]
fn the_real_binary_refuses_the_break_glass_status_without_a_session() -> TestResult {
    let (_dir, arguments) = prepared()?;
    let output = run_with(&arguments, "breakglass-status no-such-session\n")?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8(output.stdout)?.starts_with("error "));
    Ok(())
}


#[test]
fn bootstrap_creates_the_first_administrator_and_the_store_file() -> TestResult {
    let (dir, arguments) = prepared()?;
    let output = run_with(&arguments, &format!("bootstrap admin {PASSWORD}\n"))?;
    let text = String::from_utf8(output.stdout.clone())?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(!text.is_empty());
    assert!(dir.path().join("accounts.json").exists());
    Ok(())
}
