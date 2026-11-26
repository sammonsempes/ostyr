#![cfg(target_os = "linux")]

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;


const HANG_GUARD: Duration = Duration::from_secs(120);


const OPEN_DIRECTORY: u32 = 0o755;


struct KillOnDrop(Child);


impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Err(failure) = self.0.kill() {
            tracing::debug!(%failure, "child already gone");
        }
        if let Err(failure) = self.0.wait() {
            tracing::debug!(%failure, "child already reaped");
        }
    }
}


fn run_binary(arguments: &[&str]) -> Result<(Option<i32>, String), Box<dyn Error>> {
    let child = Command::new(env!("CARGO_BIN_EXE_ostyr-waf"))
        .args(arguments)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut guard = KillOnDrop(child);
    let status = guard.0.wait_timeout(HANG_GUARD)?.ok_or("the binary hung")?;
    let mut text = String::new();
    std::io::Read::read_to_string(guard.0.stderr.as_mut().ok_or("no stderr")?, &mut text)?;
    Ok((status.code(), text))
}


fn directory() -> Result<tempfile::TempDir, Box<dyn Error>> {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    Ok(dir)
}


fn settings(dir: &Path, with_audit: bool) -> Result<String, Box<dyn Error>> {
    let audit = if with_audit {
        format!("audit_file: {}/audit.log\n", dir.display())
    } else {
        String::new()
    };
    let path = dir.join("settings.yaml");
    fs::write(
        &path,
        format!(
            "routes_file: {0}/missing-routes.yaml\nout_dir: {0}/out\nadmin_socket: {0}/sock\n{audit}",
            dir.display()
        ),
    )?;
    Ok(path.display().to_string())
}


#[test]
fn no_argument_or_two_arguments_print_the_usage_and_exit_one() -> Result<(), Box<dyn Error>> {
    let (code, text) = run_binary(&[])?;
    assert_eq!(code, Some(1));
    assert!(text.contains("ostyr-waf: usage: ostyr-waf <settings.yaml>"));
    let (two, _) = run_binary(&["a", "b"])?;
    assert_eq!(two, Some(1));
    Ok(())
}


#[test]
fn a_missing_settings_file_exits_one() -> Result<(), Box<dyn Error>> {
    let (code, text) = run_binary(&["/nonexistent/settings.yaml"])?;
    assert_eq!(code, Some(1));
    assert!(text.contains("ostyr-waf: the settings file was refused"));
    Ok(())
}


#[test]
fn a_settings_file_without_an_audit_path_exits_one() -> Result<(), Box<dyn Error>> {
    let dir = directory()?;
    let (code, text) = run_binary(&[&settings(dir.path(), false)?])?;
    assert_eq!(code, Some(1));
    assert!(text.contains("names no audit_file"));
    assert!(!dir.path().join("audit.log").exists());
    Ok(())
}


#[test]
fn a_refused_start_exits_one_and_is_audited() -> Result<(), Box<dyn Error>> {
    let dir = directory()?;
    let (code, text) = run_binary(&[&settings(dir.path(), true)?])?;
    assert_eq!(code, Some(1));
    assert!(text.contains("ostyr-waf: "));
    assert!(fs::read_to_string(dir.path().join("audit.log"))?.contains("denied"));
    Ok(())
}
