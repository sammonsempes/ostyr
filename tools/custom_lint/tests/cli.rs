use std::process::Command;
use tempfile::tempdir;


mod support;


const BINARY: &str = env!("CARGO_BIN_EXE_custom_lint");


#[test]
pub fn dirty_workspace_exits_non_zero_with_the_report() -> anyhow::Result<()> {
    let workspace = tempdir()?;
    support::write_workspace(workspace.path())?;
    let output = Command::new(BINARY).arg(workspace.path()).output()?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(String::from_utf8(output.stdout)?, support::EXPECTED_REPORT);
    Ok(())
}


#[test]
pub fn clean_workspace_exits_zero() -> anyhow::Result<()> {
    let workspace = tempdir()?;
    std::fs::create_dir_all(workspace.path().join("crates"))?;
    std::fs::create_dir_all(workspace.path().join("tools"))?;
    let output = Command::new(BINARY).arg(workspace.path()).output()?;
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}


#[test]
pub fn missing_argument_fails_with_usage() -> anyhow::Result<()> {
    let output = Command::new(BINARY).output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("usage: custom_lint <workspace root>"));
    Ok(())
}
