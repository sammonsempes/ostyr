use std::path::{Path, PathBuf};
use std::process::Command;


pub fn install_script(dir: &Path, name: &str, body: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let source = dir.join(format!("{name}.src"));
    let target = dir.join(name);
    std::fs::write(&source, format!("#!/bin/sh\n{body}\n"))?;
    let status = Command::new("install").arg("-m").arg("755").arg(&source).arg(&target).status()?;
    assert!(status.success());
    Ok(target)
}


pub fn scratch() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    Ok(tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?)
}
