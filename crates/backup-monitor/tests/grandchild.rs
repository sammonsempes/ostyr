#![cfg(unix)]

use grandchild::{adopt_with, gone_within_guard, grandchild_for, release, Outcome};
use std::error::Error;
use std::process::Command;


const FOREIGN_ATTEMPTS: usize = 2;


#[path = "common/grandchild.rs"]
mod grandchild;


#[test]
fn a_grandchild_that_already_exited_is_never_signalled() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut child = Command::new("true").spawn()?;
    let pid_file = dir.path().join("pid");
    std::fs::write(&pid_file, child.id().to_string())?;
    child.wait()?;
    let mut grandchild = grandchild_for(pid_file);
    assert_eq!(release(&mut grandchild)?, Outcome::Gone);
    Ok(())
}


#[test]
fn the_fixture_process_is_signalled_through_its_pidfd() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut child = Command::new("sleep").arg("3600").spawn()?;
    let pid_file = dir.path().join("pid");
    std::fs::write(&pid_file, child.id().to_string())?;
    let mut grandchild = grandchild_for(pid_file);
    assert_eq!(release(&mut grandchild)?, Outcome::Signalled);
    assert!(!child.wait()?.success());
    assert!(gone_within_guard(&mut grandchild)?);
    Ok(())
}


#[test]
fn a_process_that_is_not_the_fixture_is_left_alone() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut child = Command::new("sleep").arg("3601").spawn()?;
    let pid_file = dir.path().join("pid");
    std::fs::write(&pid_file, child.id().to_string())?;
    let mut grandchild = grandchild_for(pid_file);
    adopt_with(&mut grandchild, FOREIGN_ATTEMPTS)?;
    let guard = gone_within_guard(&mut grandchild);
    let outcome = release(&mut grandchild);
    let still_running = child.try_wait()?.is_none();
    child.kill()?;
    child.wait()?;
    assert!(guard.is_err());
    assert_eq!(outcome?, Outcome::Foreign);
    assert!(still_running);
    Ok(())
}
