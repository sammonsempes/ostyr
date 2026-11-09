use core_pg::error::{checked_sqlstate, PgError, INVALID_SQLSTATE};
use core_pg::password::{open_checked, read_limited, read_password};
use core_pg::tls::client_config;
use std::error::Error;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;


fn make_fifo(path: &Path) -> Result<(), Box<dyn Error>> {
    let status = Command::new("mkfifo").arg(path).status()?;
    assert!(status.success());
    Ok(())
}


#[test]
fn a_fifo_password_path_is_refused_without_blocking() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let fifo = dir.path().join("pass");
    make_fifo(&fifo)?;
    assert!(matches!(read_password(&fifo), Err(PgError::NotRegular { .. })));
    Ok(())
}


#[test]
fn a_fifo_ca_path_is_refused_without_blocking() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let fifo = dir.path().join("ca.pem");
    make_fifo(&fifo)?;
    assert!(matches!(client_config(&fifo), Err(PgError::NotRegular { .. })));
    Ok(())
}


#[test]
fn a_directory_is_refused() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    assert!(matches!(read_limited(dir.path(), 1), Err(PgError::NotRegular { .. })));
    Ok(())
}


#[test]
fn a_server_code_is_kept_only_when_well_formed() -> Result<(), Box<dyn Error>> {
    assert_eq!(checked_sqlstate("42P01"), "42P01");
    ["42p01", "4260", "426011", "", "42 01", "42\u{e9}0"]
        .iter()
        .for_each(|code| assert_eq!(checked_sqlstate(code), INVALID_SQLSTATE, "{code}"));
    Ok(())
}


#[test]
fn a_failing_inspection_of_the_opened_handle_is_an_io_error() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let file = dir.path().join("pass");
    std::fs::write(&file, b"x")?;
    let result = open_checked(&file, |_handle| Err(std::io::Error::other("fstat failed")));
    assert!(matches!(result, Err(PgError::Io { .. })));
    Ok(())
}
