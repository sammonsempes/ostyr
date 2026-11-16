#![cfg(unix)]

use rustix::fs::{mknodat, FileType, Mode, CWD};
use rustix::io::Errno;
use std::error::Error;
use waf::error::WafError;
use waf::tls::{check_ca_root, read_failure, NOT_REGULAR_FILE};


const FIFO_MODE: u32 = 0o600;


#[test]
fn a_fifo_is_refused_without_blocking() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let fifo = dir.path().join("root.pem");
    mknodat(CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(FIFO_MODE), 0)?;
    let result = check_ca_root(&fifo.to_string_lossy());
    assert!(matches!(result, Err(WafError::BadTls(reason)) if reason == NOT_REGULAR_FILE));
    Ok(())
}


#[test]
fn a_failed_system_call_names_the_ca_root_file() -> Result<(), Box<dyn Error>> {
    assert!(matches!(read_failure(Errno::IO), WafError::CaRoot(_)));
    Ok(())
}
