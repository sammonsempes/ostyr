#![cfg(unix)]


#[path = "support/files.rs"]
mod files;
#[path = "support/types.rs"]
mod types;


use breached_passwords::error::ListError;
use breached_passwords::list::{handle_metadata, open_list, open_list_with};
use files::write_file;
use std::fs::File;
use std::io;
use std::process::Command;
use types::TestResult;


const CONTENT: &[u8] = b"abc";


fn failing_inspect(_: &File) -> io::Result<std::fs::Metadata> {
    Err(io::Error::other("injected"))
}


#[test]
fn a_regular_file_opens_with_its_size() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", CONTENT)?;
    let list = open_list(&path)?;
    assert_eq!(list.size, CONTENT.len() as u64);
    assert!(handle_metadata(&list.file)?.is_file());
    Ok(())
}


#[test]
fn a_symlink_a_directory_a_fifo_and_a_missing_file_are_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let target = write_file(&dir, "real.txt", CONTENT)?;
    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink(&target, &link)?;
    assert!(matches!(open_list(&link), Err(ListError::Symlink { .. })));
    assert!(matches!(open_list(dir.path()), Err(ListError::NotRegular { .. })));
    let fifo = dir.path().join("fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    assert!(matches!(open_list(&fifo), Err(ListError::NotRegular { .. })));
    assert!(matches!(open_list(&dir.path().join("missing")), Err(ListError::Open { .. })));
    assert!(matches!(open_list_with(&target, failing_inspect), Err(ListError::Open { .. })));
    Ok(())
}
