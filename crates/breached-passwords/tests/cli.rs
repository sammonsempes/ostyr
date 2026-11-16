#![cfg(unix)]


#[path = "support/files.rs"]
mod files;
#[path = "support/table.rs"]
mod table;
#[path = "support/types.rs"]
mod types;


use breached_passwords::cli::{run, run_reporting, CliError};
use files::write_file;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::ExitCode;
use table::{entries, render};
use types::TestResult;


const LIST_SIZE: usize = 200;


const OWNER_ONLY: u32 = 0o600;


const GROUP_READABLE: u32 = 0o644;


const HASH_FILE_MODE_DIR: &str = "hashes.txt";


struct FailingOut;


impl Write for FailingOut {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn hash_file(dir: &tempfile::TempDir, text: &str, mode: u32) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = write_file(dir, HASH_FILE_MODE_DIR, text.as_bytes())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
    Ok(path)
}


fn path_text(path: &Path) -> String {
    path.display().to_string()
}


#[test]
fn verdicts_are_printed_by_line_number_never_by_hash() -> TestResult {
    let table = entries(LIST_SIZE);
    let dir = tempfile::tempdir()?;
    let list = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let present = render(&table.iter().take(1).copied().collect::<Vec<_>>(), "\n");
    let present_hash = present.split(':').next().ok_or("no hash")?;
    let absent = "0".repeat(present_hash.len());
    let hashes = hash_file(&dir, &format!("{present_hash}\n{absent}\n"), OWNER_ONLY)?;
    let mut out = Vec::new();
    run(&[&path_text(&list), &path_text(&hashes)], &mut out)?;
    let text = String::from_utf8(out)?;
    assert_eq!(text, "1 compromised\n2 clean\n");
    Ok(())
}


#[test]
fn every_refusal_is_a_typed_error() -> TestResult {
    let table = entries(LIST_SIZE);
    let dir = tempfile::tempdir()?;
    let list = path_text(&write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?);
    let good = path_text(&hash_file(&dir, "00000000000000000000000000000000\n", OWNER_ONLY)?);
    let loose = path_text(&write_file(&dir, "loose.txt", b"x")?);
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(GROUP_READABLE))?;
    let reversed: Vec<_> = table.iter().rev().copied().collect();
    let unsorted = path_text(&write_file(&dir, "unsorted.txt", render(&reversed, "\n").as_bytes())?);
    let bad_hashes = path_text(&write_file(&dir, "bad.txt", b"zz\n")?);
    std::fs::set_permissions(&bad_hashes, std::fs::Permissions::from_mode(OWNER_ONLY))?;
    let mut sink = Vec::new();
    assert!(matches!(run(&[], &mut sink), Err(CliError::Usage)));
    assert!(matches!(run(&["/nonexistent/list", &good], &mut sink), Err(CliError::List(_))));
    assert!(matches!(run(&[&unsorted, &good], &mut sink), Err(CliError::List(_))));
    assert!(matches!(run(&[&list, &loose], &mut sink), Err(CliError::Secret(_))));
    assert!(matches!(run(&[&list, &bad_hashes], &mut sink), Err(CliError::HashFile(_))));
    assert!(matches!(run(&[&list, &good], &mut FailingOut), Err(CliError::Output(_))));
    Ok(())
}


#[test]
fn the_reporting_wrapper_maps_outcomes_to_exit_codes() -> TestResult {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_reporting(&[], &mut out, &mut err)?;
    assert_eq!(code, ExitCode::FAILURE);
    assert!(String::from_utf8(err)?.contains("usage"));
    let table = entries(LIST_SIZE);
    let dir = tempfile::tempdir()?;
    let list = path_text(&write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?);
    let hashes = path_text(&hash_file(&dir, "", OWNER_ONLY)?);
    let ok = run_reporting(&[&list, &hashes], &mut Vec::new(), &mut Vec::new())?;
    assert_eq!(ok, ExitCode::SUCCESS);
    assert!(run_reporting(&[], &mut Vec::new(), &mut FailingOut).is_err());
    Ok(())
}


#[test]
fn a_refused_list_prints_no_verdict() -> TestResult {
    let dir = tempfile::tempdir()?;
    let empty = write_file(&dir, "empty.txt", b"")?;
    let hashes = hash_file(&dir, "00000000000000000000000000000000\n", OWNER_ONLY)?;
    let mut out = Vec::new();
    let result = run(&[&path_text(&empty), &path_text(&hashes)], &mut out);
    assert!(matches!(result, Err(CliError::List(_))));
    assert!(out.is_empty());
    Ok(())
}
