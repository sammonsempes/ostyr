#[path = "common/types.rs"]
mod types;


use dns_rpz::atomic::write_atomic;
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use types::TestResult;


#[test]
fn a_file_is_replaced_whole_and_no_temporary_file_is_left() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("zone.db");
    write_atomic(&path, b"first\n")?;
    assert_eq!(fs::read_to_string(&path)?, "first\n");
    write_atomic(&path, b"second\n")?;
    assert_eq!(fs::read_to_string(&path)?, "second\n");
    assert_eq!(fs::read_dir(dir.path())?.count(), 1);
    Ok(())
}


#[test]
fn a_missing_directory_is_an_error() -> TestResult {
    let dir = tempdir()?;
    assert!(write_atomic(&dir.path().join("missing").join("zone.db"), b"x").is_err());
    Ok(())
}


#[test]
fn a_path_without_a_parent_is_an_error() -> TestResult {
    assert!(write_atomic(Path::new("/"), b"x").is_err());
    Ok(())
}


#[test]
fn a_directory_in_the_way_leaves_it_untouched_and_no_temporary_file() -> TestResult {
    let dir = tempdir()?;
    let target = dir.path().join("zone.db");
    fs::create_dir(&target)?;
    assert!(write_atomic(&target, b"x").is_err());
    assert!(target.is_dir());
    assert_eq!(fs::read_dir(dir.path())?.count(), 1);
    Ok(())
}
