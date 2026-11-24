#[path = "common/types.rs"]
mod types;


use agent_windows::room::{file_len, pending_bytes, NOT_REGULAR_FILE};
use types::TestResult;


const DIRECTORY_ENTRIES: u32 = 300;


#[test]
fn a_directory_is_an_error_whatever_size_the_filesystem_reports_for_it() -> TestResult {
    let dir = tempfile::tempdir()?;
    let directory = dir.path().join("directory");
    std::fs::create_dir(&directory)?;
    (0..DIRECTORY_ENTRIES).try_for_each(|index| std::fs::write(directory.join(format!("entry-with-a-long-name-{index:04}")), ""))?;
    let length = file_len(&directory).err().map(|failure| failure.to_string());
    assert_eq!(length.as_deref(), Some(NOT_REGULAR_FILE));
    let pending = pending_bytes(&directory).err().map(|failure| failure.to_string());
    assert_eq!(pending.as_deref(), Some(NOT_REGULAR_FILE));
    Ok(())
}


#[test]
fn a_missing_file_is_zero_and_a_regular_file_is_its_size() -> TestResult {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("spool");
    assert_eq!(file_len(&file)?, 0);
    std::fs::write(&file, "abc")?;
    assert_eq!(file_len(&file)?, u64::try_from("abc".len())?);
    Ok(())
}
