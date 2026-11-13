mod common;


use common::types::TestResult;
use hunt_packs::check::{run_check, CheckError};
use hunt_packs::error::PackError;
use hunt_packs::packs::{load_file, load_packs, yaml_files, yaml_path, MAX_ENTRIES};
use std::fs::{create_dir, read_dir, write};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::Path;
use tempfile::tempdir;


const SAMPLE_PACKS: usize = 3;


const QUERY_MARKER: &str = "SECRETMARKER";


pub fn pack_yaml(id: &str, technique: &str) -> String {
    format!(
        "packs:
  - id: {id}
    title: T
    hypothesis: H
    technique: {technique}
    source: osquery
    query: SELECT '{QUERY_MARKER}'
    schedule_seconds: 300
    window_seconds: 60
    cost: {{ max_rows: 1, max_seconds: 1 }}
    baseline: {{ max_matches: 0 }}
"
    )
}


pub fn failing_entry() -> io::Result<std::fs::DirEntry> {
    Err(io::Error::other("injected failure"))
}


#[test]
fn valid_directory_loads_in_name_order() -> TestResult {
    let dir = tempdir()?;
    write(dir.path().join("b.yaml"), pack_yaml("second", "T1059"))?;
    write(dir.path().join("a.yaml"), pack_yaml("first", "T1059.001"))?;
    write(dir.path().join("notes.txt"), "not a pack file")?;
    create_dir(dir.path().join("sub.yaml"))?;
    let loaded = load_packs(dir.path())?;
    let ids: Vec<&str> = loaded.iter().map(|item| item.pack.id.as_str()).collect();
    assert_eq!(ids, ["first", "second"]);
    assert!(loaded.first().ok_or("none")?.file.ends_with("a.yaml"));
    Ok(())
}


#[test]
fn duplicate_across_files_names_both() -> TestResult {
    let dir = tempdir()?;
    write(dir.path().join("a.yaml"), pack_yaml("same", "T1059"))?;
    write(dir.path().join("b.yaml"), pack_yaml("same", "T1059"))?;
    let error = load_packs(dir.path()).err().ok_or("accepted")?;
    let text = error.to_string();
    assert!(matches!(error, PackError::DuplicateAcrossFiles { .. }));
    assert!(text.contains("a.yaml") && text.contains("b.yaml") && text.contains("`same`"), "{text}");
    Ok(())
}


#[test]
fn duplicate_within_a_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let body = pack_yaml("same", "T1059");
    let second = body.replace("packs:\n", "");
    write(dir.path().join("a.yaml"), format!("{body}{second}"))?;
    let error = load_packs(dir.path()).err().ok_or("accepted")?;
    assert!(matches!(error, PackError::DuplicateId { .. }));
    Ok(())
}


#[test]
fn invalid_file_error_never_echoes_the_query() -> TestResult {
    let dir = tempdir()?;
    write(dir.path().join("a.yaml"), pack_yaml("one", "T12345"))?;
    let text = load_packs(dir.path()).err().ok_or("accepted")?.to_string();
    assert!(text.contains("invalid `technique`") && !text.contains(QUERY_MARKER), "{text}");
    Ok(())
}


#[test]
#[cfg(unix)]
fn symlink_is_refused() -> TestResult {
    let dir = tempdir()?;
    let target = tempdir()?;
    write(target.path().join("real.yaml"), pack_yaml("one", "T1059"))?;
    symlink(target.path().join("real.yaml"), dir.path().join("link.yaml"))?;
    let error = load_packs(dir.path()).err().ok_or("accepted")?;
    assert!(matches!(error, PackError::Symlink { .. }));
    assert!(error.to_string().contains("link.yaml"));
    Ok(())
}


#[test]
#[cfg(unix)]
fn symlink_with_another_name_is_ignored() -> TestResult {
    let dir = tempdir()?;
    symlink(dir.path().join("nowhere"), dir.path().join("link.txt"))?;
    assert!(load_packs(dir.path())?.is_empty());
    Ok(())
}


#[test]
fn too_many_entries_is_refused() -> TestResult {
    let dir = tempdir()?;
    (0..=MAX_ENTRIES).try_for_each(|index| write(dir.path().join(format!("f{index}.txt")), ""))?;
    let error = yaml_files(dir.path()).err().ok_or("accepted")?;
    assert!(matches!(error, PackError::TooManyEntries { .. }));
    assert!(error.to_string().contains("more than"));
    Ok(())
}


#[test]
fn io_failures_are_errors() -> TestResult {
    let dir = tempdir()?;
    assert!(matches!(load_packs(&dir.path().join("missing")), Err(PackError::Scan(_))));
    assert!(matches!(load_file(&dir.path().join("missing.yaml")), Err(PackError::Config(_))));
    let error = yaml_path(failing_entry()).err().ok_or("accepted")?;
    assert!(matches!(error, PackError::Scan(_)));
    assert!(!error.to_string().is_empty());
    Ok(())
}


#[test]
fn yaml_path_of_a_real_entry() -> TestResult {
    let dir = tempdir()?;
    write(dir.path().join("a.yaml"), "")?;
    let entry = read_dir(dir.path())?.next().ok_or("empty")?;
    assert!(yaml_path(entry)?.is_some());
    Ok(())
}


#[test]
fn check_prints_one_line_per_pack() -> TestResult {
    let dir = tempdir()?;
    write(dir.path().join("a.yaml"), pack_yaml("first", "T1059.001"))?;
    let mut out = Vec::new();
    run_check(&[dir.path().display().to_string()], &mut out)?;
    assert_eq!(String::from_utf8(out)?, "first\tT1059.001\tosquery\t300\n");
    Ok(())
}


#[test]
fn check_refuses_bad_arguments_and_directories() -> TestResult {
    let mut out = Vec::new();
    assert!(matches!(run_check(&[], &mut out), Err(CheckError::Usage)));
    assert!(matches!(run_check(&["a".to_string(), "b".to_string()], &mut out), Err(CheckError::Usage)));
    let dir = tempdir()?;
    write(dir.path().join("a.yaml"), pack_yaml("one", "T12345"))?;
    assert!(matches!(
        run_check(&[dir.path().display().to_string()], &mut out),
        Err(CheckError::Pack(_))
    ));
    Ok(())
}


pub struct FailingWriter;


impl io::Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn check_reports_a_write_failure() -> TestResult {
    let dir = tempdir()?;
    write(dir.path().join("a.yaml"), pack_yaml("one", "T1059"))?;
    let error = run_check(&[dir.path().display().to_string()], &mut FailingWriter)
        .err()
        .ok_or("accepted")?;
    assert!(matches!(error, CheckError::Write(_)));
    assert!(!error.to_string().is_empty());
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_symlink_passed_to_load_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let target = dir.path().join("real.txt");
    write(&target, pack_yaml("a", "T1059"))?;
    let link = dir.path().join("x.yaml");
    symlink(&target, &link)?;
    assert!(matches!(load_file(&link), Err(PackError::Config(_))));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_fifo_is_refused_without_blocking() -> TestResult {
    use rustix::fs::{mknodat, FileType, Mode, CWD};
    let dir = tempdir()?;
    let fifo = dir.path().join("x.yaml");
    mknodat(CWD, &fifo, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0)?;
    assert!(matches!(load_file(&fifo), Err(PackError::NotRegular { .. })));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_directory_named_yaml_is_refused() -> TestResult {
    let dir = tempdir()?;
    let sub = dir.path().join("x.yaml");
    create_dir(&sub)?;
    assert!(matches!(load_file(&sub), Err(PackError::NotRegular { .. })));
    Ok(())
}


#[test]
fn committed_sample_packs_are_valid() -> TestResult {
    let samples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples").join("packs");
    let mut out = Vec::new();
    run_check(&[samples.display().to_string()], &mut out)?;
    assert_eq!(String::from_utf8(out)?.lines().count(), SAMPLE_PACKS);
    Ok(())
}
