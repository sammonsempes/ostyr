#![cfg(unix)]

#[path = "common/types.rs"]
mod types;


use agent_windows::serve::production_winget;
use agent_windows::winget_find::{finding_name, list_directory, locate_winget, MAX_WINDOWSAPPS_ENTRIES};
use std::fs;
use types::TestResult;


const EXTRA: usize = 2;


#[test]
fn the_directory_listing_marks_directories_and_refuses_a_link() -> TestResult {
    let root = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    fs::create_dir(root.path().join("real"))?;
    fs::write(root.path().join("plain"), b"x")?;
    std::os::unix::fs::symlink(root.path().join("real"), root.path().join("link"))?;
    let mut found = list_directory(root.path())?;
    found.sort_by(|left, right| left.name.cmp(&right.name));
    let flags: Vec<(&str, bool)> = found.iter().map(|entry| (entry.name.as_str(), entry.directory)).collect();
    assert_eq!(flags, vec![("link", false), ("plain", false), ("real", true)]);
    assert!(list_directory(&root.path().join("absent")).is_err());
    Ok(())
}


#[test]
fn a_listing_over_the_bound_reads_one_entry_past_it_only() -> TestResult {
    let root = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    (0..=MAX_WINDOWSAPPS_ENTRIES + EXTRA).try_for_each(|index| fs::write(root.path().join(format!("f{index}")), b""))?;
    let found = list_directory(root.path())?;
    assert_eq!(found.len(), MAX_WINDOWSAPPS_ENTRIES + 1);
    Ok(())
}


#[test]
fn the_production_lookup_names_a_missing_parent() -> TestResult {
    let error = locate_winget().err().ok_or("no WindowsApps here")?;
    assert_eq!(finding_name(&error), "windowsapps_unreadable");
    let hooks = production_winget();
    assert!((hooks.locate)().is_err());
    assert!((hooks.run_id)() > 0);
    Ok(())
}
