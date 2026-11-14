use backup_monitor::error::BackupError;
use backup_monitor::model::Limits;
use backup_monitor::parse::parse_pbs;
use std::error::Error;


const MEBIBYTE: usize = 1024 * 1024;


const LISTING_BYTES: usize = 64 * MEBIBYTE;


const ELEMENT: &str = "{},";


const SMALL_COUNT: usize = 10;


const CHILD_ENV: &str = "T417_PBS_MEMORY_CHILD";


const ADDRESS_SPACE_BYTES: &str = "--as=450000000";


fn hostile_listing_is_refused_at_the_count() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_bytes: (LISTING_BYTES + MEBIBYTE) as u64,
        max_snapshots: SMALL_COUNT,
        ..Limits::default()
    };
    let listing = format!("[{}{{}}]", ELEMENT.repeat(LISTING_BYTES / ELEMENT.len()));
    assert!(matches!(
        parse_pbs(listing.as_bytes(), "store1", &limits),
        Err(BackupError::TooManySnapshots { .. })
    ));
    Ok(())
}


#[test]
fn memory_limited_child_refuses_the_hostile_listing() -> Result<(), Box<dyn Error>> {
    std::env::var(CHILD_ENV).map_or(Ok(()), |_marker| hostile_listing_is_refused_at_the_count())
}


#[test]
fn a_64_mib_listing_of_empty_elements_is_refused_under_an_address_space_limit() -> Result<(), Box<dyn Error>> {
    let output = std::process::Command::new("prlimit")
        .arg(ADDRESS_SPACE_BYTES)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args(["--exact", "memory_limited_child_refuses_the_hostile_listing", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"), "the child test did not run");
    Ok(())
}
