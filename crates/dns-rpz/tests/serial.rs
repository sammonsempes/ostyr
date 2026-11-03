#[path = "common/types.rs"]
mod types;


use dns_rpz::error::SerialError;
use dns_rpz::serial::{advance, day_base, next_serial, read_counter};
use std::fs;
use tempfile::tempdir;
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const TODAY: u32 = 2_026_110_300;


const TOMORROW: u32 = 2_026_110_400;


const LAST_OF_THE_DAY: u32 = 2_026_110_399;


const JANUARY_NINTH: u32 = 2_026_010_900;


const SECOND: u32 = TODAY + 2;


const FIVE_TODAY: u32 = TODAY + 5;


const FIVE_TOMORROW: u32 = TOMORROW + 5;


const SIXTH_TOMORROW: u32 = TOMORROW + 6;


const LATE_TODAY: OffsetDateTime = datetime!(2026-11-03 23:59:59 UTC);


const JANUARY: OffsetDateTime = datetime!(2026-01-09 00:00:00 UTC);


const BEFORE_COMMON_ERA: OffsetDateTime = datetime!(-0001-01-01 00:00:00 UTC);


const FAR_FUTURE: OffsetDateTime = datetime!(9999-01-01 00:00:00 UTC);


const MORNING: OffsetDateTime = datetime!(2026-11-03 08:00:00 UTC);


const MID_MORNING: OffsetDateTime = datetime!(2026-11-03 09:00:00 UTC);


const MIDNIGHT_AFTER: OffsetDateTime = datetime!(2026-11-04 00:00:00 UTC);


#[test]
fn the_day_base_is_the_utc_date_followed_by_two_zeros() -> TestResult {
    assert_eq!(day_base(LATE_TODAY)?, TODAY);
    assert_eq!(day_base(JANUARY)?, JANUARY_NINTH);
    Ok(())
}


#[test]
fn a_clock_outside_the_serial_range_is_refused() -> TestResult {
    assert!(matches!(day_base(BEFORE_COMMON_ERA), Err(SerialError::Clock(_))));
    assert!(matches!(day_base(FAR_FUTURE), Err(SerialError::Clock(_))));
    Ok(())
}


#[test]
fn the_serial_increases_within_a_day_and_across_days() -> TestResult {
    assert_eq!(next_serial(None, TODAY)?, TODAY + 1);
    assert_eq!(next_serial(Some(TODAY + 1), TODAY)?, SECOND);
    assert_eq!(next_serial(Some(TODAY - 1), TODAY)?, TODAY + 1);
    assert_eq!(next_serial(Some(FIVE_TODAY), TOMORROW)?, TOMORROW + 1);
    Ok(())
}


#[test]
fn the_serial_never_goes_back_when_the_clock_does() -> TestResult {
    assert_eq!(next_serial(Some(FIVE_TOMORROW), TODAY)?, SIXTH_TOMORROW);
    Ok(())
}


#[test]
fn the_hundredth_serial_of_a_day_is_refused() -> TestResult {
    assert_eq!(next_serial(Some(LAST_OF_THE_DAY - 1), TODAY)?, LAST_OF_THE_DAY);
    assert!(matches!(next_serial(Some(LAST_OF_THE_DAY), TODAY), Err(SerialError::Exhausted(last)) if last == LAST_OF_THE_DAY));
    Ok(())
}


#[test]
fn the_counter_survives_reopening() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("counter");
    assert_eq!(read_counter(&path)?, None);
    assert_eq!(advance(&path, MORNING)?, TODAY + 1);
    assert_eq!(advance(&path, MID_MORNING)?, SECOND);
    assert_eq!(read_counter(&path)?, Some(SECOND));
    assert_eq!(advance(&path, MIDNIGHT_AFTER)?, TOMORROW + 1);
    assert_eq!(fs::read_to_string(&path)?, format!("{}\n", TOMORROW + 1));
    Ok(())
}


#[test]
fn an_unusable_counter_is_an_error_and_is_never_reset() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("counter");
    fs::write(&path, "garbage\n")?;
    assert!(matches!(read_counter(&path), Err(SerialError::Counter { .. })));
    assert!(advance(&path, MORNING).is_err());
    assert_eq!(fs::read_to_string(&path)?, "garbage\n");
    assert!(matches!(read_counter(dir.path()), Err(SerialError::Io(_))));
    Ok(())
}


#[test]
fn a_counter_that_cannot_be_written_is_an_error() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("missing").join("counter");
    assert!(matches!(advance(&path, MORNING), Err(SerialError::Io(_))));
    Ok(())
}
