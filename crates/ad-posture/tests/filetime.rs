use ad_posture::filetime::{filetime_to_unix, FiletimeError, FILETIME_NEVER, TICKS_PER_SECOND, UNIX_EPOCH_SECONDS};
use std::error::Error;


const UNIX_2023: i64 = 1_700_000_000;


const TICKS_2023: u64 = 133_444_736_000_000_000;


const LAST_VALID_TICKS: u64 = 2_650_467_743_999_999_999;


const FIRST_INVALID_TICKS: u64 = 2_650_467_744_000_000_000;


const LAST_VALID_UNIX: i64 = 253_402_300_799;


#[test]
fn zero_and_never_are_none() -> Result<(), Box<dyn Error>> {
    assert_eq!(filetime_to_unix(0)?, None);
    assert_eq!(filetime_to_unix(FILETIME_NEVER)?, None);
    Ok(())
}


#[test]
fn a_known_value_converts() -> Result<(), Box<dyn Error>> {
    assert_eq!(filetime_to_unix(TICKS_2023)?, Some(UNIX_2023));
    assert_eq!(filetime_to_unix(1)?, Some(-UNIX_EPOCH_SECONDS));
    assert_eq!(filetime_to_unix(TICKS_PER_SECOND)?, Some(1 - UNIX_EPOCH_SECONDS));
    Ok(())
}


#[test]
fn the_end_of_year_9999_is_the_last_accepted_value() -> Result<(), Box<dyn Error>> {
    assert_eq!(filetime_to_unix(LAST_VALID_TICKS)?, Some(LAST_VALID_UNIX));
    assert!(matches!(filetime_to_unix(FIRST_INVALID_TICKS), Err(FiletimeError::OutOfRange(_))));
    Ok(())
}


#[test]
fn a_value_past_year_9999_is_refused_never_a_panic() -> Result<(), Box<dyn Error>> {
    assert!(filetime_to_unix(FILETIME_NEVER - 1).is_err());
    assert!(filetime_to_unix(u64::MAX).is_err());
    assert!(filetime_to_unix(u64::MAX - 1).is_err());
    Ok(())
}


#[test]
fn the_error_keeps_its_cause() -> Result<(), Box<dyn Error>> {
    let error = filetime_to_unix(u64::MAX).err().ok_or("no error")?;
    assert!(error.source().is_some());
    Ok(())
}
