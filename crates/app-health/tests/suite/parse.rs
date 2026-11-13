use crate::suite::common::{TestResult, MAX_BYTES, SYNCHRONISED, UNSYNCHRONISED};
use app_health::error::NtpError;
use app_health::model::LeapStatus;
use app_health::parse::{parse_chrony_tracking, parse_timedatectl};
use std::io::Read;


const TIMEDATECTL_SYNC: &str = include_str!("../fixtures/timedatectl-sync.txt");


const TIMEDATECTL_UNSYNC: &str = include_str!("../fixtures/timedatectl-unsync.txt");


const STRATUM: u32 = 3;


const OFFSET: f64 = 0.000012345;


const FREQUENCY: f64 = 1.234;


const FIELD_ID: usize = 0;


const FIELD_NAME: usize = 1;


const FIELD_STRATUM: usize = 2;


const FIELD_REF_TIME: usize = 3;


const FIELD_OFFSET: usize = 4;


const FIELD_SKEW: usize = 9;


const FIELD_DELAY: usize = 10;


const FIELD_LEAP: usize = 13;


const OVERSIZED: usize = 5000;


const LONG_NAME: usize = 65;


const BAD_BYTE: u8 = 0xff;


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("boom"))
    }
}


fn line_with(index: usize, value: &str) -> String {
    SYNCHRONISED
        .trim_end()
        .split(',')
        .enumerate()
        .map(|(position, field)| if position == index { value } else { field })
        .collect::<Vec<&str>>()
        .join(",")
}


fn is_malformed<Value>(result: Result<Value, NtpError>) -> bool {
    matches!(result, Err(NtpError::Malformed { .. }))
}


#[test]
fn parses_synchronised_capture() -> TestResult {
    let tracking = parse_chrony_tracking(SYNCHRONISED.as_bytes(), MAX_BYTES)?;
    assert_eq!(tracking.reference_id, "A9FE0101");
    assert_eq!(tracking.reference_name.as_deref(), Some("169.254.1.1"));
    assert_eq!(tracking.stratum, Some(STRATUM));
    assert_eq!(tracking.system_time_offset, Some(OFFSET));
    assert_eq!(tracking.frequency, Some(FREQUENCY));
    assert_eq!(tracking.leap_status, LeapStatus::Normal);
    assert_eq!(tracking.rejected_fields, 0);
    Ok(())
}


#[test]
fn parses_unsynchronised_capture() -> TestResult {
    let tracking = parse_chrony_tracking(UNSYNCHRONISED.as_bytes(), MAX_BYTES)?;
    assert_eq!(tracking.reference_name, None);
    assert_eq!(tracking.rejected_fields, 0);
    assert_eq!(tracking.leap_status, LeapStatus::NotSynchronised);
    Ok(())
}


#[test]
fn leap_statuses() -> TestResult {
    let insert = parse_chrony_tracking(line_with(FIELD_LEAP, "Insert second").as_bytes(), MAX_BYTES)?;
    let delete = parse_chrony_tracking(line_with(FIELD_LEAP, "Delete second").as_bytes(), MAX_BYTES)?;
    assert_eq!(insert.leap_status, LeapStatus::InsertSecond);
    assert_eq!(delete.leap_status, LeapStatus::DeleteSecond);
    assert!(is_malformed(parse_chrony_tracking(line_with(FIELD_LEAP, "Bogus").as_bytes(), MAX_BYTES)));
    Ok(())
}


#[test]
fn empty_numbers_are_missing() -> TestResult {
    let blanked = line_with(FIELD_STRATUM, "");
    let tracking = parse_chrony_tracking(line_with(FIELD_OFFSET, "").as_bytes(), MAX_BYTES)?;
    let no_stratum = parse_chrony_tracking(blanked.as_bytes(), MAX_BYTES)?;
    assert_eq!(tracking.system_time_offset, None);
    assert_eq!(no_stratum.stratum, None);
    Ok(())
}


#[test]
fn oversized_input_is_refused() -> TestResult {
    let big = "x".repeat(OVERSIZED);
    assert!(matches!(
        parse_chrony_tracking(big.as_bytes(), MAX_BYTES),
        Err(NtpError::Oversized { limit: MAX_BYTES })
    ));
    assert!(matches!(
        parse_timedatectl(big.as_bytes(), MAX_BYTES),
        Err(NtpError::Oversized { limit: MAX_BYTES })
    ));
    Ok(())
}


#[test]
fn input_at_the_cap_is_accepted() -> TestResult {
    let exact = SYNCHRONISED.len() as u64;
    parse_chrony_tracking(SYNCHRONISED.as_bytes(), exact)?;
    assert!(matches!(
        parse_chrony_tracking(SYNCHRONISED.as_bytes(), exact - 1),
        Err(NtpError::Oversized { .. })
    ));
    Ok(())
}


#[test]
fn wrong_field_counts_are_malformed() -> TestResult {
    let thirteen = SYNCHRONISED.trim_end().rsplit_once(',').map(|(head, _)| head).unwrap_or("");
    let fifteen = format!("{},Normal", SYNCHRONISED.trim_end());
    assert!(is_malformed(parse_chrony_tracking(thirteen.as_bytes(), MAX_BYTES)));
    assert!(is_malformed(parse_chrony_tracking(fifteen.as_bytes(), MAX_BYTES)));
    assert!(is_malformed(parse_chrony_tracking("".as_bytes(), MAX_BYTES)));
    Ok(())
}


#[test]
fn bad_numbers_are_malformed_without_echo() -> TestResult {
    let cases = [
        ("NaN", FIELD_OFFSET),
        ("inf", FIELD_OFFSET),
        ("-inf", FIELD_SKEW),
        ("secretvalue", FIELD_SKEW),
        ("1e999", FIELD_DELAY),
        ("NaN", FIELD_REF_TIME),
        ("-1", FIELD_STRATUM),
        ("zz", FIELD_ID),
        ("ZZZZZZZZ", FIELD_ID),
    ];
    cases.iter().for_each(|(value, index)| {
        let result = parse_chrony_tracking(line_with(*index, value).as_bytes(), MAX_BYTES);
        assert!(!format!("{result:?}").contains("secretvalue"));
        assert!(is_malformed(result), "{value} at {index}");
    });
    Ok(())
}


#[test]
fn hostile_reference_names_are_dropped_and_counted() -> TestResult {
    let long = "a".repeat(LONG_NAME);
    ["-evil", "bad\u{202e}name", "caf\u{e9}", long.as_str()].iter().try_for_each(|name| {
        let tracking = parse_chrony_tracking(line_with(FIELD_NAME, name).as_bytes(), MAX_BYTES)?;
        assert_eq!(tracking.reference_name, None);
        assert_eq!(tracking.rejected_fields, 1);
        Ok::<(), NtpError>(())
    })?;
    Ok(())
}


#[test]
fn non_utf8_is_refused() -> TestResult {
    let bytes: &[u8] = &[BAD_BYTE, BAD_BYTE];
    assert!(matches!(parse_chrony_tracking(bytes, MAX_BYTES), Err(NtpError::NotUtf8(_))));
    Ok(())
}


#[test]
fn non_utf8_error_keeps_no_input_bytes() -> TestResult {
    let bytes: &[u8] = b"SECRET\xff";
    let error = parse_chrony_tracking(bytes, MAX_BYTES).err().ok_or("expected an error")?;
    let typed: &std::str::Utf8Error = match &error {
        NtpError::NotUtf8(cause) => Ok(cause),
        other => Err(format!("expected NotUtf8, got {other}")),
    }?;
    assert_eq!(typed.valid_up_to(), "SECRET".len());
    [format!("{error:?}"), format!("{error}")].iter().for_each(|text| {
        assert!(!text.contains("bytes"));
        assert!(!text.contains("83, 69, 67"));
        assert!(!text.contains("SECRET"));
    });
    assert!(std::error::Error::source(&error).is_some());
    Ok(())
}


#[test]
fn read_failure_is_an_error() -> TestResult {
    assert!(matches!(parse_chrony_tracking(FailingReader, MAX_BYTES), Err(NtpError::Read(_))));
    assert!(matches!(parse_timedatectl(FailingReader, MAX_BYTES), Err(NtpError::Read(_))));
    Ok(())
}


#[test]
fn timedatectl_synchronised() -> TestResult {
    let state = parse_timedatectl(TIMEDATECTL_SYNC.as_bytes(), MAX_BYTES)?;
    assert_eq!(state.ntp_enabled, Some(true));
    assert_eq!(state.synchronized, Some(true));
    assert_eq!(state.timezone.as_deref(), Some("Europe/Paris"));
    assert_eq!(state.rejected_fields, 0);
    Ok(())
}


#[test]
fn timedatectl_unsynchronised() -> TestResult {
    let state = parse_timedatectl(TIMEDATECTL_UNSYNC.as_bytes(), MAX_BYTES)?;
    assert_eq!(state.synchronized, Some(false));
    Ok(())
}


#[test]
fn timedatectl_missing_keys_and_unknown_lines() -> TestResult {
    let state = parse_timedatectl("Other=1\nno equals here\n".as_bytes(), MAX_BYTES)?;
    assert_eq!((state.ntp_enabled, state.synchronized, state.timezone), (None, None, None));
    assert_eq!(state.rejected_fields, 0);
    Ok(())
}


#[test]
fn timedatectl_duplicates_and_bad_values_are_malformed() -> TestResult {
    let cases = [
        "NTP=yes\nNTP=no\n",
        "NTPSynchronized=yes\nNTPSynchronized=yes\n",
        "Timezone=A\nTimezone=B\n",
        "NTP=maybe\n",
        "NTPSynchronized=1\n",
    ];
    cases
        .iter()
        .for_each(|text| assert!(is_malformed(parse_timedatectl(text.as_bytes(), MAX_BYTES)), "{text}"));
    Ok(())
}


#[test]
fn timedatectl_hostile_timezone_is_dropped_and_counted() -> TestResult {
    let state = parse_timedatectl("Timezone=-bad\n".as_bytes(), MAX_BYTES)?;
    assert_eq!(state.timezone, None);
    assert_eq!(state.rejected_fields, 1);
    Ok(())
}


#[test]
fn spaces_are_kept_and_an_empty_timezone_is_dropped() -> TestResult {
    let named = parse_chrony_tracking(line_with(FIELD_NAME, "pool ntp").as_bytes(), MAX_BYTES)?;
    assert_eq!(named.reference_name.as_deref(), Some("pool ntp"));
    let state = parse_timedatectl("Timezone=\n".as_bytes(), MAX_BYTES)?;
    assert_eq!((state.timezone, state.rejected_fields), (None, 1));
    Ok(())
}
