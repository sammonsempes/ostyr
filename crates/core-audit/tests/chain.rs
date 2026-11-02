#[path = "support/failing_reader.rs"]
mod failing_reader;
#[path = "support/log_builder.rs"]
mod log_builder;
#[path = "support/sample.rs"]
mod sample;
#[path = "support/types.rs"]
mod types;


use core_audit::canonical::{compute_hash, seal};
use core_audit::error::{AuditError, BrokenReason};
use core_audit::log::{append, genesis_log, head};
use core_audit::model::{ActorKind, Outcome, GENESIS_HASH};
use core_audit::verify::{verify, VerifyReport};
use failing_reader::flaky_reader;
use log_builder::build_log;
use proptest::prelude::*;
use sample::entry;
use std::io::BufReader;
use time::{Date, Month, UtcOffset};
use types::TestResult;


const RECORD_COUNT: usize = 4;


const KIND_COUNT: usize = 3;


const SECOND_LINE: usize = 2;


const THIRD_LINE: usize = 3;


const OFFSET_HOURS: i8 = 2;


const SHA256_HEX_LENGTH: usize = 64;


fn verify_text(lines: &[String], anchor: Option<&str>) -> Result<VerifyReport, AuditError> {
    verify(lines.concat().as_bytes(), anchor)
}


fn replaced(lines: &[String], index: usize, from: &str, to: &str) -> Vec<String> {
    lines
        .iter()
        .enumerate()
        .map(|(position, line)| if position == index { line.replacen(from, to, 1) } else { line.clone() })
        .collect()
}


#[test]
fn round_trip_verifies_and_reports_head() -> TestResult {
    let (lines, expected_head) = build_log(RECORD_COUNT)?;
    let report = verify_text(&lines, Some(&expected_head))?;
    assert_eq!(
        report,
        VerifyReport {
            records: RECORD_COUNT,
            head: expected_head
        }
    );
    assert_eq!(report.head.len(), SHA256_HEX_LENGTH);
    Ok(())
}


#[test]
fn empty_log_verifies_at_genesis() -> TestResult {
    let report = verify(&b""[..], None)?;
    assert_eq!(
        report,
        VerifyReport {
            records: 0,
            head: GENESIS_HASH.to_owned()
        }
    );
    assert!(verify(&b""[..], Some(GENESIS_HASH)).is_ok());
    Ok(())
}


#[test]
fn appended_record_carries_every_field() -> TestResult {
    let log = genesis_log(Vec::new());
    let record = append(&log, entry(0)?)?;
    assert_eq!(record.timestamp, "2023-11-14T22:13:20Z");
    assert_eq!(record.actor_id, "user-0");
    assert_eq!(record.previous_hash, GENESIS_HASH);
    assert_eq!(record.hash, compute_hash(&record));
    assert_eq!(head(&log), record.hash);
    Ok(())
}


#[test]
fn timestamp_is_converted_to_utc() -> TestResult {
    let mut local = entry(0)?;
    local.timestamp = local.timestamp.to_offset(UtcOffset::from_hms(OFFSET_HOURS, 0, 0)?);
    let record = seal(local, GENESIS_HASH)?;
    assert_eq!(record.timestamp, "2023-11-14T22:13:20Z");
    Ok(())
}


#[test]
fn unformattable_timestamp_is_an_error() -> TestResult {
    let mut early = entry(0)?;
    early.timestamp = Date::from_calendar_date(-1, Month::January, 1)?.midnight().assume_utc();
    let log = genesis_log(Vec::new());
    assert!(matches!(append(&log, early), Err(AuditError::Timestamp(_))));
    assert_eq!(head(&log), GENESIS_HASH);
    Ok(())
}


#[test]
fn edited_record_is_reported_at_its_line() -> TestResult {
    let (lines, _) = build_log(RECORD_COUNT)?;
    let tampered = replaced(&lines, 1, "tenant-a", "tenant-b");
    let result = verify_text(&tampered, None);
    assert!(matches!(
        result,
        Err(AuditError::Broken {
            line: SECOND_LINE,
            reason: BrokenReason::HashMismatch
        })
    ));
    Ok(())
}


#[test]
fn deleted_record_is_reported_at_the_next_line() -> TestResult {
    let (mut lines, _) = build_log(RECORD_COUNT)?;
    lines.remove(1);
    let result = verify_text(&lines, None);
    assert!(matches!(
        result,
        Err(AuditError::Broken {
            line: SECOND_LINE,
            reason: BrokenReason::ChainMismatch
        })
    ));
    Ok(())
}


#[test]
fn deleted_first_record_is_reported() -> TestResult {
    let (mut lines, _) = build_log(RECORD_COUNT)?;
    lines.remove(0);
    assert!(matches!(
        verify_text(&lines, None),
        Err(AuditError::Broken {
            line: 1,
            reason: BrokenReason::ChainMismatch
        })
    ));
    Ok(())
}


#[test]
fn reordered_records_are_reported() -> TestResult {
    let (mut lines, _) = build_log(RECORD_COUNT)?;
    lines.swap(1, SECOND_LINE);
    let result = verify_text(&lines, None);
    assert!(matches!(
        result,
        Err(AuditError::Broken {
            line: SECOND_LINE,
            reason: BrokenReason::ChainMismatch
        })
    ));
    Ok(())
}


#[test]
fn inserted_record_is_reported() -> TestResult {
    let (mut lines, _) = build_log(RECORD_COUNT)?;
    let duplicate = lines.get(1).cloned().ok_or("missing line")?;
    lines.insert(SECOND_LINE, duplicate);
    let result = verify_text(&lines, None);
    assert!(matches!(
        result,
        Err(AuditError::Broken {
            line: THIRD_LINE,
            reason: BrokenReason::ChainMismatch
        })
    ));
    Ok(())
}


#[test]
fn malformed_unterminated_and_non_canonical_lines_are_reported() -> TestResult {
    let (lines, _) = build_log(RECORD_COUNT)?;
    let garbage = verify(&b"garbage\n"[..], None);
    assert!(matches!(
        garbage,
        Err(AuditError::Broken {
            line: 1,
            reason: BrokenReason::Malformed(_)
        })
    ));
    let unterminated = lines.concat();
    let trimmed = unterminated.trim_end_matches('\n');
    assert!(matches!(
        verify(trimmed.as_bytes(), None),
        Err(AuditError::Broken {
            line: RECORD_COUNT,
            reason: BrokenReason::Unterminated
        })
    ));
    let spaced = replaced(&lines, 0, ",\"hash\"", ", \"hash\"");
    assert!(matches!(
        verify_text(&spaced, None),
        Err(AuditError::Broken {
            line: 1,
            reason: BrokenReason::NonCanonical
        })
    ));
    let message = verify_text(&spaced, None)
        .err()
        .map(|error| error.to_string())
        .ok_or("expected an error")?;
    assert!(message.starts_with("line 1:"));
    Ok(())
}


#[test]
fn truncated_tail_is_only_caught_with_the_anchor() -> TestResult {
    let (mut lines, anchor) = build_log(RECORD_COUNT)?;
    lines.pop();
    assert!(verify_text(&lines, None).is_ok());
    let result = verify_text(&lines, Some(&anchor));
    assert!(matches!(result, Err(AuditError::HeadMismatch { .. })));
    let message = result.err().map(|error| error.to_string()).ok_or("expected an error")?;
    assert!(message.contains(&anchor));
    Ok(())
}


#[test]
fn rewritten_chain_does_not_match_the_anchor() -> TestResult {
    let (_, anchor) = build_log(RECORD_COUNT)?;
    let (forged, _) = build_log(RECORD_COUNT - 1)?;
    assert!(matches!(verify_text(&forged, Some(&anchor)), Err(AuditError::HeadMismatch { .. })));
    Ok(())
}


#[test]
fn read_failure_is_an_io_error() {
    let result = verify(BufReader::new(flaky_reader(Vec::new(), true)), None);
    assert!(matches!(result, Err(AuditError::Io(_))));
}


const MAX_PROPERTY_RECORDS: usize = 4;


proptest! {
    #[test]
    fn any_single_byte_change_is_detected(
        texts in proptest::collection::vec(".{0,12}", 1..=MAX_PROPERTY_RECORDS),
        position in any::<usize>(),
        delta in 1..=u8::MAX,
    ) {
        let log = genesis_log(Vec::new());
        for (index, text) in texts.iter().enumerate() {
            let mut new = entry(index).map_err(|error| TestCaseError::fail(error.to_string()))?;
            new.target.clone_from(text);
            new.justification = Some(text.clone());
            append(&log, new).map_err(|error| TestCaseError::fail(error.to_string()))?;
        }
        let state = log.state.into_inner().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let mut bytes = state.writer;
        let index = position % bytes.len();
        let byte = bytes.get_mut(index).ok_or_else(|| TestCaseError::fail("index out of range"))?;
        *byte ^= delta;
        prop_assert!(verify(bytes.as_slice(), Some(&state.head)).is_err());
        prop_assert!(verify(bytes.as_slice(), None).is_err());
    }
}


#[test]
fn every_actor_kind_and_outcome_round_trips() -> TestResult {
    let log = genesis_log(Vec::new());
    [ActorKind::User, ActorKind::Ai, ActorKind::System]
        .into_iter()
        .zip([Outcome::Success, Outcome::Failure, Outcome::Denied])
        .try_for_each(|(kind, outcome)| {
            entry(0).map_err(|error| error.to_string()).and_then(|mut new| {
                new.actor.kind = kind;
                new.outcome = outcome;
                append(&log, new).map(|_| ()).map_err(|error| error.to_string())
            })
        })?;
    let state = log.state.into_inner()?;
    assert_eq!(verify(state.writer.as_slice(), Some(&state.head))?.records, KIND_COUNT);
    Ok(())
}


#[test]
fn read_failure_after_valid_records_is_an_io_error_and_success_works() -> TestResult {
    let (lines, expected_head) = build_log(RECORD_COUNT)?;
    let healthy = verify(BufReader::new(flaky_reader(lines.concat().into_bytes(), false)), Some(&expected_head))?;
    assert_eq!(healthy.records, RECORD_COUNT);
    let failing = verify(BufReader::new(flaky_reader(lines.concat().into_bytes(), true)), None);
    assert!(matches!(failing, Err(AuditError::Io(_))));
    Ok(())
}
