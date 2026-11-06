use crate::support::{
    bench, connection, failed_login, FailingReader, FailingWriter, NewlineFails, BEACON, BRUTE_FORCE, DISTINCT_DESTINATIONS, LOGIN, SEC_2, SEC_3,
    SEC_4, SEC_5,
};
use crate::types::TestResult;
use serde_json::{json, Value};
use std::io::{BufReader, Read};
use std::path::Path;
use stream_correlation::checkpoint::load_checkpoint;
use stream_correlation::cli::{event_id, run_stream, Summary, CHECKPOINT_EVERY};
use stream_correlation::error::CorrelationError;
use stream_correlation::window::Alert;


const BURST_LENGTH: u64 = 3;


const NUMERIC_ID: u64 = 7;


const TWO_ALERTS: u64 = 2;


const FREQUENT: u64 = 1;


fn lines(events: &[Value]) -> String {
    events.iter().map(|event| format!("{event}\n")).collect()
}


fn burst() -> Vec<Value> {
    vec![failed_login(0, "a", "h1"), failed_login(1, "b", "h1"), failed_login(SEC_2, "c", "h1")]
}


#[test]
fn a_stream_yields_alert_lines_a_summary_and_a_final_checkpoint() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    let mut text = lines(&burst());
    text.push_str("this is not json\n");
    let mut output = Vec::new();
    let summary = run_stream(&bench.engine, &mut text.as_bytes(), &mut output, &bench.checkpoint, CHECKPOINT_EVERY)?;
    assert_eq!(
        summary,
        Summary {
            events: BURST_LENGTH,
            alerts: 1,
            malformed: 1
        }
    );
    let alerts: Vec<Alert> = String::from_utf8(output)?.lines().map(serde_json::from_str).collect::<Result<_, _>>()?;
    assert_eq!(alerts.len(), 1);
    assert!(load_checkpoint(&bench.checkpoint)?.is_some());
    Ok(())
}


#[test]
fn periodic_checkpoints_are_written_before_the_end() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    let failing_after_first = lines(&[failed_login(0, "a", "h1")]);
    let reader = failing_after_first.as_bytes().chain(FailingReader);
    let result = run_stream(&bench.engine, &mut BufReader::new(reader), &mut Vec::new(), &bench.checkpoint, FREQUENT);
    assert!(matches!(result, Err(CorrelationError::Output(_))));
    let restored = load_checkpoint(&bench.checkpoint)?.ok_or("no periodic checkpoint")?;
    assert_eq!(restored.counters.processed, 1);
    Ok(())
}


#[test]
fn periodic_checkpoints_can_be_turned_off() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    let one = lines(&[failed_login(0, "a", "h1")]);
    let reader = one.as_bytes().chain(FailingReader);
    assert!(run_stream(&bench.engine, &mut BufReader::new(reader), &mut Vec::new(), &bench.checkpoint, 0).is_err());
    assert!(load_checkpoint(&bench.checkpoint)?.is_none());
    Ok(())
}


#[test]
fn checkpoint_failures_stop_the_stream() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    let missing = bench.dir.path().join("no-such-dir").join("cp.json");
    let text = lines(&burst());
    assert!(matches!(
        run_stream(&bench.engine, &mut text.as_bytes(), &mut Vec::new(), &missing, FREQUENT),
        Err(CorrelationError::CheckpointIo { .. })
    ));
    assert!(matches!(
        run_stream(&bench.engine, &mut "".as_bytes(), &mut Vec::new(), Path::new(&missing), CHECKPOINT_EVERY),
        Err(CorrelationError::CheckpointIo { .. })
    ));
    Ok(())
}


#[test]
fn output_failures_stop_the_stream() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    let text = lines(&burst());
    assert!(matches!(
        run_stream(
            &bench.engine,
            &mut text.as_bytes(),
            &mut FailingWriter,
            &bench.checkpoint,
            CHECKPOINT_EVERY
        ),
        Err(CorrelationError::Serialize(_))
    ));
    let other = crate::support::bench(&[LOGIN, BRUTE_FORCE])?;
    assert!(matches!(
        run_stream(
            &other.engine,
            &mut text.as_bytes(),
            &mut NewlineFails,
            &other.checkpoint,
            CHECKPOINT_EVERY
        ),
        Err(CorrelationError::Output(_))
    ));
    Ok(())
}


#[test]
fn event_ids_come_from_the_event_or_the_line_number() -> TestResult {
    assert_eq!(event_id(&json!({"event": {"id": "abc"}}), 1), "abc");
    assert_eq!(event_id(&json!({"event.id": NUMERIC_ID}), 1), NUMERIC_ID.to_string());
    assert_eq!(event_id(&json!({}), 1), "line-1");
    Ok(())
}


#[test]
fn several_rules_share_one_stream() -> TestResult {
    let bench = bench(&[LOGIN, BEACON, BRUTE_FORCE, DISTINCT_DESTINATIONS])?;
    let mut events = burst();
    events.extend([
        connection(SEC_3, "x", "h1", "10.0.0.1"),
        connection(SEC_4, "y", "h1", "10.0.0.2"),
        connection(SEC_5, "z", "h1", "10.0.0.3"),
    ]);
    let mut output = Vec::new();
    let summary = run_stream(
        &bench.engine,
        &mut lines(&events).as_bytes(),
        &mut output,
        &bench.checkpoint,
        CHECKPOINT_EVERY,
    )?;
    assert_eq!(summary.alerts, TWO_ALERTS);
    Ok(())
}
