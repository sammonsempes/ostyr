#[path = "common/types.rs"]
mod types;


use core_export::error::ExportError;
use core_export::types::BoxError;
use core_export::webhook::{backoff_delay, batch_body, batches, deliver, RetryPolicy, BACKOFF_BASE, BACKOFF_CAP, MAX_ATTEMPTS};
use std::error::Error;
use std::time::Duration;
use types::TestResult;


const POLICY_ATTEMPTS: u32 = 4;


const HUGE_ATTEMPT: u32 = 1000;


const DOUBLE: u32 = 2;


const QUADRUPLE: u32 = 4;


const EVENT_COUNT: usize = 5;


const BATCH_SIZE: usize = 2;


const LAST_BATCH_EVENTS: usize = 1;


const SINGLE_EVENT_BATCHES: usize = 3;


const MILLISECOND: Duration = Duration::from_millis(1);


fn events(count: usize) -> Vec<String> {
    (0..count).map(|index| format!("{{\"n\":{index}}}")).collect()
}


#[test]
fn default_policy_uses_the_constants() -> TestResult {
    let policy = RetryPolicy::default();
    assert_eq!((policy.base, policy.cap, policy.max_attempts), (BACKOFF_BASE, BACKOFF_CAP, MAX_ATTEMPTS));
    Ok(())
}


#[test]
fn delay_doubles_then_stops_at_the_cap() -> TestResult {
    let policy = RetryPolicy::default();
    assert_eq!(backoff_delay(&policy, 0), BACKOFF_BASE);
    assert_eq!(backoff_delay(&policy, 1), BACKOFF_BASE * DOUBLE);
    assert_eq!(backoff_delay(&policy, DOUBLE), BACKOFF_BASE * QUADRUPLE);
    assert_eq!(backoff_delay(&policy, HUGE_ATTEMPT), BACKOFF_CAP);
    Ok(())
}


#[test]
fn a_batch_is_a_json_array() -> TestResult {
    assert_eq!(batch_body(&events(BATCH_SIZE)), r#"[{"n":0},{"n":1}]"#);
    assert_eq!(batch_body(&[]), "[]");
    Ok(())
}


#[test]
fn events_are_split_into_batches_of_at_most_the_size() -> TestResult {
    let split = batches(&events(EVENT_COUNT), BATCH_SIZE);
    assert_eq!(
        split.iter().map(|(count, _body)| *count).collect::<Vec<_>>(),
        vec![BATCH_SIZE, BATCH_SIZE, LAST_BATCH_EVENTS]
    );
    assert_eq!(split.last().map(|(_count, body)| body.as_str()), Some(r#"[{"n":4}]"#));
    assert_eq!(batches(&events(SINGLE_EVENT_BATCHES), 0).len(), SINGLE_EVENT_BATCHES);
    assert!(batches(&[], BATCH_SIZE).is_empty());
    Ok(())
}


#[test]
fn delivery_succeeds_on_the_first_attempt_without_sleeping() -> TestResult {
    let mut sleeps = Vec::new();
    let attempts = deliver(&RetryPolicy::default(), &mut |_body| Ok(()), &mut |delay| sleeps.push(delay), "[]")?;
    assert_eq!(attempts, 1);
    assert!(sleeps.is_empty());
    Ok(())
}


#[test]
fn delivery_retries_with_growing_delays_until_it_succeeds() -> TestResult {
    let mut calls = u32::MIN;
    let mut sleeps = Vec::new();
    let mut post = |_body: &str| -> Result<(), BoxError> {
        calls += 1;
        if calls < POLICY_ATTEMPTS {
            Err("down".into())
        } else {
            Ok(())
        }
    };
    let attempts = deliver(&RetryPolicy::default(), &mut post, &mut |delay| sleeps.push(delay), "[]")?;
    assert_eq!(attempts, POLICY_ATTEMPTS);
    assert_eq!(sleeps, vec![BACKOFF_BASE, BACKOFF_BASE * DOUBLE, BACKOFF_BASE * QUADRUPLE]);
    Ok(())
}


#[test]
fn retries_stop_at_the_attempt_cap_and_keep_the_last_error() -> TestResult {
    let policy = RetryPolicy {
        base: MILLISECOND,
        cap: MILLISECOND,
        max_attempts: POLICY_ATTEMPTS,
    };
    let mut calls = u32::MIN;
    let mut sleeps = Vec::new();
    let mut post = |_body: &str| -> Result<(), BoxError> {
        calls += 1;
        Err(format!("failure {calls}").into())
    };
    let error = deliver(&policy, &mut post, &mut |delay| sleeps.push(delay), "[]")
        .err()
        .ok_or("must fail")?;
    assert_eq!(calls, POLICY_ATTEMPTS);
    assert_eq!(sleeps.len(), (POLICY_ATTEMPTS - 1) as usize);
    assert!(matches!(
        error,
        ExportError::Exhausted {
            attempts: POLICY_ATTEMPTS,
            ..
        }
    ));
    assert_eq!(error.source().map(ToString::to_string), Some(format!("failure {POLICY_ATTEMPTS}")));
    Ok(())
}


#[test]
fn zero_attempts_fails_without_posting() -> TestResult {
    let policy = RetryPolicy {
        max_attempts: 0,
        ..RetryPolicy::default()
    };
    let error = deliver(&policy, &mut |_body| Ok(()), &mut |_delay| {}, "[]").err().ok_or("must fail")?;
    assert!(error.source().is_none());
    Ok(())
}
