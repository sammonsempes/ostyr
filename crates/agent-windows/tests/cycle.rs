#[path = "common/types.rs"]
mod types;


use agent_windows::cycle::{poll_cycle, sleep_seconds};
use agent_windows::error::{PollError, RunError};
use agent_windows::model::{
    ChannelState, PollEnv, PollTotals, RunEnd, RunRequest, MAX_REPOLLS_PER_CYCLE, POLL_INTERVAL_SECONDS, SECURITY, WEVTUTIL_PATH,
};
use core_export::ecs::to_json;
use ecs_normalise::types::SeenIds;
use std::fs;
use std::path::PathBuf;
use std::sync::LazyLock;
use types::TestResult;


static LOGGING: LazyLock<bool> =
    LazyLock::new(|| tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(std::io::sink).finish()).is_ok());


const TIME: &str = "2026-11-03T10:00:00.1234567Z";


const BOM: [u8; 2] = [0xFF, 0xFE];


const SMALL_BATCH: u32 = 2;


const POLLS_PER_CYCLE: usize = 5;


const SECOND_CYCLE_FIRST_BATCH: u32 = 64;


const READ_AFTER_FIRST_CYCLE: u64 = 62;


const LONG_LOG: u64 = 1_000;


const SHORT_LOG: u64 = 3;


const MAX_SPOOL: u64 = 1_073_741_824;


const LINE_LIMIT: usize = 524_288;


const OUTPUT_CAP: usize = 8_388_608;


const DEADLINE: u64 = 30;


const LOCK_ATTEMPTS: u32 = 10;


const FAIL_AT_REQUEST: usize = 5;


const QUERIES_IN_A_QUIET_POLL: usize = 3;


const QUERY_INDEX: usize = 2;


const COUNT_INDEX: usize = 3;


fn security(record: u64) -> String {
    format!(
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/>\
         <EventID>4625</EventID><TimeCreated SystemTime='{TIME}'/><EventRecordID>{record}</EventRecordID><Channel>Security</Channel>\
         <Computer>WIN-01</Computer></System><EventData><Data Name='TargetUserName'>bob</Data><Data Name='Status'>0xC000006D</Data>\
         <Data Name='IpAddress'>10.0.0.9</Data></EventData></Event>"
    )
}


fn wide(text: &str) -> Vec<u8> {
    BOM.into_iter().chain(text.encode_utf16().flat_map(u16::to_le_bytes)).collect()
}


fn numbers(query: &str) -> (u64, u64) {
    let digits: Vec<u64> = query
        .split(|found: char| !found.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse().ok())
        .collect();
    (digits.first().copied().unwrap_or(0), digits.get(1).copied().unwrap_or(0))
}


fn serve(newest: u64, request: &RunRequest<'_>) -> String {
    let query = request.args.get(QUERY_INDEX).cloned().unwrap_or_else(String::new);
    let count: u64 = request
        .args
        .get(COUNT_INDEX)
        .map_or(1, |found| found.trim_start_matches("/c:").parse().unwrap_or(1));
    if request.args.iter().any(|arg| arg == "/rd:true") {
        security(newest)
    } else if query.contains("EventRecordID=") {
        security(numbers(&query).0)
    } else {
        let (after, upper) = numbers(&query);
        (after + 1..=upper.min(after + count)).map(security).collect()
    }
}


struct Harness {
    dir: tempfile::TempDir,
}


fn harness() -> Result<Harness, Box<dyn std::error::Error>> {
    let made = Harness { dir: tempfile::tempdir()? };
    fs::create_dir_all(made.dir.path().join("state"))?;
    Ok(made)
}


fn cycle(harness: &Harness, state: &mut ChannelState, newest: u64, fail_at: usize) -> (Result<Vec<PollTotals>, PollError>, Vec<u64>, usize) {
    LazyLock::force(&LOGGING);
    let state_dir: PathBuf = harness.dir.path().join("state");
    let spool: PathBuf = harness.dir.path().join("spool");
    let mut requests = 0usize;
    let mut run = |request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> {
        requests += 1;
        sink(&wide(&serve(newest, request)));
        if requests >= fail_at {
            Err(RunError::Reader)
        } else {
            Ok(RunEnd::Done)
        }
    };
    let mut seen = SeenIds::new();
    let mut env = PollEnv {
        run: &mut run,
        encode: to_json,
        program: WEVTUTIL_PATH,
        state_dir: &state_dir,
        spool: &spool,
        line_limit: LINE_LIMIT,
        lock_attempts: LOCK_ATTEMPTS,
        max_output_bytes: OUTPUT_CAP,
        deadline_seconds: DEADLINE,
        max_spool_bytes: MAX_SPOOL,
        seen: &mut seen,
    };
    let mut waits: Vec<u64> = Vec::new();
    let result = poll_cycle(&mut env, &SECURITY, state, &mut |seconds| waits.push(seconds));
    (result, waits, requests)
}


fn cursor_id(harness: &Harness) -> Option<u64> {
    fs::read_to_string(harness.dir.path().join("state").join(SECURITY.cursor_file))
        .ok()
        .and_then(|text| text.split(' ').next().and_then(|id| id.parse().ok()))
}


#[test]
fn full_batches_repoll_at_once_up_to_the_cap_then_the_cycle_waits_once() -> TestResult {
    let lab = harness()?;
    let mut state = ChannelState {
        batch: SMALL_BATCH,
        ..ChannelState::default()
    };
    let (result, waits, _) = cycle(&lab, &mut state, LONG_LOG, usize::MAX);
    let polls = result?;
    assert_eq!(polls.len(), POLLS_PER_CYCLE);
    assert_eq!(polls.len(), usize::try_from(MAX_REPOLLS_PER_CYCLE)? + 1);
    assert!(polls.iter().all(|totals| totals.full_batches == 1));
    assert_eq!(waits, vec![POLL_INTERVAL_SECONDS]);
    assert_eq!(cursor_id(&lab), Some(READ_AFTER_FIRST_CYCLE));
    assert_eq!(state.batch, SECOND_CYCLE_FIRST_BATCH);
    Ok(())
}


#[test]
fn a_batch_that_is_not_full_ends_the_cycle_after_one_poll() -> TestResult {
    let lab = harness()?;
    let mut state = ChannelState::default();
    let (result, waits, requests) = cycle(&lab, &mut state, SHORT_LOG, usize::MAX);
    let polls = result?;
    assert_eq!(polls.len(), 1);
    assert_eq!(polls.first().map(|totals| totals.full_batches), Some(0));
    assert_eq!(waits, vec![POLL_INTERVAL_SECONDS]);
    assert_eq!(requests, QUERIES_IN_A_QUIET_POLL);
    Ok(())
}


#[test]
fn a_failure_in_a_repoll_ends_the_cycle_with_the_error_and_no_wait() -> TestResult {
    let lab = harness()?;
    let mut state = ChannelState {
        batch: SMALL_BATCH,
        ..ChannelState::default()
    };
    let (result, waits, _) = cycle(&lab, &mut state, LONG_LOG, FAIL_AT_REQUEST);
    assert!(matches!(result, Err(PollError::Run(_))));
    assert!(waits.is_empty());
    Ok(())
}


#[test]
fn a_failure_in_the_first_poll_is_returned() -> TestResult {
    let lab = harness()?;
    let mut state = ChannelState::default();
    let (result, waits, _) = cycle(&lab, &mut state, SHORT_LOG, 1);
    assert!(matches!(result, Err(PollError::Run(_))));
    assert!(waits.is_empty());
    Ok(())
}


#[test]
fn the_production_wait_returns() -> TestResult {
    sleep_seconds(0);
    Ok(())
}
