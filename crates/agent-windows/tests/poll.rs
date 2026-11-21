#[path = "poll_support/types.rs"]
mod types;


use agent_windows::error::{PollError, RunError};
use agent_windows::model::{
    Channel, ChannelState, PollEnv, PollTotals, RunEnd, RunRequest, CHANNEL_NOT_FOUND_EXIT, MAX_EVENTS_PER_POLL, MAX_ITEM_BYTES, SECURITY, SYSMON,
    WEVTUTIL_PATH,
};
use agent_windows::newest::newest_args;
use agent_windows::poll::{poll_channel, query_args};
use agent_windows::types::EncodeFn;
use core_export::ecs::{to_json, EcsEvent};
use core_export::error::ExportError;
use ecs_normalise::types::SeenIds;
use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tempfile::TempDir;
use types::{Requests, TestResult};


static LOGGING: LazyLock<bool> =
    LazyLock::new(|| tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(std::io::sink).finish()).is_ok());


const LINE_LIMIT: usize = 524_288;


const LOCK_ATTEMPTS: u32 = 10;


const OUTPUT_CAP: usize = 8_388_608;


const DEADLINE: u64 = 30;


const SMALL_LINE_LIMIT: usize = 100;


const TIME: &str = "2026-11-03T10:00:00.1234567Z";


const SEC_PROVIDER: &str = "Microsoft-Windows-Security-Auditing";


const SECURITY_DATA: &str = "<Data Name='TargetUserName'>bob</Data><Data Name='Status'>0xC000006D</Data><Data Name='IpAddress'>10.0.0.9</Data>";


const SYSMON_DATA: &str = "<Data Name='UtcTime'>2026-11-03 10:00:00.123</Data><Data Name='Image'>C:\\Windows\\notepad.exe</Data>";


const HALF: u32 = 250;


const QUARTER: u32 = 125;


const THREE: u32 = 3;


const PAD: usize = 20_000;


const FIELD_PAD: usize = 8_000;


const FIELDS: usize = 10;


const PAIR: u64 = 2;


const TWO_LINES: usize = 2;


const THREE_LINES: usize = 3;


const EVENT_LOGON_FAILED: u32 = 4625;


const EVENT_UNKNOWN_SYSMON: u32 = 99;


const EVENT_UNKNOWN_SECURITY: u32 = 9999;


const COUNT_INDEX: usize = 3;


const QUERY_INDEX: usize = 2;


const DOUBLED_BATCH: u32 = 2;


const FIRST: u64 = 10;


const SECOND: u64 = 11;


const THIRD: u64 = 12;


const FOURTH: u64 = 13;


const FIFTH: u64 = 14;


const FAR: u64 = 50;


const FAILED_EXIT: i32 = 1;


const WIDE_CURSOR: usize = 200;


const BIG_COMPUTER: usize = 3_000;


const HUGE_ID: u64 = 9_223_372_036_854_775_806;


const REPLACED_TWO: u64 = 2;


const SINGLE: u32 = 1;


const TWO_LIMIT: u32 = 2;


const BAD_CURSORS: usize = 6;


const HALVES: usize = 2;


const BOM_BYTES: [u8; 2] = [0xFF, 0xFE];


const LONE_BOM_BYTES: [u8; 2] = [0xFF, 0xFE];


const LONE_HIGH_BYTES: [u8; 2] = [0x00, 0xD8];


#[derive(Clone)]
pub struct Reply {
    pub chunks: Vec<Vec<u8>>,
    pub end: Result<RunEnd, ()>,
}


pub struct Script {
    pub newest: Reply,
    pub main: VecDeque<Reply>,
}


fn wide(text: &str) -> Vec<u8> {
    BOM_BYTES.into_iter().chain(text.encode_utf16().flat_map(u16::to_le_bytes)).collect()
}


fn reply(text: &str, end: RunEnd) -> Reply {
    Reply {
        chunks: vec![wide(text)],
        end: Ok(end),
    }
}


fn ok(text: &str) -> Reply {
    reply(text, RunEnd::Done)
}


fn broken(end: RunEnd) -> Reply {
    Reply {
        chunks: Vec::new(),
        end: Ok(end),
    }
}


fn script(newest: u64, main: Vec<Reply>) -> Script {
    Script {
        newest: ok(&security(newest)),
        main: main.into(),
    }
}


fn event(source: &str, event_id: u32, record: u64, data: &str) -> String {
    let provider = if source == "sysmon" { "Microsoft-Windows-Sysmon" } else { SEC_PROVIDER };
    let channel = if source == "sysmon" {
        "Microsoft-Windows-Sysmon/Operational"
    } else {
        "Security"
    };
    format!(
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='{provider}'/><EventID>{event_id}</EventID>\
         <TimeCreated SystemTime='{TIME}'/><EventRecordID>{record}</EventRecordID><Channel>{channel}</Channel><Computer>WIN-01</Computer></System>\
         <EventData>{data}</EventData></Event>"
    )
}


fn security(record: u64) -> String {
    event("security", EVENT_LOGON_FAILED, record, SECURITY_DATA)
}


fn sysmon(record: u64) -> String {
    event("sysmon", 1, record, SYSMON_DATA)
}


struct Lab {
    dir: TempDir,
}


fn lab() -> Result<Lab, Box<dyn Error>> {
    let made = Lab { dir: tempfile::tempdir()? };
    fs::create_dir_all(made.dir.path().join("state"))?;
    Ok(made)
}


fn state_dir(lab: &Lab) -> PathBuf {
    lab.dir.path().join("state")
}


fn spool_path(lab: &Lab) -> PathBuf {
    lab.dir.path().join("spool")
}


fn spool_lines(lab: &Lab) -> io::Result<Vec<String>> {
    match fs::read_to_string(spool_path(lab)) {
        Ok(text) => Ok(text.lines().map(str::to_string).collect()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}


fn cursor_text(lab: &Lab, channel: &Channel) -> Option<String> {
    fs::read_to_string(state_dir(lab).join(channel.cursor_file)).ok()
}


fn expected_cursor(record: u64) -> Option<String> {
    Some(format!("{record} {TIME}\n"))
}


fn set_cursor(lab: &Lab, channel: &Channel, record: u64) -> TestResult {
    Ok(fs::write(state_dir(lab).join(channel.cursor_file), format!("{record} {TIME}\n"))?)
}


fn main_queries(requests: &Requests) -> Vec<&Vec<String>> {
    requests.iter().filter(|args| !args.iter().any(|arg| arg == "/rd:true")).collect()
}


fn count_arg(args: &[String]) -> Option<String> {
    args.get(COUNT_INDEX).cloned()
}


fn query_arg(args: &[String]) -> Option<String> {
    args.get(QUERY_INDEX).cloned()
}


fn bounded(after: u64, newest: u64) -> Option<String> {
    Some(format!("/q:*[System[(EventRecordID>{after} and EventRecordID<={newest})]]"))
}


fn failing_encode(_event: &EcsEvent) -> Result<String, ExportError> {
    Err(ExportError::Io {
        context: "test".to_string(),
        source: std::io::Error::from(std::io::ErrorKind::Other),
    })
}


fn run_poll(lab: &Lab, channel: &Channel, state: &mut ChannelState, scripted: Script) -> (Result<PollTotals, PollError>, Requests) {
    run_poll_in(&state_dir(lab), &spool_path(lab), channel, state, (scripted, to_json, LINE_LIMIT))
}


fn run_poll_with(
    lab: &Lab,
    channel: &Channel,
    state: &mut ChannelState,
    scripted: Script,
    options: (EncodeFn, usize),
) -> (Result<PollTotals, PollError>, Requests) {
    run_poll_in(&state_dir(lab), &spool_path(lab), channel, state, (scripted, options.0, options.1))
}


fn run_poll_in(
    state_dir: &Path,
    spool: &Path,
    channel: &Channel,
    state: &mut ChannelState,
    scripted: (Script, EncodeFn, usize),
) -> (Result<PollTotals, PollError>, Requests) {
    LazyLock::force(&LOGGING);
    let (mut remaining, encode, line_limit) = scripted;
    let mut requests: Requests = Vec::new();
    let mut run = |request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> {
        assert_eq!(request.program, WEVTUTIL_PATH);
        requests.push(request.args.to_vec());
        let served = if request.args.iter().any(|arg| arg == "/rd:true") {
            remaining.newest.clone()
        } else {
            remaining.main.pop_front().unwrap_or_else(|| ok(""))
        };
        served.chunks.iter().for_each(|chunk| sink(chunk));
        served.end.map_err(|()| RunError::Reader)
    };
    let mut seen = SeenIds::new();
    let mut env = PollEnv {
        run: &mut run,
        encode,
        program: WEVTUTIL_PATH,
        state_dir,
        spool,
        line_limit,
        lock_attempts: LOCK_ATTEMPTS,
        max_output_bytes: OUTPUT_CAP,
        deadline_seconds: DEADLINE,
        seen: &mut seen,
    };
    let result = poll_channel(&mut env, channel, state);
    (result, requests)
}


fn totals(result: Result<PollTotals, PollError>) -> Result<PollTotals, Box<dyn Error>> {
    Ok(result?)
}


#[test]
fn two_events_are_spooled_the_cursor_follows_and_both_queries_are_exact() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let text = format!("{}{}", security(FIRST), security(SECOND));
    let (result, requests) = run_poll(&lab, &SECURITY, &mut state, script(SECOND, vec![ok(&text)]));
    let counts = totals(result)?;
    assert_eq!(counts.spooled, PAIR);
    let lines = spool_lines(&lab)?;
    assert_eq!(lines.len(), TWO_LINES);
    assert!(lines.iter().all(|line| line.contains("authentication")));
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(SECOND));
    let expected_newest: Vec<String> = ["qe", "Security", "/c:1", "/rd:true", "/f:xml", "/uni:true"]
        .iter()
        .map(|arg| (*arg).to_string())
        .collect();
    let expected_main: Vec<String> = [
        "qe",
        "Security",
        "/q:*[System[(EventRecordID>0 and EventRecordID<=11)]]",
        "/c:500",
        "/rd:false",
        "/f:xml",
        "/uni:true",
    ]
    .iter()
    .map(|arg| (*arg).to_string())
    .collect();
    assert_eq!(requests, vec![expected_newest, expected_main]);
    assert_eq!(Some(&newest_args(&SECURITY)), requests.first());
    Ok(())
}


#[test]
fn a_caught_up_cursor_runs_no_main_query_and_an_empty_result_changes_nothing() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    totals(run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![ok(&security(FIRST))])).0)?;
    let (caught, caught_requests) = run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![]));
    assert_eq!(totals(caught)?, PollTotals::default());
    assert!(main_queries(&caught_requests).is_empty());
    let (empty, requests) = run_poll(&lab, &SECURITY, &mut state, script(SECOND, vec![ok("")]));
    assert_eq!(totals(empty)?, PollTotals::default());
    assert_eq!(main_queries(&requests).first().and_then(|args| query_arg(args)), bounded(FIRST, SECOND));
    assert_eq!(spool_lines(&lab)?.len(), 1);
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(FIRST));
    Ok(())
}


#[test]
fn the_query_for_the_largest_id_is_formatted_by_the_code() -> TestResult {
    let args = query_args(&SECURITY, u64::MAX, u64::MAX, MAX_EVENTS_PER_POLL);
    assert_eq!(
        args.get(QUERY_INDEX).map(String::as_str),
        Some("/q:*[System[(EventRecordID>18446744073709551615 and EventRecordID<=18446744073709551615)]]")
    );
    assert!(args.iter().any(|arg| arg == "/uni:true"));
    assert!(args.iter().all(|arg| !arg.contains("cmd") && !arg.contains("powershell")));
    Ok(())
}


#[test]
fn an_event_without_a_time_still_moves_the_cursor_with_a_placeholder() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let text = security(FIRST).replace(&format!("<TimeCreated SystemTime='{TIME}'/>"), "");
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![ok(&text)])).0)?;
    assert_eq!((counts.spooled, counts.malformed), (0, 1));
    assert_eq!(cursor_text(&lab, &SECURITY), Some(format!("{FIRST} -\n")));
    Ok(())
}


#[test]
fn a_sysmon_event_is_spooled_as_a_process_event() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let counts = totals(run_poll(&lab, &SYSMON, &mut state, script(FIRST, vec![ok(&sysmon(FIRST))])).0)?;
    assert_eq!(counts.spooled, 1);
    assert!(spool_lines(&lab)?.iter().all(|line| line.contains("notepad.exe")));
    Ok(())
}


#[test]
fn an_unknown_sysmon_id_is_spooled_and_counted() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let text = event("sysmon", EVENT_UNKNOWN_SYSMON, FIRST, SYSMON_DATA);
    let counts = totals(run_poll(&lab, &SYSMON, &mut state, script(FIRST, vec![ok(&text)])).0)?;
    assert_eq!((counts.spooled, counts.unknown), (1, 1));
    assert_eq!(cursor_text(&lab, &SYSMON), expected_cursor(FIRST));
    Ok(())
}


#[test]
fn an_unknown_security_id_is_counted_and_the_cursor_advances() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let text = event("security", EVENT_UNKNOWN_SECURITY, FIRST, SECURITY_DATA);
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![ok(&text)])).0)?;
    assert_eq!((counts.spooled, counts.unknown), (0, 1));
    assert!(spool_lines(&lab)?.is_empty());
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(FIRST));
    Ok(())
}


#[test]
fn an_oversized_item_between_two_good_ones_leaves_a_stub() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let big = event("security", EVENT_LOGON_FAILED, SECOND, &"x".repeat(MAX_ITEM_BYTES + 1));
    let text = format!("{}{big}{}", security(FIRST), security(THIRD));
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, script(THIRD, vec![ok(&text)])).0)?;
    assert_eq!((counts.spooled, counts.oversized), (PAIR, 1));
    let lines = spool_lines(&lab)?;
    assert_eq!(lines.len(), THREE_LINES);
    assert!(lines
        .get(1)
        .is_some_and(|line| line.contains("agent.event_refused") && line.contains("oversized") && line.contains("\"record_id\":11")));
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(THIRD));
    Ok(())
}


#[test]
fn a_long_computer_name_before_the_record_id_does_not_hide_it() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let text = security(FIRST).replace("<Channel>", &format!("<Computer>{}</Computer><Channel>", "h".repeat(BIG_COMPUTER)));
    let padded = text.replace("<TimeCreated", &format!("<Computer>{}</Computer><TimeCreated", "h".repeat(BIG_COMPUTER)));
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![ok(&padded)])).0)?;
    assert_eq!(counts.forged, 0);
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(FIRST));
    Ok(())
}


#[test]
fn a_padded_data_value_is_cut_visibly_and_still_gives_an_event() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let data = format!(
        "<Data Name='UtcTime'>2026-11-03 10:00:00.123</Data><Data Name='CommandLine'>{}</Data>",
        "a&quot;".repeat(PAD)
    );
    let text = event("sysmon", 1, FIRST, &data);
    let counts = totals(run_poll(&lab, &SYSMON, &mut state, script(FIRST, vec![ok(&text)])).0)?;
    assert_eq!(counts.spooled, 1);
    assert!(spool_lines(&lab)?.iter().all(|line| line.contains("cut,")));
    Ok(())
}


#[test]
fn a_cut_event_still_over_the_event_limit_is_refused_with_a_stub() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let data: String = (0..FIELDS)
        .map(|i| format!("<Data Name='F{i}'>{}</Data>", "b".repeat(FIELD_PAD)))
        .collect();
    let text = event("sysmon", 1, FIRST, &data);
    let counts = totals(run_poll(&lab, &SYSMON, &mut state, script(FIRST, vec![ok(&text)])).0)?;
    assert_eq!((counts.spooled, counts.oversized), (0, 1));
    assert!(spool_lines(&lab)?.iter().all(|line| line.contains("agent.event_refused")));
    Ok(())
}


#[test]
fn an_ecs_line_over_the_line_limit_is_refused_with_a_stub() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let scripted = script(FIRST, vec![ok(&security(FIRST))]);
    let counts = totals(run_poll_with(&lab, &SECURITY, &mut state, scripted, (to_json, SMALL_LINE_LIMIT)).0)?;
    assert_eq!((counts.spooled, counts.oversized), (0, 1));
    assert!(spool_lines(&lab)?.iter().all(|line| line.contains("agent.event_refused")));
    Ok(())
}


#[test]
fn malformed_items_leave_stubs_and_advance() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let bad_xml = event("sysmon", 1, FIRST, "<Data Name='a' Name='b'>v</Data>");
    let nested = format!("<Event><System><EventRecordID>{SECOND}</EventRecordID></System><Event></Event>");
    let text = format!("{bad_xml}{nested}{}", sysmon(THIRD));
    let counts = totals(run_poll(&lab, &SYSMON, &mut state, script(THIRD, vec![ok(&text)])).0)?;
    assert_eq!((counts.malformed, counts.spooled), (PAIR, 1));
    let lines = spool_lines(&lab)?;
    assert_eq!(lines.iter().filter(|line| line.contains("agent.event_refused")).count(), TWO_LINES);
    assert_eq!(cursor_text(&lab, &SYSMON), expected_cursor(THIRD));
    Ok(())
}


#[test]
fn an_encoder_failure_is_a_malformed_stub() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let scripted = script(FIRST, vec![ok(&security(FIRST))]);
    let counts = totals(run_poll_with(&lab, &SECURITY, &mut state, scripted, (failing_encode, LINE_LIMIT)).0)?;
    assert_eq!((counts.spooled, counts.malformed), (0, 1));
    assert!(spool_lines(&lab)?
        .iter()
        .all(|line| line.contains("agent.event_refused") && line.contains("malformed")));
    Ok(())
}


#[test]
fn a_malformed_security_item_leaves_a_stub() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let text = event("security", EVENT_LOGON_FAILED, FIRST, "<Data Name='a' Name='b'>v</Data>");
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![ok(&text)])).0)?;
    assert_eq!((counts.spooled, counts.malformed), (0, 1));
    Ok(())
}


#[test]
fn a_forward_jump_from_the_cursor_is_a_hole_line() -> TestResult {
    let lab = lab()?;
    set_cursor(&lab, &SECURITY, FIRST)?;
    let mut state = ChannelState::default();
    let counts = totals(
        run_poll(
            &lab,
            &SECURITY,
            &mut state,
            script(FIFTH + 1, vec![ok(&format!("{}{}", security(FIFTH), security(FIFTH + 1)))]),
        )
        .0,
    )?;
    assert_eq!((counts.holes, counts.spooled), (1, PAIR));
    let lines = spool_lines(&lab)?;
    assert!(lines
        .first()
        .is_some_and(|line| line.contains("\"reason\":\"hole\"") && line.contains("\"first_missing\":11") && line.contains("\"count\":3")));
    Ok(())
}


#[test]
fn a_gap_inside_a_batch_is_a_forged_batch_and_nothing_of_it_is_spooled() -> TestResult {
    let lab = lab()?;
    set_cursor(&lab, &SECURITY, FIRST)?;
    let mut state = ChannelState::default();
    let first_batch = ok(&format!("{}{}", security(SECOND), security(FOURTH)));
    let scripted = script(FIFTH, vec![first_batch, ok(&security(SECOND))]);
    let (result, requests) = run_poll(&lab, &SECURITY, &mut state, scripted);
    let counts = totals(result)?;
    assert_eq!((counts.forged, counts.spooled), (1, 1));
    let lines = spool_lines(&lab)?;
    assert_eq!(lines.len(), TWO_LINES);
    assert!(lines
        .first()
        .is_some_and(|line| line.contains("\"reason\":\"forged\"") && line.contains("\"first_id\":11") && line.contains("\"breaking_id\":13")));
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(SECOND));
    let counts_sent: Vec<Option<String>> = main_queries(&requests).iter().map(|args| count_arg(args)).collect();
    assert_eq!(counts_sent, vec![Some("/c:500".to_string()), Some("/c:1".to_string())]);
    assert_eq!(state.batch, DOUBLED_BATCH);
    Ok(())
}


#[test]
fn a_forged_next_id_followed_by_the_real_one_is_isolated_at_one_event() -> TestResult {
    let lab = lab()?;
    set_cursor(&lab, &SECURITY, FIRST)?;
    let mut state = ChannelState::default();
    let batch = ok(&format!("{}{}", security(SECOND), security(SECOND)));
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, script(SECOND, vec![batch, ok(&security(SECOND))])).0)?;
    assert_eq!((counts.forged, counts.spooled), (1, 1));
    let lines = spool_lines(&lab)?;
    assert!(lines.get(1).is_some_and(|line| line.contains("authentication")));
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(SECOND));
    Ok(())
}


#[test]
fn every_batch_integrity_check_refuses_the_batch() -> TestResult {
    let above_newest = ok(&security(FIFTH));
    let below_cursor = ok(&security(FIRST));
    let no_id = ok("<Event><System><EventID>4625</EventID></System></Event>");
    let too_many = ok(&format!("{}{}{}", security(SECOND), security(THIRD), security(FOURTH)));
    let cases = [
        (above_newest, THIRD, 1),
        (below_cursor, THIRD, 1),
        (no_id, THIRD, 1),
        (too_many, FIFTH, TWO_LIMIT),
    ];
    cases.into_iter().try_for_each(|(batch, newest, limit)| -> TestResult {
        let lab = lab()?;
        set_cursor(&lab, &SECURITY, FIRST)?;
        let mut state = ChannelState {
            batch: if limit == 1 { MAX_EVENTS_PER_POLL } else { limit },
            absent_logged: false,
        };
        let scripted = script(newest, vec![batch, ok("")]);
        let counts = totals(run_poll(&lab, &SECURITY, &mut state, scripted).0)?;
        assert!(counts.forged >= 1, "{counts:?}");
        assert_eq!(counts.spooled, 0);
        assert_eq!(cursor_text(&lab, &SECURITY), Some(format!("{FIRST} {TIME}\n")));
        assert!(spool_lines(&lab)?.first().is_some_and(|line| line.contains("\"reason\":\"forged\"")));
        Ok(())
    })
}


#[test]
fn at_one_event_extra_items_make_the_first_a_forged_stub_and_the_cursor_follows_it() -> TestResult {
    let lab = lab()?;
    set_cursor(&lab, &SECURITY, FIRST)?;
    let mut state = ChannelState {
        batch: SINGLE,
        absent_logged: false,
    };
    let batch = ok(&format!("{}{}{}", security(FIFTH), security(FIFTH + 1), security(FIFTH + PAIR)));
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, script(FAR, vec![batch])).0)?;
    assert_eq!(counts.forged, THREE as u64);
    let lines = spool_lines(&lab)?;
    assert_eq!(lines.len(), TWO_LINES);
    assert!(lines.first().is_some_and(|line| line.contains("\"reason\":\"hole\"")));
    assert!(lines
        .get(1)
        .is_some_and(|line| line.contains("agent.event_refused") && line.contains("forged") && line.contains("\"record_id\":14")));
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(FIFTH));
    Ok(())
}


#[test]
fn an_invalid_cursor_gives_one_gap_line_and_resumes_at_the_start() -> TestResult {
    let bad_cursors: [&[u8]; BAD_CURSORS] = [
        b"abc",
        b"007 2026-11-03T10:00:00Z",
        b"5",
        b"-5 x",
        b"9223372036854775808 2026-11-03T10:00:00Z",
        &LONE_BOM_BYTES,
    ];
    bad_cursors.iter().try_for_each(|content| -> TestResult {
        let lab = lab()?;
        fs::write(state_dir(&lab).join(SECURITY.cursor_file), content)?;
        let mut state = ChannelState::default();
        let (result, requests) = run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![ok(&security(FIRST))]));
        let counts = totals(result)?;
        assert_eq!((counts.cursor_invalid, counts.spooled), (1, 1));
        assert!(spool_lines(&lab)?.first().is_some_and(|line| line.contains("cursor_invalid")));
        assert_eq!(main_queries(&requests).first().and_then(|args| query_arg(args)), bounded(0, FIRST));
        Ok(())
    })
}


#[test]
fn a_cursor_over_its_cap_is_invalid_and_one_without_a_newline_is_valid() -> TestResult {
    let lab = lab()?;
    fs::write(state_dir(&lab).join(SECURITY.cursor_file), format!("{FIRST} {}", "a".repeat(WIDE_CURSOR)))?;
    let mut state = ChannelState::default();
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![])).0)?;
    assert_eq!(counts.cursor_invalid, 1);
    let other = self::lab()?;
    fs::write(state_dir(&other).join(SECURITY.cursor_file), format!("{FIRST} {TIME}"))?;
    let (result, requests) = run_poll(&other, &SECURITY, &mut state, script(SECOND, vec![]));
    assert_eq!(totals(result)?.cursor_invalid, 0);
    assert_eq!(main_queries(&requests).first().and_then(|args| query_arg(args)), bounded(FIRST, SECOND));
    Ok(())
}


#[test]
fn a_cursor_above_the_newest_record_is_one_loud_gap_and_a_replay() -> TestResult {
    let lab = lab()?;
    set_cursor(&lab, &SECURITY, FAR)?;
    let mut state = ChannelState::default();
    let (result, requests) = run_poll(
        &lab,
        &SECURITY,
        &mut state,
        script(SECOND, vec![ok(&format!("{}{}", security(1), security(PAIR)))]),
    );
    let counts = totals(result)?;
    assert_eq!((counts.cursor_ahead, counts.spooled), (1, PAIR));
    assert!(spool_lines(&lab)?.first().is_some_and(|line| line.contains("cursor_ahead")));
    assert_eq!(main_queries(&requests).first().and_then(|args| query_arg(args)), bounded(0, SECOND));
    assert_eq!(cursor_text(&lab, &SECURITY), Some(format!("2 {TIME}\n")));
    Ok(())
}


#[test]
fn an_unreadable_cursor_is_an_error() -> TestResult {
    let lab = lab()?;
    fs::create_dir_all(state_dir(&lab).join(SECURITY.cursor_file))?;
    let mut state = ChannelState::default();
    let (result, _) = run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![]));
    assert!(matches!(result, Err(PollError::CursorRead(_))));
    Ok(())
}


#[test]
fn a_cursor_that_cannot_be_written_is_an_error() -> TestResult {
    let lab = lab()?;
    fs::remove_dir_all(state_dir(&lab))?;
    let mut state = ChannelState::default();
    let (result, _) = run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![ok(&security(FIRST))]));
    assert!(matches!(result, Err(PollError::Cursor(_))));
    Ok(())
}


#[test]
fn a_spool_that_cannot_be_written_leaves_the_cursor_alone() -> TestResult {
    let lab = lab()?;
    fs::create_dir_all(spool_path(&lab))?;
    let mut state = ChannelState::default();
    let (result, _) = run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![ok(&security(FIRST))]));
    assert!(matches!(result, Err(PollError::Spool(_))));
    assert_eq!(cursor_text(&lab, &SECURITY), None);
    Ok(())
}


#[test]
fn a_runner_error_is_propagated_from_both_queries() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let failing = Reply {
        chunks: Vec::new(),
        end: Err(()),
    };
    let on_newest = Script {
        newest: failing.clone(),
        main: VecDeque::new(),
    };
    let (first, _) = run_poll(&lab, &SECURITY, &mut state, on_newest);
    assert!(matches!(first, Err(PollError::Run(RunError::Reader))));
    let (second, _) = run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![failing]));
    assert!(matches!(second, Err(PollError::Run(RunError::Reader))));
    Ok(())
}


#[test]
fn a_missing_channel_is_named_once_and_does_not_stop_the_other() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let absent = || Script {
        newest: broken(RunEnd::Failed(Some(CHANNEL_NOT_FOUND_EXIT))),
        main: VecDeque::new(),
    };
    assert_eq!(totals(run_poll(&lab, &SYSMON, &mut state, absent()).0)?.channel_absent, 1);
    assert!(state.absent_logged);
    assert_eq!(totals(run_poll(&lab, &SYSMON, &mut state, absent()).0)?.channel_absent, 1);
    let mut other = ChannelState::default();
    let counts = totals(run_poll(&lab, &SECURITY, &mut other, script(FIRST, vec![ok(&security(FIRST))])).0)?;
    assert_eq!(counts.spooled, 1);
    totals(run_poll(&lab, &SYSMON, &mut state, script(FIRST, vec![])).0)?;
    assert!(!state.absent_logged);
    let main_absent = script(FIRST, vec![broken(RunEnd::Failed(Some(CHANNEL_NOT_FOUND_EXIT)))]);
    assert_eq!(totals(run_poll(&lab, &SYSMON, &mut state, main_absent).0)?.channel_absent, 1);
    Ok(())
}


#[test]
fn a_failed_query_is_counted_and_keeps_the_cursor() -> TestResult {
    let failures = [RunEnd::Failed(Some(FAILED_EXIT)), RunEnd::Failed(None)];
    failures.iter().try_for_each(|end| -> TestResult {
        let lab = lab()?;
        let mut state = ChannelState::default();
        let main_fails = script(FIRST, vec![reply(&security(FIRST), *end)]);
        let counts = totals(run_poll(&lab, &SECURITY, &mut state, main_fails).0)?;
        assert_eq!((counts.query_failed, counts.channel_absent), (1, 0));
        let newest_fails = Script {
            newest: reply(&security(FIRST), *end),
            main: VecDeque::new(),
        };
        assert_eq!(totals(run_poll(&lab, &SECURITY, &mut state, newest_fails).0)?.query_failed, 1);
        assert!(spool_lines(&lab)?.is_empty());
        assert_eq!(cursor_text(&lab, &SECURITY), None);
        Ok(())
    })
}


#[test]
fn a_bad_newest_answer_is_a_failed_query_and_an_empty_channel_skips_the_main_query() -> TestResult {
    let lab = lab()?;
    let half = security(FIRST);
    let torn = half.split_at(half.len() / HALVES).0;
    let no_id = "<Event><System><EventID>1</EventID></System></Event>";
    let bad = [
        ok(torn),
        ok(no_id),
        reply(&security(FIRST), RunEnd::Capped),
        reply(&security(FIRST), RunEnd::Deadline),
    ];
    bad.into_iter().try_for_each(|newest| -> TestResult {
        let mut state = ChannelState::default();
        let scripted = Script {
            newest,
            main: VecDeque::new(),
        };
        let (result, requests) = run_poll(&lab, &SECURITY, &mut state, scripted);
        assert_eq!(totals(result)?.query_failed, 1);
        assert_eq!(requests.len(), 1);
        Ok(())
    })?;
    let mut state = ChannelState::default();
    let empty = Script {
        newest: ok(""),
        main: VecDeque::new(),
    };
    let (result, requests) = run_poll(&lab, &SECURITY, &mut state, empty);
    assert_eq!(totals(result)?, PollTotals::default());
    assert_eq!(requests.len(), 1);
    Ok(())
}


#[test]
fn a_newest_answer_with_extra_items_is_counted_forged_and_still_used() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let scripted = Script {
        newest: ok(&format!("{}{}", security(FIRST), security(FIFTH))),
        main: VecDeque::from(vec![ok(&security(FIRST))]),
    };
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, scripted).0)?;
    assert_eq!((counts.forged, counts.spooled), (1, 1));
    Ok(())
}


#[test]
fn an_output_over_the_cap_keeps_the_complete_items_and_moves_the_cursor() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let partial = security(SECOND);
    let text = format!("{}{}", security(FIRST), partial.split_at(partial.len() / HALVES).0);
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, script(SECOND, vec![reply(&text, RunEnd::Capped)])).0)?;
    assert_eq!((counts.spooled, counts.output_capped, counts.batch_halved), (1, 1, 0));
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(FIRST));
    assert_eq!(state.batch, MAX_EVENTS_PER_POLL);
    Ok(())
}


#[test]
fn a_deadline_keeps_the_complete_items_and_is_named() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let counts = totals(
        run_poll(
            &lab,
            &SECURITY,
            &mut state,
            script(FIRST, vec![reply(&security(FIRST), RunEnd::Deadline)]),
        )
        .0,
    )?;
    assert_eq!((counts.spooled, counts.deadline), (1, 1));
    Ok(())
}


#[test]
fn nothing_complete_halves_the_batch_down_to_one_then_the_item_is_a_stub() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let partial = security(FIRST);
    let head = partial.split_at(partial.find("<EventData>").unwrap_or(0)).0.to_string();
    let capped = || script(FIRST, vec![reply(&head, RunEnd::Capped)]);
    let (first, requests) = run_poll(&lab, &SECURITY, &mut state, capped());
    assert_eq!((totals(first)?.batch_halved, state.batch), (1, HALF));
    assert_eq!(
        main_queries(&requests).first().and_then(|args| count_arg(args)),
        Some("/c:500".to_string())
    );
    let (second, _) = run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![reply(&head, RunEnd::Deadline)]));
    assert_eq!((totals(second)?.deadline, state.batch), (1, QUARTER));
    assert_eq!(cursor_text(&lab, &SECURITY), None);
    state.batch = THREE;
    totals(run_poll(&lab, &SECURITY, &mut state, capped()).0)?;
    assert_eq!(state.batch, 1);
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, capped()).0)?;
    assert_eq!((counts.oversized, counts.batch_halved), (1, 0));
    assert!(spool_lines(&lab)?.iter().all(|line| line.contains("agent.event_refused")));
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(FIRST));
    totals(run_poll(&lab, &SECURITY, &mut state, script(SECOND, vec![ok("")])).0)?;
    assert_eq!(state.batch, DOUBLED_BATCH);
    Ok(())
}


#[test]
fn a_single_event_cap_with_no_partial_item_is_only_named() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState {
        batch: 1,
        absent_logged: false,
    };
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![broken(RunEnd::Capped)])).0)?;
    assert_eq!((counts.output_capped, counts.oversized, counts.batch_halved), (1, 0, 0));
    Ok(())
}


#[test]
fn fullwidth_markup_in_a_value_stays_inside_the_real_event() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let forged = format!(
        "x\u{ff1c}/Data\u{ff1e}\u{ff1c}/EventData\u{ff1e}\u{ff1c}/Event\u{ff1e}\u{ff1c}Event\u{ff1e}\u{ff1c}EventRecordID\u{ff1e}{HUGE_ID}\u{ff1c}/EventRecordID\u{ff1e}\u{ff06}"
    );
    let data = format!("<Data Name='UtcTime'>2026-11-03 10:00:00.123</Data><Data Name='CommandLine'>{forged}</Data>");
    let text = format!("{}{}", event("sysmon", 1, FIRST, &data), sysmon(SECOND));
    let (result, _) = run_poll(&lab, &SYSMON, &mut state, script(SECOND, vec![ok(&text)]));
    let counts = totals(result)?;
    assert_eq!((counts.spooled, counts.forged, counts.malformed), (PAIR, 0, 0));
    let lines = spool_lines(&lab)?;
    assert_eq!(lines.len(), TWO_LINES);
    assert!(lines.first().is_some_and(|line| line.contains("\u{ff1c}/Event\u{ff1e}")));
    assert_eq!(cursor_text(&lab, &SYSMON), expected_cursor(SECOND));
    Ok(())
}


#[test]
fn a_lone_surrogate_is_replaced_the_event_is_spooled_whole_and_counted() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let text = event(
        "sysmon",
        1,
        FIRST,
        "<Data Name='UtcTime'>2026-11-03 10:00:00.123</Data><Data Name='CommandLine'>a\u{1}b\u{1b}c</Data>",
    );
    let (before, after) = text.split_once("b\u{1b}").unwrap_or(("", ""));
    let units: Vec<u8> = wide(before)
        .into_iter()
        .chain(LONE_HIGH_BYTES)
        .chain(wide(&format!("b\u{1b}{after}")).into_iter().skip(BOM_BYTES.len()))
        .collect();
    let served = Reply {
        chunks: vec![units],
        end: Ok(RunEnd::Done),
    };
    let counts = totals(run_poll(&lab, &SYSMON, &mut state, script(FIRST, vec![served])).0)?;
    assert_eq!((counts.spooled, counts.malformed), (1, 0));
    assert!(counts.utf16_replaced >= REPLACED_TWO);
    assert!(spool_lines(&lab)?.iter().all(|line| line.contains("agent.utf16_replaced")));
    Ok(())
}


#[test]
fn an_odd_trailing_byte_is_one_stream_gap_and_the_complete_items_are_kept() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let mut bytes = wide(&security(FIRST));
    bytes.push(b'x');
    let served = Reply {
        chunks: vec![bytes],
        end: Ok(RunEnd::Done),
    };
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, script(FIRST, vec![served])).0)?;
    assert_eq!((counts.utf16, counts.spooled), (1, 1));
    assert!(spool_lines(&lab)?.first().is_some_and(|line| line.contains("\"reason\":\"utf16\"")));
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(FIRST));
    Ok(())
}
