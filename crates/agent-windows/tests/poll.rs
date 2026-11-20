#[path = "common/types.rs"]
mod types;


use agent_windows::error::{PollError, RunError};
use agent_windows::model::{
    Channel, ChannelState, PollEnv, PollTotals, RunEnd, RunRequest, CHANNEL_NOT_FOUND_EXIT, MAX_EVENTS_PER_POLL, MAX_ITEM_BYTES, SECURITY, SYSMON,
    WEVTUTIL_PATH,
};
use agent_windows::poll::{poll_channel, query_args};
use agent_windows::types::EncodeFn;
use core_export::ecs::{to_json, EcsEvent};
use core_export::error::ExportError;
use ecs_normalise::types::SeenIds;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tempfile::TempDir;
use types::TestResult;


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


const NO_ID: &str = "<Event><System><EventID>4625</EventID></System></Event>";


const HALF: u32 = 250;


const QUARTER: u32 = 125;


const THREE: u32 = 3;


const PAD: usize = 20_000;


const FIELD_PAD: usize = 8_000;


const FIELDS: usize = 10;


const PAIR: u64 = 2;


const TWO_LINES: usize = 2;


const THREE_LINES: usize = 3;


const BAD_CURSOR_COUNT: usize = 6;


const EVENT_LOGON_FAILED: u32 = 4625;


const EVENT_UNKNOWN_SYSMON: u32 = 99;


const EVENT_UNKNOWN_SECURITY: u32 = 9999;


const QUERY_INDEX: usize = 2;


const COUNT_INDEX: usize = 3;


const HALVES: usize = 2;


const DOUBLED_BATCH: u32 = 2;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const CODE_PAGE_BYTE: u8 = 0xae;


const FIRST: u64 = 10;


const SECOND: u64 = 11;


const THIRD: u64 = 12;


const FIFTH: u64 = 14;


const SEVENTH: u64 = 16;


const QUERY_ZERO: &str = "/q:*[System[(EventRecordID>0)]]";


const FAILED_EXIT: i32 = 1;


const WIDE_CURSOR: usize = 200;


pub struct Script {
    pub chunks: Vec<Vec<u8>>,
    pub end: Result<RunEnd, ()>,
}


pub struct Seen {
    pub programs: Vec<String>,
    pub args: Vec<Vec<String>>,
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


fn done(text: &str) -> Script {
    ending(text.as_bytes(), RunEnd::Done)
}


fn ending(text: &[u8], end: RunEnd) -> Script {
    Script {
        chunks: vec![text.to_vec()],
        end: Ok(end),
    }
}


struct Lab {
    dir: TempDir,
}


fn lab() -> Result<Lab, Box<dyn Error>> {
    Ok(Lab { dir: tempfile::tempdir()? })
}


fn state_dir(lab: &Lab) -> PathBuf {
    lab.dir.path().join("state")
}


fn spool_path(lab: &Lab) -> PathBuf {
    lab.dir.path().join("spool")
}


fn prepare(lab: &Lab) -> TestResult {
    Ok(fs::create_dir_all(state_dir(lab))?)
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


fn query_of(seen: &Seen) -> Option<String> {
    seen.args.first().and_then(|args| args.get(QUERY_INDEX).cloned())
}


fn query_after(record: u64) -> Option<String> {
    Some(format!("/q:*[System[(EventRecordID>{record})]]"))
}


fn run_poll(lab: &Lab, channel: &Channel, state: &mut ChannelState, script: Script, line_limit: usize) -> (Result<PollTotals, PollError>, Seen) {
    run_poll_in(&state_dir(lab), &spool_path(lab), channel, state, (script, to_json), line_limit)
}


fn failing_encode(_event: &EcsEvent) -> Result<String, ExportError> {
    Err(ExportError::Io {
        context: "test".to_string(),
        source: std::io::Error::from(std::io::ErrorKind::Other),
    })
}


fn run_poll_in(
    state_dir: &Path,
    spool: &Path,
    channel: &Channel,
    state: &mut ChannelState,
    scripted: (Script, EncodeFn),
    line_limit: usize,
) -> (Result<PollTotals, PollError>, Seen) {
    LazyLock::force(&LOGGING);
    let (script, encode) = scripted;
    let mut seen_requests = Seen {
        programs: Vec::new(),
        args: Vec::new(),
    };
    let mut run = |request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])| -> Result<RunEnd, RunError> {
        seen_requests.programs.push(request.program.to_string());
        seen_requests.args.push(request.args.to_vec());
        script.chunks.iter().for_each(|chunk| sink(chunk));
        script.end.map_err(|()| RunError::Reader)
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
    (result, seen_requests)
}


fn totals(result: Result<PollTotals, PollError>) -> Result<PollTotals, Box<dyn Error>> {
    Ok(result?)
}


#[test]
fn two_events_are_spooled_and_the_cursor_follows() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let text = format!("{}{}", security(FIRST), security(SECOND));
    let mut state = ChannelState::default();
    let (result, seen) = run_poll(&lab, &SECURITY, &mut state, done(&text), LINE_LIMIT);
    let counts = totals(result)?;
    assert_eq!(counts.spooled, PAIR);
    let lines = spool_lines(&lab)?;
    assert_eq!(lines.len(), TWO_LINES);
    assert!(lines.iter().all(|line| line.contains("authentication")));
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(SECOND));
    assert_eq!(seen.programs, vec![WEVTUTIL_PATH.to_string()]);
    assert_eq!(query_of(&seen), Some(QUERY_ZERO.to_string()));
    Ok(())
}


#[test]
fn a_second_poll_reads_after_the_cursor_and_an_empty_result_changes_nothing() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    totals(run_poll(&lab, &SECURITY, &mut state, done(&security(FIRST)), LINE_LIMIT).0)?;
    let (result, seen) = run_poll(&lab, &SECURITY, &mut state, done(""), LINE_LIMIT);
    assert_eq!(totals(result)?, PollTotals::default());
    assert_eq!(spool_lines(&lab)?.len(), 1);
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(FIRST));
    assert_eq!(query_of(&seen), query_after(FIRST));
    Ok(())
}


#[test]
fn the_query_for_the_largest_id_is_formatted_by_the_code() -> TestResult {
    let args = query_args(&SYSMON, u64::MAX, MAX_EVENTS_PER_POLL);
    assert_eq!(
        args,
        vec![
            "qe".to_string(),
            "Microsoft-Windows-Sysmon/Operational".to_string(),
            "/q:*[System[(EventRecordID>18446744073709551615)]]".to_string(),
            "/c:500".to_string(),
            "/rd:false".to_string(),
            "/f:xml".to_string(),
        ]
    );
    Ok(())
}


#[test]
fn the_runner_only_gets_the_const_program_and_no_shell_words() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let (_, sysmon_seen) = run_poll(&lab, &SYSMON, &mut state, done(""), LINE_LIMIT);
    let (_, security_seen) = run_poll(&lab, &SECURITY, &mut state, done(""), LINE_LIMIT);
    [sysmon_seen, security_seen].iter().for_each(|seen| {
        assert_eq!(seen.programs, vec![WEVTUTIL_PATH.to_string()]);
        let all = seen
            .args
            .iter()
            .flatten()
            .map(|arg| arg.to_ascii_lowercase())
            .collect::<Vec<String>>()
            .join(" ");
        assert!(!all.contains("powershell") && !all.contains("cmd") && !all.contains("-c "));
    });
    Ok(())
}


#[test]
fn a_sysmon_event_is_spooled_as_a_process_event() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let counts = totals(run_poll(&lab, &SYSMON, &mut state, done(&sysmon(FIRST)), LINE_LIMIT).0)?;
    assert_eq!(counts.spooled, 1);
    assert!(spool_lines(&lab)?.iter().all(|line| line.contains("notepad.exe")));
    Ok(())
}


#[test]
fn an_unknown_sysmon_id_is_spooled_and_counted() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let text = event("sysmon", EVENT_UNKNOWN_SYSMON, FIRST, SYSMON_DATA);
    let counts = totals(run_poll(&lab, &SYSMON, &mut state, done(&text), LINE_LIMIT).0)?;
    assert_eq!((counts.spooled, counts.unknown), (1, 1));
    assert_eq!(cursor_text(&lab, &SYSMON), expected_cursor(FIRST));
    Ok(())
}


#[test]
fn an_unknown_security_id_is_counted_and_the_cursor_advances() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let text = event("security", EVENT_UNKNOWN_SECURITY, FIRST, SECURITY_DATA);
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, done(&text), LINE_LIMIT).0)?;
    assert_eq!((counts.spooled, counts.unknown), (0, 1));
    assert!(spool_lines(&lab)?.is_empty());
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(FIRST));
    Ok(())
}


#[test]
fn an_oversized_item_between_two_good_ones_leaves_a_stub() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let big = event("security", EVENT_LOGON_FAILED, SECOND, &"x".repeat(MAX_ITEM_BYTES + 1));
    let text = format!("{}{big}{}", security(FIRST), security(THIRD));
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, done(&text), LINE_LIMIT).0)?;
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
fn a_padded_data_value_is_cut_visibly_and_still_gives_an_event() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let data = format!(
        "<Data Name='UtcTime'>2026-11-03 10:00:00.123</Data><Data Name='CommandLine'>{}</Data>",
        "a&quot;".repeat(PAD)
    );
    let text = event("sysmon", 1, FIRST, &data);
    let counts = totals(run_poll(&lab, &SYSMON, &mut state, done(&text), LINE_LIMIT).0)?;
    assert_eq!(counts.spooled, 1);
    assert!(spool_lines(&lab)?.iter().all(|line| line.contains("cut,")));
    Ok(())
}


#[test]
fn a_cut_event_still_over_the_event_limit_is_refused_with_a_stub() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let data: String = (0..FIELDS)
        .map(|i| format!("<Data Name='F{i}'>{}</Data>", "b".repeat(FIELD_PAD)))
        .collect();
    let text = event("sysmon", 1, FIRST, &data);
    let counts = totals(run_poll(&lab, &SYSMON, &mut state, done(&text), LINE_LIMIT).0)?;
    assert_eq!((counts.spooled, counts.oversized), (0, 1));
    assert!(spool_lines(&lab)?.iter().all(|line| line.contains("agent.event_refused")));
    Ok(())
}


#[test]
fn an_ecs_line_over_the_line_limit_is_refused_with_a_stub() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, done(&security(FIRST)), SMALL_LINE_LIMIT).0)?;
    assert_eq!((counts.spooled, counts.oversized), (0, 1));
    assert!(spool_lines(&lab)?.iter().all(|line| line.contains("agent.event_refused")));
    Ok(())
}


#[test]
fn malformed_items_leave_stubs_and_advance() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let bad_xml = event("sysmon", 1, FIRST, "<Data Name='a' Name='b'>v</Data>");
    let nested = format!("<Event><System><EventRecordID>{SECOND}</EventRecordID></System>{}", sysmon(THIRD));
    let mut text = format!("{bad_xml}{nested}").into_bytes();
    text.extend_from_slice(event("sysmon", 1, FIFTH, SYSMON_DATA).as_bytes());
    let (result, _) = run_poll(&lab, &SYSMON, &mut state, ending(&text, RunEnd::Done), LINE_LIMIT);
    let counts = totals(result)?;
    assert_eq!((counts.malformed, counts.spooled), (PAIR, 1));
    let lines = spool_lines(&lab)?;
    assert_eq!(lines.iter().filter(|line| line.contains("agent.event_refused")).count(), TWO_LINES);
    assert_eq!(counts.holes, 1);
    assert_eq!(cursor_text(&lab, &SYSMON), expected_cursor(FIFTH));
    Ok(())
}


#[test]
fn an_item_without_a_record_id_stops_the_poll_after_the_earlier_ones() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let text = format!("{}{NO_ID}{}", security(FIRST), security(SECOND));
    let (result, _) = run_poll(&lab, &SECURITY, &mut state, done(&text), LINE_LIMIT);
    assert!(matches!(result, Err(PollError::MissingRecordId)));
    assert_eq!(spool_lines(&lab)?.len(), 1);
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(FIRST));
    Ok(())
}


#[test]
fn ids_out_of_order_stop_the_poll_with_the_cursor_on_the_last_good_one() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let text = format!("{}{}{}", security(SECOND), security(FIRST), security(THIRD));
    let (result, _) = run_poll(&lab, &SECURITY, &mut state, done(&text), LINE_LIMIT);
    assert!(matches!(
        result,
        Err(PollError::OutOfOrder {
            previous: SECOND,
            found: FIRST
        })
    ));
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(SECOND));
    let repeat = format!("{}{}", security(THIRD), security(THIRD));
    let (again, _) = run_poll(&lab, &SECURITY, &mut state, done(&repeat), LINE_LIMIT);
    assert!(matches!(again, Err(PollError::OutOfOrder { .. })));
    Ok(())
}


#[test]
fn a_forward_jump_is_a_hole_line_not_an_error() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    totals(run_poll(&lab, &SECURITY, &mut state, done(&security(FIRST)), LINE_LIMIT).0)?;
    let text = format!("{}{}", security(FIFTH), security(SEVENTH));
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, done(&text), LINE_LIMIT).0)?;
    assert_eq!((counts.spooled, counts.holes), (PAIR, PAIR));
    let lines = spool_lines(&lab)?;
    let holes: Vec<&String> = lines.iter().filter(|line| line.contains("agent.event_gap")).collect();
    assert_eq!(holes.len(), TWO_LINES);
    assert!(holes.first().is_some_and(|line| line.contains("\"reason\":\"hole\"")
        && line.contains("\"first_missing\":11")
        && line.contains("\"last_missing\":13")
        && line.contains("\"count\":3")));
    Ok(())
}


#[test]
fn an_invalid_cursor_gives_one_gap_line_and_resumes_at_the_start() -> TestResult {
    let bad_cursors: [&[u8]; BAD_CURSOR_COUNT] = [
        b"abc",
        b"007 2026-11-03T10:00:00Z",
        b"5",
        b"-5 x",
        b"9223372036854775808 2026-11-03T10:00:00Z",
        &INVALID_UTF8,
    ];
    bad_cursors.iter().try_for_each(|content| -> TestResult {
        let lab = lab()?;
        prepare(&lab)?;
        fs::write(state_dir(&lab).join(SECURITY.cursor_file), content)?;
        let mut state = ChannelState::default();
        let (result, seen) = run_poll(&lab, &SECURITY, &mut state, done(&security(FIRST)), LINE_LIMIT);
        let counts = totals(result)?;
        assert_eq!((counts.cursor_invalid, counts.spooled), (1, 1));
        assert!(spool_lines(&lab)?.first().is_some_and(|line| line.contains("cursor_invalid")));
        assert_eq!(query_of(&seen), Some(QUERY_ZERO.to_string()));
        Ok(())
    })
}


#[test]
fn a_cursor_over_its_cap_is_invalid() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let content = format!("{FIRST} {}", "a".repeat(WIDE_CURSOR));
    fs::write(state_dir(&lab).join(SECURITY.cursor_file), content)?;
    let mut state = ChannelState::default();
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, done(""), LINE_LIMIT).0)?;
    assert_eq!(counts.cursor_invalid, 1);
    Ok(())
}


#[test]
fn a_cursor_without_a_final_newline_is_valid() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    fs::write(state_dir(&lab).join(SECURITY.cursor_file), format!("{FIRST} {TIME}"))?;
    let mut state = ChannelState::default();
    let (result, seen) = run_poll(&lab, &SECURITY, &mut state, done(""), LINE_LIMIT);
    assert_eq!(totals(result)?.cursor_invalid, 0);
    assert_eq!(query_of(&seen), query_after(FIRST));
    Ok(())
}


#[test]
fn an_unreadable_cursor_is_an_error() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    fs::create_dir_all(state_dir(&lab).join(SECURITY.cursor_file))?;
    let mut state = ChannelState::default();
    let (result, _) = run_poll(&lab, &SECURITY, &mut state, done(""), LINE_LIMIT);
    assert!(matches!(result, Err(PollError::CursorRead(_))));
    Ok(())
}


#[test]
fn a_cursor_that_cannot_be_written_is_an_error() -> TestResult {
    let lab = lab()?;
    let mut state = ChannelState::default();
    let (result, _) = run_poll(&lab, &SECURITY, &mut state, done(&security(FIRST)), LINE_LIMIT);
    assert!(matches!(result, Err(PollError::Cursor(_))));
    Ok(())
}


#[test]
fn a_spool_that_cannot_be_written_leaves_the_cursor_alone() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    fs::create_dir_all(spool_path(&lab))?;
    let mut state = ChannelState::default();
    let (result, _) = run_poll(&lab, &SECURITY, &mut state, done(&security(FIRST)), LINE_LIMIT);
    assert!(matches!(result, Err(PollError::Spool(_))));
    assert_eq!(cursor_text(&lab, &SECURITY), None);
    Ok(())
}


#[test]
fn a_runner_error_is_propagated() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let script = Script {
        chunks: Vec::new(),
        end: Err(()),
    };
    let (result, _) = run_poll(&lab, &SECURITY, &mut state, script, LINE_LIMIT);
    assert!(matches!(result, Err(PollError::Run(RunError::Reader))));
    Ok(())
}


#[test]
fn a_missing_channel_is_named_once_and_does_not_stop_the_other() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let (first, _) = run_poll(
        &lab,
        &SYSMON,
        &mut state,
        ending(b"", RunEnd::Failed(Some(CHANNEL_NOT_FOUND_EXIT))),
        LINE_LIMIT,
    );
    assert_eq!(totals(first)?.channel_absent, 1);
    assert!(state.absent_logged);
    let (second, _) = run_poll(
        &lab,
        &SYSMON,
        &mut state,
        ending(b"", RunEnd::Failed(Some(CHANNEL_NOT_FOUND_EXIT))),
        LINE_LIMIT,
    );
    assert_eq!(totals(second)?.channel_absent, 1);
    assert!(state.absent_logged);
    let mut other = ChannelState::default();
    let counts = totals(run_poll(&lab, &SECURITY, &mut other, done(&security(FIRST)), LINE_LIMIT).0)?;
    assert_eq!(counts.spooled, 1);
    let (back, _) = run_poll(&lab, &SYSMON, &mut state, done(""), LINE_LIMIT);
    totals(back)?;
    assert!(!state.absent_logged);
    Ok(())
}


#[test]
fn a_failed_query_is_counted_and_keeps_the_cursor() -> TestResult {
    let failures = [RunEnd::Failed(Some(FAILED_EXIT)), RunEnd::Failed(None)];
    failures.iter().try_for_each(|end| -> TestResult {
        let lab = lab()?;
        prepare(&lab)?;
        let mut state = ChannelState::default();
        let (result, _) = run_poll(&lab, &SECURITY, &mut state, ending(security(FIRST).as_bytes(), *end), LINE_LIMIT);
        let counts = totals(result)?;
        assert_eq!((counts.query_failed, counts.channel_absent), (1, 0));
        assert!(spool_lines(&lab)?.is_empty());
        assert_eq!(cursor_text(&lab, &SECURITY), None);
        Ok(())
    })
}


#[test]
fn an_output_over_the_cap_keeps_the_complete_items_and_moves_the_cursor() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let partial = security(SECOND);
    let text = format!("{}{}", security(FIRST), partial.split_at(partial.len() / HALVES).0);
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, ending(text.as_bytes(), RunEnd::Capped), LINE_LIMIT).0)?;
    assert_eq!((counts.spooled, counts.output_capped, counts.batch_halved), (1, 1, 0));
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(FIRST));
    assert_eq!(state.batch, MAX_EVENTS_PER_POLL);
    Ok(())
}


#[test]
fn a_deadline_keeps_the_complete_items_and_is_named() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let counts = totals(
        run_poll(
            &lab,
            &SECURITY,
            &mut state,
            ending(security(FIRST).as_bytes(), RunEnd::Deadline),
            LINE_LIMIT,
        )
        .0,
    )?;
    assert_eq!((counts.spooled, counts.deadline), (1, 1));
    Ok(())
}


#[test]
fn nothing_complete_halves_the_batch_down_to_one_then_the_item_is_a_stub() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let partial = security(FIRST);
    let head = partial.split_at(partial.find("<EventData>").unwrap_or(0)).0.as_bytes().to_vec();
    let (first, seen) = run_poll(&lab, &SECURITY, &mut state, ending(&head, RunEnd::Capped), LINE_LIMIT);
    assert_eq!((totals(first)?.batch_halved, state.batch), (1, HALF));
    assert_eq!(
        seen.args.first().map(|args| args.get(COUNT_INDEX).cloned()),
        Some(Some("/c:500".to_string()))
    );
    let (second, _) = run_poll(&lab, &SECURITY, &mut state, ending(&head, RunEnd::Deadline), LINE_LIMIT);
    assert_eq!((totals(second)?.deadline, state.batch), (1, QUARTER));
    assert_eq!(cursor_text(&lab, &SECURITY), None);
    state.batch = THREE;
    totals(run_poll(&lab, &SECURITY, &mut state, ending(&head, RunEnd::Capped), LINE_LIMIT).0)?;
    assert_eq!(state.batch, 1);
    let (single, _) = run_poll(&lab, &SECURITY, &mut state, ending(&head, RunEnd::Capped), LINE_LIMIT);
    let counts = totals(single)?;
    assert_eq!((counts.oversized, counts.batch_halved), (1, 0));
    assert!(spool_lines(&lab)?.iter().all(|line| line.contains("agent.event_refused")));
    assert_eq!(cursor_text(&lab, &SECURITY), expected_cursor(FIRST));
    let (good, _) = run_poll(&lab, &SECURITY, &mut state, done(""), LINE_LIMIT);
    totals(good)?;
    assert_eq!(state.batch, DOUBLED_BATCH);
    Ok(())
}


#[test]
fn a_single_event_cap_with_no_partial_item_is_only_named() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState {
        batch: 1,
        absent_logged: false,
    };
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, ending(b"", RunEnd::Capped), LINE_LIMIT).0)?;
    assert_eq!((counts.output_capped, counts.oversized, counts.batch_halved), (1, 0, 0));
    Ok(())
}


#[test]
fn an_encoder_failure_is_a_malformed_stub() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let (result, _) = run_poll_in(
        &state_dir(&lab),
        &spool_path(&lab),
        &SECURITY,
        &mut state,
        (done(&security(FIRST)), failing_encode),
        LINE_LIMIT,
    );
    let counts = totals(result)?;
    assert_eq!((counts.spooled, counts.malformed), (0, 1));
    assert!(spool_lines(&lab)?
        .iter()
        .all(|line| line.contains("agent.event_refused") && line.contains("malformed")));
    Ok(())
}


#[test]
fn a_malformed_security_item_leaves_a_stub() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let text = event("security", EVENT_LOGON_FAILED, FIRST, "<Data Name='a' Name='b'>v</Data>");
    let counts = totals(run_poll(&lab, &SECURITY, &mut state, done(&text), LINE_LIMIT).0)?;
    assert_eq!((counts.spooled, counts.malformed), (0, 1));
    Ok(())
}


#[test]
fn a_code_page_byte_in_a_value_is_replaced_not_refused() -> TestResult {
    let lab = lab()?;
    prepare(&lab)?;
    let mut state = ChannelState::default();
    let data = "<Data Name='UtcTime'>2026-11-03 10:00:00.123</Data><Data Name='Product'>Microsoft\u{0}\u{0} Windows</Data>";
    let text = event("sysmon", 1, FIRST, data).replace("\u{0}\u{0}", "\u{1}");
    let mut bytes = text.into_bytes();
    let at = bytes.iter().position(|byte| *byte == 1).unwrap_or(0);
    bytes.splice(at..=at, [CODE_PAGE_BYTE]);
    let counts = totals(run_poll(&lab, &SYSMON, &mut state, ending(&bytes, RunEnd::Done), LINE_LIMIT).0)?;
    assert_eq!((counts.spooled, counts.malformed), (1, 0));
    assert!(spool_lines(&lab)?.iter().all(|line| line.contains("Microsoft")));
    Ok(())
}
