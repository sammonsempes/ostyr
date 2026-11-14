mod common;


use common::types::TestResult;
use hunt_packs::due::{due_files, run_due, DueError, USAGE};
use hunt_packs::model::{Baseline, Cost, HuntPack, Source};
use hunt_packs::schedule::{checked_time, due_runs, window_for, RunWindow, ScheduleError, MAX_DUE_RUNS};
use std::fs;
use std::io::{self, Write};
use tempfile::tempdir;


const MIDNIGHT: i64 = 1_641_600_000;


const HOUR: i64 = 3_600;


const HOURLY: u64 = 3_600;


const MIN_SCHEDULE: u64 = 300;


const DAY: i64 = 86_400;


const OUTAGE_DAYS: i64 = 400;


const YEAR_ZERO: i64 = -62_167_219_200;


const SMALL_WINDOW: u64 = 7_200;


const MARGIN: i64 = 10;


const TWO_RUNS: u32 = 2;


const HALF_HOUR: i64 = 1_800;


const AT_05: i64 = MIDNIGHT + 5 * HOUR;


const AT_08: i64 = MIDNIGHT + 8 * HOUR;


const AT_09: i64 = MIDNIGHT + 9 * HOUR;


const AT_10: i64 = MIDNIGHT + 10 * HOUR;


const GRACE: i64 = 600;


fn pack(source: Source, schedule: u64, window: u64) -> HuntPack {
    HuntPack {
        id: "sample".to_string(),
        title: "Sample".to_string(),
        hypothesis: "A sample".to_string(),
        technique: "T1059".to_string(),
        source,
        query: "SELECT 1".to_string(),
        schedule_seconds: schedule,
        window_seconds: window,
        cost: Cost {
            max_rows: 1,
            max_seconds: 1,
            max_bytes_read: None,
        },
        baseline: Baseline { max_matches: 0 },
        tests: Vec::new(),
    }
}


fn hourly() -> HuntPack {
    pack(Source::Clickhouse, HOURLY, SMALL_WINDOW)
}


fn ends(runs: &[RunWindow]) -> Vec<i64> {
    runs.iter().map(|run| run.end).collect()
}


#[test]
fn now_is_aligned_on_the_epoch() -> TestResult {
    let runs = due_runs(&hourly(), None, AT_10 + HALF_HOUR, 0, 1)?;
    let expected = RunWindow { start: AT_08, end: AT_10 };
    assert_eq!(runs, vec![expected]);
    Ok(())
}


#[test]
fn grace_boundary() -> TestResult {
    let end = AT_10;
    assert_eq!(ends(&due_runs(&hourly(), None, end + GRACE, GRACE, 1)?), vec![end]);
    assert_eq!(ends(&due_runs(&hourly(), None, end + GRACE - 1, GRACE, 1)?), vec![end - HOUR]);
    Ok(())
}


#[test]
fn nothing_after_the_latest_done() -> TestResult {
    let end = AT_10;
    assert!(due_runs(&hourly(), Some(end), end + HOUR - 1, 0, MAX_DUE_RUNS)?.is_empty());
    assert_eq!(ends(&due_runs(&hourly(), Some(end), end + HOUR, 0, MAX_DUE_RUNS)?), vec![end + HOUR]);
    assert_eq!(ends(&due_runs(&hourly(), Some(end - 1), end + 1, 0, MAX_DUE_RUNS)?), vec![end]);
    Ok(())
}


#[test]
fn long_outage_is_capped_oldest_first() -> TestResult {
    let step = i64::try_from(MIN_SCHEDULE)?;
    let last = MIDNIGHT;
    let source = pack(Source::Clickhouse, MIN_SCHEDULE, MIN_SCHEDULE);
    let runs = due_runs(&source, Some(last), last + OUTAGE_DAYS * DAY, 0, MAX_DUE_RUNS)?;
    let expected: Vec<i64> = (1..=i64::from(MAX_DUE_RUNS)).map(|index| last + index * step).collect();
    assert_eq!(ends(&runs), expected);
    assert!(runs.iter().all(|run| run.end - run.start == step));
    Ok(())
}


#[test]
fn none_gives_only_the_latest() -> TestResult {
    let runs = due_runs(&hourly(), None, AT_05 + 1, 0, MAX_DUE_RUNS)?;
    assert_eq!(ends(&runs), vec![AT_05]);
    Ok(())
}


#[test]
fn max_runs_zero_gives_nothing() -> TestResult {
    assert!(due_runs(&hourly(), None, MIDNIGHT, 0, 0)?.is_empty());
    Ok(())
}


#[test]
fn osquery_gives_nothing() -> TestResult {
    assert!(due_runs(&pack(Source::Osquery, HOURLY, HOURLY), None, MIDNIGHT, 0, 1)?.is_empty());
    Ok(())
}


#[test]
fn argument_caps() -> TestResult {
    assert!(matches!(
        due_runs(&hourly(), None, MIDNIGHT, 0, MAX_DUE_RUNS + 1),
        Err(ScheduleError::TooManyRuns)
    ));
    assert!(matches!(due_runs(&hourly(), None, MIDNIGHT, -1, 1), Err(ScheduleError::InvalidGrace)));
    assert!(matches!(
        due_runs(&hourly(), None, MIDNIGHT, HOUR + 1, 1),
        Err(ScheduleError::InvalidGrace)
    ));
    assert!(due_runs(&hourly(), None, MIDNIGHT, HOUR, 1).is_ok());
    Ok(())
}


#[test]
fn out_of_range_is_an_error() -> TestResult {
    let zero_schedule = pack(Source::Clickhouse, 0, HOURLY);
    let huge_schedule = pack(Source::Clickhouse, u64::MAX, HOURLY);
    let huge_window = pack(Source::Clickhouse, HOURLY, u64::MAX);
    assert!(matches!(due_runs(&hourly(), None, i64::MAX, 0, TWO_RUNS), Err(ScheduleError::OutOfRange)));
    assert!(matches!(due_runs(&hourly(), None, i64::MIN, 1, 1), Err(ScheduleError::OutOfRange)));
    assert!(matches!(due_runs(&hourly(), None, i64::MIN, 0, 1), Err(ScheduleError::OutOfRange)));
    assert!(matches!(
        due_runs(&hourly(), Some(i64::MAX), i64::MAX, 0, 1),
        Err(ScheduleError::OutOfRange)
    ));
    assert!(matches!(
        due_runs(&hourly(), None, YEAR_ZERO + MARGIN, 0, 1),
        Err(ScheduleError::OutOfRange)
    ));
    assert!(matches!(due_runs(&huge_window, None, MIDNIGHT, 0, 1), Err(ScheduleError::OutOfRange)));
    assert!(matches!(due_runs(&zero_schedule, None, MIDNIGHT, 0, 1), Err(ScheduleError::OutOfRange)));
    assert!(matches!(due_runs(&huge_schedule, None, MIDNIGHT, 0, 1), Err(ScheduleError::OutOfRange)));
    Ok(())
}


#[test]
fn helpers() -> TestResult {
    assert!(checked_time(0).is_ok());
    assert!(checked_time(YEAR_ZERO - 1).is_err());
    assert!(window_for(i64::MIN, 1).is_err());
    assert!(window_for(MIDNIGHT, HOUR).is_ok());
    Ok(())
}


const PACK_FILE: &str = "packs:
  - id: one
    title: One
    hypothesis: H
    technique: T1059
    source: clickhouse
    query: SELECT 1 WHERE {tenant:String} != '' AND {window_start:DateTime64(3)} < {window_end:DateTime64(3)}
    schedule_seconds: 3600
    window_seconds: 7200
    cost: { max_rows: 10, max_seconds: 1, max_bytes_read: 1000 }
    baseline: { max_matches: 1 }
";


struct Refusing;


impl Write for Refusing {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("refused"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn due_cli() -> TestResult {
    let dir = tempdir()?;
    fs::write(dir.path().join("one.yaml"), PACK_FILE)?;
    let path = dir.path().display().to_string();
    let now = (AT_10 + 1).to_string();
    let line = format!("one\t{}\t{}\n", AT_08, AT_10);
    let mut out = Vec::new();
    run_due(&[path.clone(), now.clone()], &mut out)?;
    assert_eq!(String::from_utf8(out)?, line);
    let mut again = Vec::new();
    run_due(&[path.clone(), now.clone(), (AT_09).to_string()], &mut again)?;
    assert_eq!(String::from_utf8(again)?, line);
    assert!(matches!(run_due(std::slice::from_ref(&path), &mut Vec::new()), Err(DueError::Usage)));
    assert!(USAGE.starts_with("usage"));
    assert!(matches!(
        run_due(&[path.clone(), "x".to_string()], &mut Vec::new()),
        Err(DueError::Time(_))
    ));
    assert!(matches!(
        run_due(&[path.clone(), now.clone(), "x".to_string()], &mut Vec::new()),
        Err(DueError::Time(_))
    ));
    assert!(matches!(
        run_due(&["/nonexistent-dir".to_string(), now], &mut Vec::new()),
        Err(DueError::Pack(_))
    ));
    assert!(matches!(due_files(&path, i64::MAX, None, &mut Vec::new()), Err(DueError::Schedule(_))));
    assert!(matches!(due_files(&path, AT_10, None, &mut Refusing), Err(DueError::Write(_))));
    Ok(())
}
