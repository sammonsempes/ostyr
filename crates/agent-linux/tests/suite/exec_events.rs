use crate::types::TestResult;
use agent_linux::exec_events::{
    add_report, deliver, deliver_or_stop, exec_cap, exec_line, exec_lines, own_loss_text, status_due, status_line, system_offset, timestamp_text,
    Delivery, ExecSink, Losses, DATASET_EXEC, DATASET_STATUS, EXEC_SPOOL_DIVISOR, STATUS_INTERVAL_SECONDS,
};
use agent_linux::model::SourceSettings;
use agent_linux::spool::append_within;
use agent_linux::types::SpoolLock;
use arc_swap::ArcSwap;
use ebpf_probes::drain::{DrainReport, Drained, KernelDropped};
use ebpf_probes::record::ExecRecord;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use tempfile::tempdir;


const OFFSET_NANOS: i128 = 1_700_000_000_000_000_000;


const MAX_SPOOL: u64 = 8000;


const UNPRIVILEGED_UID: u32 = 65534;


const SETUID_REAL_UID: u32 = 1000;


const FAR_FUTURE_NANOS: i128 = 400_000_000_000_000_000_000;


const FAR_PAST_NANOS: i128 = -100_000_000_000_000_000_000;


const OTHER_PRODUCER_BYTES: usize = 3000;


const SECOND_NANOS: u64 = 1_000_000_000;


const RECORDS_PER_STORM: usize = 40;


const PADDING_OVERHEAD: usize = 10;


const FIRST_PID: u32 = 2;


const SECOND_PID: u32 = 3;


const SETUID_PID: u32 = 77;


const LATER_PID: u32 = 10;


const REFUSED_PID: u32 = 5;


const PAIR: u64 = 2;


const HALF: u64 = 2;


const PAIR_LEN: usize = 2;


const TRIPLE_LEN: usize = 3;


const KERNEL_DROPPED: u64 = 5;


const BIG_DROP: u64 = 9;


const LIMITED_FIRST: u64 = 2;


const LIMITED_THIRD: u64 = 3;


const PENDING_LIMITED: u64 = 4;


const LAST_STATUS: u64 = 7;


static NULL: Value = Value::Null;


fn at<'a>(event: &'a Value, pointer: &str) -> &'a Value {
    event.pointer(pointer).unwrap_or(&NULL)
}


fn clock_zero() -> u64 {
    0
}


fn clock_thirty() -> u64 {
    STATUS_INTERVAL_SECONDS / HALF
}


fn clock_sixty() -> u64 {
    STATUS_INTERVAL_SECONDS
}


fn fixed_offset() -> i128 {
    OFFSET_NANOS
}


fn record(pid: u32, uid: u32, comm: &str) -> ExecRecord {
    ExecRecord {
        pid,
        ppid: 1,
        uid,
        gid: uid,
        monotonic_ns: SECOND_NANOS,
        comm: comm.to_owned(),
    }
}


fn report(kernel_dropped: KernelDropped, limited: u64, refused: u64) -> DrainReport {
    DrainReport {
        delivered: 0,
        refused,
        first_refused_len: None,
        limited,
        kernel_dropped,
        more_pending: false,
    }
}


fn drained(records: Vec<ExecRecord>, kernel_dropped: KernelDropped) -> Drained {
    Drained {
        records,
        report: report(kernel_dropped, 0, 0),
    }
}


struct Fixture {
    dir: tempfile::TempDir,
    sink: ExecSink,
}


fn fixture(monotonic: fn() -> u64) -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let sink = ExecSink {
        spool: dir.path().join("spool"),
        sending: dir.path().join("sending"),
        lock: SpoolLock::default(),
        settings: Arc::new(ArcSwap::from_pointee(SourceSettings {
            max_spool_bytes: MAX_SPOOL,
            ..SourceSettings::default()
        })),
        offset: fixed_offset,
        monotonic,
    };
    Ok(Fixture { dir, sink })
}


fn spooled(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    Ok(text.lines().map(serde_json::from_str).collect::<Result<_, _>>()?)
}


fn padding(bytes: usize) -> String {
    format!("{{\"pad\":\"{}\"}}", "y".repeat(bytes.saturating_sub(PADDING_OVERHEAD)))
}


fn status_events(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    Ok(spooled(path)?
        .into_iter()
        .filter(|event| at(event, "/event/dataset") == DATASET_STATUS)
        .collect())
}


#[test]
fn an_exec_record_is_one_event_with_the_real_ids_and_no_identity_of_the_agent() -> TestResult {
    let stamp = timestamp_text(OFFSET_NANOS, SECOND_NANOS).ok_or("no timestamp")?;
    let event: Value = serde_json::from_str(&exec_line(&record(SETUID_PID, SETUID_REAL_UID, "pass\\x5cwd"), &stamp))?;
    assert_eq!(at(&event, "/event/dataset"), DATASET_EXEC);
    assert_eq!(at(&event, "/process/pid"), SETUID_PID);
    assert_eq!(at(&event, "/process/parent/pid"), 1);
    assert_eq!(at(&event, "/process/real_user/id"), "1000");
    assert_eq!(at(&event, "/process/real_group/id"), "1000");
    assert_eq!(at(&event, "/process/name"), "pass\\x5cwd");
    assert_eq!(at(&event, "/@timestamp"), "2023-11-14T22:13:21Z");
    assert!(event.get("user").is_none() && event.get("tenant").is_none() && event.get("agent").is_none());
    assert!(at(&event, "/process").get("user").is_none());
    Ok(())
}


#[test]
fn a_time_outside_rfc_3339_is_refused_and_counted_not_written() -> TestResult {
    assert_eq!(timestamp_text(FAR_FUTURE_NANOS, 0), None);
    assert_eq!(timestamp_text(FAR_PAST_NANOS, 0), None);
    assert_eq!(timestamp_text(i128::MAX, u64::MAX), None);
    let records = vec![record(FIRST_PID, 0, "a"), record(SECOND_PID, 0, "b")];
    let (lines, refused) = exec_lines(&records, FAR_FUTURE_NANOS);
    assert!(lines.is_empty());
    assert_eq!(refused, PAIR);
    let (kept, none_refused) = exec_lines(&records, OFFSET_NANOS);
    assert_eq!((kept.len(), none_refused), (PAIR_LEN, 0));
    Ok(())
}


#[test]
fn the_production_offset_places_a_record_of_now_within_a_year_of_the_wall_clock() -> TestResult {
    let monotonic = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let nanos = u64::try_from(monotonic.tv_sec)? * SECOND_NANOS + u64::try_from(monotonic.tv_nsec)?;
    let stamp = timestamp_text(system_offset(), nanos).ok_or("no timestamp")?;
    assert!(stamp.starts_with("20"), "{stamp}");
    Ok(())
}


#[test]
fn losses_keep_the_counter_faults_apart_from_the_sums() -> TestResult {
    let first = add_report(Losses::default(), &report(KernelDropped::Counted(KERNEL_DROPPED), LIMITED_FIRST, 1));
    let second = add_report(first, &report(KernelDropped::Unknown, 0, 0));
    let third = add_report(second, &report(KernelDropped::CounterWentDown, LIMITED_THIRD, 0));
    assert_eq!(
        third,
        Losses {
            limited: LIMITED_FIRST + LIMITED_THIRD,
            kernel_dropped: KERNEL_DROPPED,
            refused: 1,
            spool_full: 0,
            bad_time: 0,
            counter_unknown: 1,
            counter_went_down: 1,
        }
    );
    let line: Value = serde_json::from_str(&status_line(&third))?;
    let counts = at(&line, "/ostyr/exec_probe");
    assert_eq!(at(&line, "/event/dataset"), DATASET_STATUS);
    assert_eq!(
        (
            at(counts, "/counter_unknown"),
            at(counts, "/counter_went_down"),
            at(counts, "/kernel_dropped")
        ),
        (&1.into(), &1.into(), &KERNEL_DROPPED.into())
    );
    assert_eq!(at(counts, "/limited"), LIMITED_FIRST + LIMITED_THIRD);
    assert_eq!(at(counts, "/refused"), 1);
    assert_eq!(at(counts, "/spool_full"), 0);
    assert_eq!(at(counts, "/bad_time"), 0);
    Ok(())
}


#[test]
fn the_status_is_due_only_with_losses_and_at_most_once_a_minute() -> TestResult {
    let lost = Losses {
        limited: 1,
        ..Losses::default()
    };
    assert!(!status_due(&Losses::default(), None, STATUS_INTERVAL_SECONDS * PAIR));
    assert!(status_due(&lost, None, 0));
    assert!(!status_due(&lost, Some(1), STATUS_INTERVAL_SECONDS));
    assert!(status_due(&lost, Some(1), STATUS_INTERVAL_SECONDS + 1));
    assert_eq!(own_loss_text(0, 0), None);
    assert!(own_loss_text(LIMITED_THIRD, 0).is_some_and(|text| text.contains("spool_full=3")));
    assert!(own_loss_text(0, PAIR).is_some_and(|text| text.contains("bad_time=2")));
    Ok(())
}


#[test]
fn the_cap_is_a_fraction_of_the_source_bound() -> TestResult {
    assert_eq!(exec_cap(MAX_SPOOL), MAX_SPOOL / EXEC_SPOOL_DIVISOR);
    Ok(())
}


#[test]
fn a_delivered_drain_is_spooled_and_a_lost_record_is_never_an_event() -> TestResult {
    let fixture = fixture(clock_zero)?;
    let records = vec![
        record(LATER_PID, UNPRIVILEGED_UID, "true"),
        record(LATER_PID + 1, UNPRIVILEGED_UID, "true"),
    ];
    let state = deliver(&fixture.sink, Delivery::default(), &drained(records, KernelDropped::Counted(BIG_DROP)))?;
    let events = spooled(&fixture.sink.spool)?;
    let exec: Vec<&Value> = events.iter().filter(|event| at(event, "/event/dataset") == DATASET_EXEC).collect();
    assert_eq!(exec.len(), PAIR_LEN);
    assert_eq!(events.len(), TRIPLE_LEN);
    let status = status_events(&fixture.sink.spool)?;
    assert_eq!(status.len(), 1);
    assert_eq!(
        status.first().map(|event| at(event, "/ostyr/exec_probe/kernel_dropped")),
        Some(&BIG_DROP.into())
    );
    assert_eq!(state.losses, Losses::default());
    assert_eq!(state.last_status, Some(0));
    Ok(())
}


#[test]
fn a_status_per_drain_with_losses_but_at_most_one_a_minute() -> TestResult {
    let fixture = fixture(clock_zero)?;
    let lossy = drained(vec![], KernelDropped::Counted(1));
    let first = deliver(&fixture.sink, Delivery::default(), &lossy)?;
    let second = deliver(&fixture.sink, first, &lossy)?;
    assert_eq!(status_events(&fixture.sink.spool)?.len(), 1);
    assert_eq!(second.losses.kernel_dropped, 1);
    let later = ExecSink {
        monotonic: clock_sixty,
        ..fixture.sink.clone()
    };
    let third = deliver(&later, second, &lossy)?;
    let events = status_events(&fixture.sink.spool)?;
    assert_eq!(events.len(), PAIR_LEN);
    assert_eq!(
        events.last().map(|event| at(event, "/ostyr/exec_probe/kernel_dropped")),
        Some(&PAIR.into())
    );
    assert_eq!(third.losses, Losses::default());
    let quiet = deliver(&later, third, &drained(vec![], KernelDropped::Counted(0)))?;
    assert_eq!(status_events(&fixture.sink.spool)?.len(), PAIR_LEN);
    assert_eq!(quiet.losses, Losses::default());
    let halfway = ExecSink {
        monotonic: clock_thirty,
        ..fixture.sink.clone()
    };
    let held = deliver(&halfway, quiet, &lossy)?;
    assert_eq!(status_events(&fixture.sink.spool)?.len(), PAIR_LEN);
    assert_eq!(held.losses.kernel_dropped, 1);
    Ok(())
}


#[test]
fn the_exec_producer_sits_at_its_cap_while_the_other_producers_keep_their_headroom() -> TestResult {
    let fixture = fixture(clock_zero)?;
    let cap = MAX_SPOOL / EXEC_SPOOL_DIVISOR;
    let state = (FIRST_PID..).take(RECORDS_PER_STORM).try_fold(Delivery::default(), |state, pid| {
        deliver(&fixture.sink, state, &drained(vec![record(pid, 0, "storm")], KernelDropped::Counted(0)))
    })?;
    let events = spooled(&fixture.sink.spool)?;
    let exec_bytes: usize = events
        .iter()
        .filter(|event| at(event, "/event/dataset") == DATASET_EXEC)
        .map(|event| event.to_string().len() + 1)
        .sum();
    let size = fs::metadata(&fixture.sink.spool)?.len();
    assert!(
        u64::try_from(exec_bytes)? <= cap,
        "{exec_bytes} exec bytes pending against a cap of {cap}"
    );
    assert!(exec_bytes > 0);
    assert!(state.losses.spool_full > 0);
    let other = vec!["x".repeat(OTHER_PRODUCER_BYTES)];
    assert!(append_within(
        &fixture.sink.lock,
        &fixture.sink.spool,
        &fixture.sink.sending,
        MAX_SPOOL,
        &other
    )?);
    assert!(fs::metadata(&fixture.sink.spool)?.len() > size);
    Ok(())
}


#[test]
fn a_producer_at_its_cap_still_reports_the_refused_batch_in_a_status() -> TestResult {
    let fixture = fixture(clock_zero)?;
    let full = vec![padding(usize::try_from(MAX_SPOOL / EXEC_SPOOL_DIVISOR)?)];
    assert!(append_within(
        &fixture.sink.lock,
        &fixture.sink.spool,
        &fixture.sink.sending,
        MAX_SPOOL,
        &full
    )?);
    let refused = deliver(
        &fixture.sink,
        Delivery::default(),
        &drained(vec![record(REFUSED_PID, 0, "a")], KernelDropped::Counted(0)),
    )?;
    let status = status_events(&fixture.sink.spool)?;
    assert_eq!(status.first().map(|event| at(event, "/ostyr/exec_probe/spool_full")), Some(&1.into()));
    assert_eq!(refused.losses, Losses::default());
    assert_eq!(refused.last_status, Some(0));
    assert!(spooled(&fixture.sink.spool)?
        .iter()
        .all(|event| at(event, "/event/dataset") != DATASET_EXEC));
    Ok(())
}


#[test]
fn a_status_the_whole_bound_refuses_stays_pending_until_there_is_room() -> TestResult {
    let fixture = fixture(clock_zero)?;
    let full = vec![padding(usize::try_from(MAX_SPOOL)?)];
    assert!(append_within(
        &fixture.sink.lock,
        &fixture.sink.spool,
        &fixture.sink.sending,
        MAX_SPOOL * PAIR,
        &full
    )?);
    let refused = deliver(
        &fixture.sink,
        Delivery::default(),
        &drained(vec![record(REFUSED_PID, 0, "a")], KernelDropped::Counted(0)),
    )?;
    assert_eq!(refused.losses.spool_full, 1);
    assert_eq!(refused.last_status, None);
    fs::write(&fixture.sink.spool, "")?;
    let recovered = deliver(&fixture.sink, refused, &drained(vec![], KernelDropped::Counted(0)))?;
    let status = status_events(&fixture.sink.spool)?;
    assert_eq!(status.first().map(|event| at(event, "/ostyr/exec_probe/spool_full")), Some(&1.into()));
    assert_eq!(recovered.losses, Losses::default());
    Ok(())
}


#[test]
fn a_time_refusal_is_counted_in_the_status_and_no_event_is_written() -> TestResult {
    let fixture = fixture(clock_zero)?;
    let far = ExecSink {
        offset: far_offset,
        ..fixture.sink.clone()
    };
    let state = deliver(
        &far,
        Delivery::default(),
        &drained(vec![record(REFUSED_PID, 0, "a")], KernelDropped::Counted(0)),
    )?;
    let events = spooled(&fixture.sink.spool)?;
    assert!(events.iter().all(|event| at(event, "/event/dataset") == DATASET_STATUS));
    assert_eq!(
        status_events(&fixture.sink.spool)?
            .first()
            .map(|event| at(event, "/ostyr/exec_probe/bad_time")),
        Some(&1.into())
    );
    assert_eq!(state.losses, Losses::default());
    Ok(())
}


fn far_offset() -> i128 {
    FAR_FUTURE_NANOS
}


#[test]
fn a_failing_spool_write_stops_the_probe_and_reaches_the_controller() -> TestResult {
    let fixture = fixture(clock_zero)?;
    fs::create_dir(fixture.dir.path().join("blocked"))?;
    let broken = ExecSink {
        spool: fixture.dir.path().join("blocked"),
        ..fixture.sink.clone()
    };
    let batch = drained(vec![record(REFUSED_PID, 0, "a")], KernelDropped::Counted(0));
    assert!(deliver(&broken, Delivery::default(), &batch).is_err());
    let stop = AtomicBool::new(false);
    let (sender, receiver) = channel();
    let kept = Delivery {
        losses: Losses {
            limited: PENDING_LIMITED,
            ..Losses::default()
        },
        last_status: Some(LAST_STATUS),
    };
    let after = deliver_or_stop(&broken, kept.clone(), &batch, &stop, &sender);
    assert_eq!(after, kept);
    assert!(stop.load(Ordering::Relaxed));
    assert_eq!(receiver.try_iter().count(), 1);
    drop(receiver);
    let orphan_stop = AtomicBool::new(false);
    assert_eq!(deliver_or_stop(&broken, kept.clone(), &batch, &orphan_stop, &sender), kept);
    assert!(orphan_stop.load(Ordering::Relaxed));
    Ok(())
}
