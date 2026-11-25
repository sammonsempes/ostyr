use ebpf_probes::drain::{
    decode_batch, finish_drain, kernel_dropped, may_proceed, poll_loop, report_of, sum_per_cpu, wait_after, warning_text, Batch, Decoder,
    DrainReport, Drained, KernelDropped, EXEC_DECODER, FILE_DECODER, MAX_DRAIN_PER_POLL, POLL_INTERVAL_MILLIS, REASON_UNKNOWN, REASON_WENT_DOWN,
};
use ebpf_probes::limiter::{Limiter, MAX_EXEC_EVENTS_PER_SECOND, NANOS_PER_SECOND};
use ebpf_probes::record::{ExecRecord, EXEC_RECORD_BYTES, FILE_PATH_BYTES, FILE_RECORD_BYTES, FILE_RECORD_KIND};
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;


const EXEC_NAME: &str = "exec";


const RING_RECORDS_PER_INTERVAL: usize = 1365;


const MILLIS_PER_SECOND: u64 = 1000;


const READ_CAP: usize = 3;


const AVAILABLE: u32 = 5;


const SHORT_LENGTH: usize = 7;


const FILL: u8 = 9;


const ANY_CAP: usize = 10;


const REFUSED_TWICE: u64 = 2;


const OVER_BUDGET: u64 = 5;


const FIRST_COUNT: u64 = 10;


const GROWN_COUNT: u64 = 25;


const GROWTH: u64 = 15;


const OLD_BASELINE: u64 = 100;


const RESET_COUNT: u64 = 4;


const AFTER_RESET_COUNT: u64 = 6;


const AFTER_RESET_GROWTH: u64 = 2;


const UNKNOWN_BASELINE: u64 = 7;


const DELIVERED: usize = 3;


const LOST_BY_KERNEL: u64 = 4;


const LOST_BY_LIMIT: u64 = 2;


const REFUSED_RECORDS: u64 = 3;


const FIRST_REFUSED: usize = 9;


const THREE_POLLS: u32 = 3;


const CAP_ONE: usize = 1;


const STOP_AFTER: u32 = 2;


const SECOND_PID: u32 = 2;


fn raw(pid: u32, monotonic_ns: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    [pid, 1, 0, 0].iter().for_each(|word| bytes.extend_from_slice(&word.to_le_bytes()));
    bytes.extend_from_slice(&monotonic_ns.to_le_bytes());
    bytes.extend_from_slice(b"true\0\0\0\0\0\0\0\0\0\0\0\0");
    bytes
}


fn report(kernel: KernelDropped) -> DrainReport {
    DrainReport {
        delivered: DELIVERED,
        refused: 0,
        first_refused_len: None,
        limited: 0,
        kernel_dropped: kernel,
        more_pending: false,
    }
}


#[test]
fn the_sizing_covers_the_limiter_and_the_ring() -> Result<(), Box<dyn Error>> {
    let polls_per_second = MILLIS_PER_SECOND / POLL_INTERVAL_MILLIS;
    let per_second = u64::try_from(MAX_DRAIN_PER_POLL)? * polls_per_second;
    assert!(per_second > u64::from(MAX_EXEC_EVENTS_PER_SECOND));
    assert_eq!(MAX_DRAIN_PER_POLL.cmp(&RING_RECORDS_PER_INTERVAL), std::cmp::Ordering::Greater);
    assert_eq!(MILLIS_PER_SECOND % POLL_INTERVAL_MILLIS, 0);
    Ok(())
}


#[test]
fn a_batch_decodes_in_order_and_reads_at_most_the_cap() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    let mut source = (1..=AVAILABLE).map(|pid| raw(pid, u64::from(pid)));
    let batch = decode_batch(&mut source, &mut limiter, READ_CAP, &EXEC_DECODER);
    let expected: Vec<u32> = (1..=AVAILABLE).take(READ_CAP).collect();
    assert_eq!(batch.records.iter().map(|record| record.pid).collect::<Vec<_>>(), expected);
    assert_eq!(batch.read, READ_CAP);
    assert_eq!(source.count(), usize::try_from(AVAILABLE)? - READ_CAP);
    assert!(report_of(&batch, READ_CAP, KernelDropped::Counted(0)).more_pending);
    assert!(!report_of(&batch, READ_CAP + 1, KernelDropped::Counted(0)).more_pending);
    Ok(())
}


#[test]
fn a_refused_record_is_counted_with_its_length_only() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    let mut source = vec![vec![FILL; SHORT_LENGTH], raw(1, 1), vec![FILL; EXEC_RECORD_BYTES + 1]].into_iter();
    let batch = decode_batch(&mut source, &mut limiter, ANY_CAP, &EXEC_DECODER);
    assert_eq!(batch.refused, REFUSED_TWICE);
    assert_eq!(batch.first_refused_len, Some(SHORT_LENGTH));
    assert_eq!(batch.records.len(), 1);
    Ok(())
}


#[test]
fn the_limiter_runs_on_the_record_kernel_time() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    let allowed = usize::try_from(MAX_EXEC_EVENTS_PER_SECOND)?;
    let over = allowed + usize::try_from(OVER_BUDGET)?;
    let mut same_second = (0..over).map(|pid| raw(pid as u32, 1));
    let first = decode_batch(&mut same_second, &mut limiter, over, &EXEC_DECODER);
    assert_eq!(first.records.len(), allowed);
    assert_eq!(first.limited, OVER_BUDGET);
    assert_eq!(limiter.dropped, 0);
    let mut next_second = vec![raw(1, 1 + NANOS_PER_SECOND)].into_iter();
    let second = decode_batch(&mut next_second, &mut limiter, ANY_CAP, &EXEC_DECODER);
    assert_eq!((second.records.len(), second.limited), (1, 0));
    Ok(())
}


#[test]
fn the_kernel_counter_is_a_delta_against_the_baseline() -> Result<(), Box<dyn Error>> {
    let mut baseline = 0;
    assert_eq!(kernel_dropped(&mut baseline, Some(FIRST_COUNT)), KernelDropped::Counted(FIRST_COUNT));
    assert_eq!(kernel_dropped(&mut baseline, Some(FIRST_COUNT)), KernelDropped::Counted(0));
    assert_eq!(kernel_dropped(&mut baseline, Some(GROWN_COUNT)), KernelDropped::Counted(GROWTH));
    assert_eq!(baseline, GROWN_COUNT);
    Ok(())
}


#[test]
fn an_unreadable_counter_is_unknown_and_never_zero() -> Result<(), Box<dyn Error>> {
    let mut baseline = UNKNOWN_BASELINE;
    assert_eq!(kernel_dropped(&mut baseline, None), KernelDropped::Unknown);
    assert_eq!(baseline, UNKNOWN_BASELINE);
    assert!(warning_text(EXEC_NAME, &report(KernelDropped::Unknown)).is_some());
    Ok(())
}


#[test]
fn a_counter_that_went_down_is_named_and_becomes_the_baseline() -> Result<(), Box<dyn Error>> {
    let mut baseline = OLD_BASELINE;
    assert_eq!(kernel_dropped(&mut baseline, Some(RESET_COUNT)), KernelDropped::CounterWentDown);
    assert_eq!(baseline, RESET_COUNT);
    assert_eq!(
        kernel_dropped(&mut baseline, Some(AFTER_RESET_COUNT)),
        KernelDropped::Counted(AFTER_RESET_GROWTH)
    );
    assert!(warning_text(EXEC_NAME, &report(KernelDropped::CounterWentDown)).is_some());
    Ok(())
}


#[test]
fn a_quiet_drain_has_no_warning() -> Result<(), Box<dyn Error>> {
    assert_eq!(warning_text(EXEC_NAME, &report(KernelDropped::Counted(0))), None);
    Ok(())
}


#[test]
fn every_loss_makes_one_line_of_counts() -> Result<(), Box<dyn Error>> {
    let kernel = warning_text(EXEC_NAME, &report(KernelDropped::Counted(LOST_BY_KERNEL)));
    assert!(
        kernel
            .as_deref()
            .is_some_and(|text| text.contains(&format!("kernel_dropped={LOST_BY_KERNEL}"))),
        "{kernel:?}"
    );
    let limited = warning_text(
        EXEC_NAME,
        &DrainReport {
            limited: LOST_BY_LIMIT,
            ..report(KernelDropped::Counted(0))
        },
    );
    assert!(
        limited.as_deref().is_some_and(|text| text.contains(&format!("limited={LOST_BY_LIMIT}"))),
        "{limited:?}"
    );
    let refused = warning_text(
        EXEC_NAME,
        &DrainReport {
            refused: REFUSED_RECORDS,
            first_refused_len: Some(FIRST_REFUSED),
            ..report(KernelDropped::Counted(0))
        },
    );
    let refused_text = format!("refused={REFUSED_RECORDS} first_refused_len={FIRST_REFUSED}");
    assert!(refused.as_deref().is_some_and(|text| text.contains(&refused_text)), "{refused:?}");
    let unknown = warning_text(EXEC_NAME, &report(KernelDropped::Unknown));
    assert!(
        unknown
            .as_deref()
            .is_some_and(|text| text.contains(REASON_UNKNOWN) && !text.contains('\n')),
        "{unknown:?}"
    );
    let down = warning_text(EXEC_NAME, &report(KernelDropped::CounterWentDown));
    assert!(down.as_deref().is_some_and(|text| text.contains(REASON_WENT_DOWN)), "{down:?}");
    Ok(())
}


#[test]
fn the_wait_is_the_fixed_interval_even_when_more_is_pending() -> Result<(), Box<dyn Error>> {
    let pending = DrainReport {
        more_pending: true,
        ..report(KernelDropped::Counted(0))
    };
    let quiet = report(KernelDropped::Counted(0));
    let interval = Duration::from_millis(POLL_INTERVAL_MILLIS);
    assert_eq!(wait_after(&pending), interval);
    assert_eq!(wait_after(&quiet), interval);
    Ok(())
}


#[test]
fn the_report_copies_the_batch_counts() -> Result<(), Box<dyn Error>> {
    let batch = Batch {
        read: 1,
        refused: REFUSED_RECORDS,
        first_refused_len: Some(FIRST_REFUSED),
        limited: LOST_BY_LIMIT,
        ..Batch::<ExecRecord>::default()
    };
    let made = report_of(&batch, ANY_CAP, KernelDropped::Counted(LOST_BY_KERNEL));
    assert_eq!(
        (made.delivered, made.refused, made.first_refused_len, made.limited),
        (0, REFUSED_RECORDS, Some(FIRST_REFUSED), LOST_BY_LIMIT)
    );
    assert_eq!(made.kernel_dropped, KernelDropped::Counted(LOST_BY_KERNEL));
    Ok(())
}


fn pending_drain() -> Drained {
    Drained {
        records: Vec::new(),
        report: DrainReport {
            more_pending: true,
            ..report(KernelDropped::Counted(0))
        },
    }
}


#[test]
fn every_poll_drains_once_and_waits_the_fixed_interval_even_when_more_is_pending() -> Result<(), Box<dyn Error>> {
    let stop = AtomicBool::new(false);
    let mut drains = 0;
    let mut delivered = 0;
    let mut waits = Vec::new();
    let done = poll_loop(
        &stop,
        THREE_POLLS,
        &mut || {
            drains += 1;
            pending_drain()
        },
        &mut |_| delivered += 1,
        &mut |wait| waits.push(wait),
    );
    let interval = Duration::from_millis(POLL_INTERVAL_MILLIS);
    assert_eq!((done, drains, delivered), (THREE_POLLS, THREE_POLLS, THREE_POLLS));
    assert_eq!(waits, vec![interval; usize::try_from(THREE_POLLS)?]);
    Ok(())
}


#[test]
fn a_stop_flag_ends_the_loop_before_or_between_polls() -> Result<(), Box<dyn Error>> {
    let stopped = AtomicBool::new(true);
    let mut drains = 0;
    let none = poll_loop(
        &stopped,
        THREE_POLLS,
        &mut || {
            drains += 1;
            pending_drain()
        },
        &mut |_| {},
        &mut |_| {},
    );
    assert_eq!((none, drains), (0, 0));
    let stop = AtomicBool::new(false);
    let mut delivered = 0;
    let done = poll_loop(
        &stop,
        THREE_POLLS + STOP_AFTER,
        &mut pending_drain,
        &mut |_| {
            delivered += 1;
            stop.store(delivered >= STOP_AFTER, Ordering::Relaxed);
        },
        &mut |_| {},
    );
    assert_eq!((done, delivered), (STOP_AFTER, STOP_AFTER));
    let capped = poll_loop(&AtomicBool::new(false), 0, &mut pending_drain, &mut |_| {}, &mut |_| {});
    assert_eq!(capped, 0);
    Ok(())
}


#[test]
fn a_finished_drain_carries_the_records_and_at_most_one_warning() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    let mut source = vec![raw(1, 1), raw(SECOND_PID, 1)].into_iter();
    let batch = decode_batch(&mut source, &mut limiter, CAP_ONE, &EXEC_DECODER);
    let mut baseline = 0;
    let (quiet, none) = finish_drain(EXEC_NAME, batch.clone(), CAP_ONE, &mut baseline, Some(0));
    assert_eq!(quiet.records.len(), 1);
    assert!(quiet.report.more_pending);
    assert_eq!(none, None);
    let (unknown, warning) = finish_drain(EXEC_NAME, batch.clone(), CAP_ONE, &mut baseline, None);
    assert_eq!(unknown.report.kernel_dropped, KernelDropped::Unknown);
    assert!(
        warning
            .as_deref()
            .is_some_and(|text| text.contains(REASON_UNKNOWN) && !text.contains('\n')),
        "{warning:?}"
    );
    let (lost, lost_warning) = finish_drain(EXEC_NAME, batch, CAP_ONE, &mut baseline, Some(LOST_BY_KERNEL));
    assert_eq!(lost.report.kernel_dropped, KernelDropped::Counted(LOST_BY_KERNEL));
    assert_eq!(baseline, LOST_BY_KERNEL);
    assert!(lost_warning.is_some());
    Ok(())
}


#[test]
fn the_kernel_dropped_names_print_fixed_text() -> Result<(), Box<dyn Error>> {
    assert_eq!(KernelDropped::Counted(LOST_BY_KERNEL).to_string(), LOST_BY_KERNEL.to_string());
    assert_eq!(KernelDropped::Unknown.to_string(), REASON_UNKNOWN);
    assert_eq!(KernelDropped::CounterWentDown.to_string(), REASON_WENT_DOWN);
    Ok(())
}


#[test]
fn the_per_cpu_drop_counter_is_summed_and_saturates() -> Result<(), Box<dyn Error>> {
    assert_eq!(sum_per_cpu(&[]), 0);
    assert_eq!(
        sum_per_cpu(&[AVAILABLE.into(), SHORT_LENGTH as u64]),
        u64::from(AVAILABLE) + SHORT_LENGTH as u64
    );
    assert_eq!(sum_per_cpu(&[u64::MAX, 1]), u64::MAX);
    Ok(())
}


#[test]
fn a_stop_seen_before_attach_refuses_the_attach() -> Result<(), Box<dyn Error>> {
    let stop = AtomicBool::new(false);
    assert!(may_proceed(&stop));
    stop.store(true, Ordering::Relaxed);
    assert!(!may_proceed(&stop));
    Ok(())
}


const FILE_NAME: &str = "file";


const EXEC_PAIR: usize = 2;


const CUSTOM_BUDGET: u32 = 2;


fn raw_file(pid: u32, monotonic_ns: u64, path: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    [FILE_RECORD_KIND, pid, 0, 1, 0]
        .iter()
        .for_each(|word| bytes.extend_from_slice(&word.to_le_bytes()));
    bytes.extend_from_slice(&monotonic_ns.to_le_bytes());
    let mut field = path.to_vec();
    field.resize(FILE_PATH_BYTES, 0);
    bytes.extend_from_slice(&field);
    bytes
}


#[test]
fn a_file_batch_decodes_with_its_own_decoder_and_refuses_an_exec_record() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    let mut source = vec![raw_file(1, 1, b"/tmp/a"), raw(SECOND_PID, 1), raw_file(SECOND_PID, 1, b"/tmp/b")].into_iter();
    let batch = decode_batch(&mut source, &mut limiter, ANY_CAP, &FILE_DECODER);
    assert_eq!(
        batch.records.iter().map(|record| record.path.as_str()).collect::<Vec<_>>(),
        ["/tmp/a", "/tmp/b"]
    );
    assert_eq!(batch.refused, 1);
    assert_eq!(batch.first_refused_len, Some(EXEC_RECORD_BYTES));
    let mut exec_source = vec![raw_file(1, 1, b"/tmp/a")].into_iter();
    let wrong_way = decode_batch(&mut exec_source, &mut Limiter::default(), ANY_CAP, &EXEC_DECODER);
    assert_eq!(
        (wrong_way.records.len(), wrong_way.refused, wrong_way.first_refused_len),
        (0, 1, Some(FILE_RECORD_BYTES))
    );
    Ok(())
}


#[test]
fn a_write_storm_is_limited_by_the_file_budget_and_never_touches_the_exec_limiter() -> Result<(), Box<dyn Error>> {
    let mut file_limiter = Limiter::default();
    let mut exec_limiter = Limiter::default();
    let budget = usize::try_from(FILE_DECODER.per_second)?;
    let storm = budget + usize::try_from(OVER_BUDGET)?;
    let mut writes = (0..storm).map(|pid| raw_file(pid as u32, 1, b"/tmp/storm"));
    let files = decode_batch(&mut writes, &mut file_limiter, storm, &FILE_DECODER);
    assert_eq!(files.records.len(), budget);
    assert_eq!(files.limited, OVER_BUDGET);
    let mut execs = vec![raw(1, 1), raw(SECOND_PID, 1)].into_iter();
    let exec = decode_batch(&mut execs, &mut exec_limiter, ANY_CAP, &EXEC_DECODER);
    assert_eq!((exec.records.len(), exec.limited), (EXEC_PAIR, 0));
    assert_eq!(exec_limiter.dropped, 0);
    let (_, warning) = finish_drain(FILE_NAME, files, storm, &mut 0, Some(0));
    let expected = format!("file drain lost events: delivered={budget} refused=0 first_refused_len=none limited={OVER_BUDGET}");
    assert!(warning.as_deref().is_some_and(|text| text.starts_with(&expected)), "{warning:?}");
    Ok(())
}


#[test]
fn a_decoder_budget_is_the_one_the_batch_enforces() -> Result<(), Box<dyn Error>> {
    let small = Decoder {
        per_second: CUSTOM_BUDGET,
        ..FILE_DECODER
    };
    let mut source = (0..ANY_CAP).map(|pid| raw_file(pid as u32, 1, b"/x"));
    let batch = decode_batch(&mut source, &mut Limiter::default(), ANY_CAP, &small);
    assert_eq!(batch.records.len(), usize::try_from(CUSTOM_BUDGET)?);
    assert_eq!(batch.limited, u64::try_from(ANY_CAP)? - u64::from(CUSTOM_BUDGET));
    Ok(())
}
