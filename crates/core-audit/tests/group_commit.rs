#[path = "support/sample.rs"]
mod sample;
#[path = "support/types.rs"]
mod types;


use core_audit::error::AuditError;
use core_audit::log::{
    append, append_bounded, commit_round, fill_slot, new_log, take_outcome, AuditLog, LogState, Pending, SlotCell, MAX_GROUP_RECORDS,
};
use core_audit::model::GENESIS_HASH;
use core_audit::types::Slot;
use core_audit::verify::{verify, MAX_RECORD_BYTES};
use sample::entry;
use std::error::Error;
use std::io::{self, Write};
use std::sync::Arc;
use std::thread;
use types::TestResult;


const EXTRA_QUEUED: usize = 3;


const THREADS: usize = 8;


const APPENDS_PER_THREAD: usize = 20;


const SECOND_WRITE: usize = 2;


const TWO_GROUPS: usize = 2;


#[derive(Debug, Default)]
struct CountingWriter {
    bytes: Vec<u8>,
    writes: usize,
    fail_at_write: Option<usize>,
    syncs: usize,
    watched: Vec<Slot>,
    answered_before_sync: usize,
}


impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.fail_at_write == Some(self.writes) {
            Err(io::Error::other("injected write failure"))
        } else {
            self.bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn counting_sync(writer: &mut CountingWriter) -> io::Result<()> {
    writer.syncs += 1;
    Ok(())
}


fn observing_sync(writer: &mut CountingWriter) -> io::Result<()> {
    writer.syncs += 1;
    writer.answered_before_sync = writer
        .watched
        .iter()
        .filter(|slot| slot.outcome.lock().map(|outcome| outcome.is_some()).unwrap_or(true))
        .count();
    Ok(())
}


fn failing_sync(writer: &mut CountingWriter) -> io::Result<()> {
    writer.syncs += 1;
    Err(io::Error::other("injected sync failure"))
}


fn log_with(fail_at_write: Option<usize>, sync: fn(&mut CountingWriter) -> io::Result<()>) -> AuditLog<CountingWriter> {
    new_log(
        CountingWriter {
            fail_at_write,
            ..CountingWriter::default()
        },
        GENESIS_HASH,
        sync,
    )
}


fn queue(log: &AuditLog<CountingWriter>, count: usize) -> Result<Vec<Slot>, Box<dyn Error>> {
    (0..count)
        .map(|index| {
            let slot: Slot = Arc::new(SlotCell::default());
            let new = entry(index + 1)?;
            log.pending.lock().map_err(|error| error.to_string())?.push(Pending {
                entry: new,
                slot: Arc::clone(&slot),
            });
            Ok(slot)
        })
        .collect()
}


fn syncs(log: &AuditLog<CountingWriter>) -> Result<usize, Box<dyn Error>> {
    Ok(log.state.lock().map_err(|_| "poisoned")?.writer.syncs)
}


fn all_failed(slots: &[Slot]) -> bool {
    slots.iter().all(|slot| matches!(take_outcome(slot), Some(Err(AuditError::Io(_)))))
}


#[test]
fn queued_entries_share_one_sync_and_the_chain_verifies() -> TestResult {
    let log = log_with(None, counting_sync);
    let slots = queue(&log, EXTRA_QUEUED)?;
    append(&log, entry(0)?)?;
    assert_eq!(syncs(&log)?, 1);
    assert!(slots.iter().all(|slot| matches!(take_outcome(slot), Some(Ok(_)))));
    let state = log.state.into_inner()?;
    assert_eq!(verify(state.writer.bytes.as_slice(), Some(&state.head))?.records, EXTRA_QUEUED + 1);
    Ok(())
}


#[test]
fn a_group_is_capped_and_the_rest_follows_in_order() -> TestResult {
    let log = log_with(None, counting_sync);
    let slots = queue(&log, MAX_GROUP_RECORDS + EXTRA_QUEUED)?;
    let own = append(&log, entry(0)?)?;
    assert_eq!(syncs(&log)?, TWO_GROUPS);
    assert!(slots.iter().all(|slot| matches!(take_outcome(slot), Some(Ok(_)))));
    let state = log.state.into_inner()?;
    assert_eq!(state.head, own.hash);
    assert_eq!(
        verify(state.writer.bytes.as_slice(), Some(&state.head))?.records,
        MAX_GROUP_RECORDS + EXTRA_QUEUED + 1
    );
    Ok(())
}


#[test]
fn a_failed_sync_fails_every_waiter_of_the_group_and_poisons_the_log() -> TestResult {
    let log = log_with(None, failing_sync);
    let slots = queue(&log, EXTRA_QUEUED)?;
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::Io(_))));
    assert!(all_failed(&slots));
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::LogPoisoned)));
    assert_eq!(log.state.into_inner()?.head, GENESIS_HASH);
    Ok(())
}


#[test]
fn a_failed_write_fails_the_whole_group_without_a_sync() -> TestResult {
    let log = log_with(Some(SECOND_WRITE), counting_sync);
    let slots = queue(&log, EXTRA_QUEUED)?;
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::Io(_))));
    assert!(all_failed(&slots));
    assert_eq!(syncs(&log)?, 0);
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::LogPoisoned)));
    assert_eq!(log.state.into_inner()?.head, GENESIS_HASH);
    Ok(())
}


#[test]
fn an_oversized_entry_fails_alone_and_the_others_commit() -> TestResult {
    let log = log_with(None, counting_sync);
    let slots = queue(&log, EXTRA_QUEUED)?;
    let mut big = entry(0)?;
    big.target = "t".repeat(MAX_RECORD_BYTES);
    let big_slot: Slot = Arc::new(SlotCell::default());
    log.pending.lock().map_err(|error| error.to_string())?.insert(
        1,
        Pending {
            entry: big,
            slot: Arc::clone(&big_slot),
        },
    );
    append(&log, entry(0)?)?;
    assert!(matches!(take_outcome(&big_slot), Some(Err(AuditError::RecordTooLarge { .. }))));
    assert!(slots.iter().all(|slot| matches!(take_outcome(slot), Some(Ok(_)))));
    let state = log.state.into_inner()?;
    assert!(!state.poisoned);
    assert_eq!(verify(state.writer.bytes.as_slice(), Some(&state.head))?.records, EXTRA_QUEUED + 1);
    Ok(())
}


#[test]
fn a_group_of_refused_entries_syncs_nothing() -> TestResult {
    let log = log_with(None, counting_sync);
    let mut big = entry(0)?;
    big.target = "t".repeat(MAX_RECORD_BYTES);
    assert!(matches!(append(&log, big), Err(AuditError::RecordTooLarge { .. })));
    assert_eq!(syncs(&log)?, 0);
    Ok(())
}


#[test]
fn a_poisoned_log_refuses_the_queued_entries_too() -> TestResult {
    let log = log_with(None, counting_sync);
    log.state.lock().map_err(|_| "poisoned")?.poisoned = true;
    let slots = queue(&log, EXTRA_QUEUED)?;
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::LogPoisoned)));
    assert!(slots.iter().all(|slot| matches!(take_outcome(slot), Some(Err(AuditError::LogPoisoned)))));
    assert_eq!(log.state.into_inner()?.writer.bytes.len(), 0);
    Ok(())
}


#[test]
fn a_panicked_writer_lock_refuses_and_withdraws_the_entry() -> TestResult {
    let log = log_with(None, counting_sync);
    thread::scope(|scope| {
        let _panicked = scope
            .spawn(|| {
                let _guard = log.state.lock();
                assert!(log.state.is_poisoned(), "poison the writer lock");
            })
            .join();
    });
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::LogPoisoned)));
    assert!(log.pending.lock().map_err(|error| error.to_string())?.is_empty());
    Ok(())
}


#[test]
fn a_panicked_queue_lock_is_a_poisoned_log() -> TestResult {
    let log = log_with(None, counting_sync);
    thread::scope(|scope| {
        let _panicked = scope
            .spawn(|| {
                let _guard = log.pending.lock();
                assert!(log.pending.is_poisoned(), "poison the queue lock");
            })
            .join();
    });
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::LogPoisoned)));
    Ok(())
}


#[test]
fn an_entry_not_committed_within_the_cap_is_withdrawn_unwritten() -> TestResult {
    let log = log_with(None, counting_sync);
    assert!(matches!(append_bounded(&log, entry(0)?, 0), Err(AuditError::LogPoisoned)));
    assert!(log.pending.lock().map_err(|error| error.to_string())?.is_empty());
    assert_eq!(log.state.into_inner()?.writer.bytes.len(), 0);
    Ok(())
}


#[test]
fn a_follower_takes_the_outcome_a_leader_left_without_flushing() -> TestResult {
    let log = log_with(None, counting_sync);
    let record = append(&log, entry(0)?)?;
    let slot: Slot = Arc::new(SlotCell::default());
    fill_slot(&slot, Ok(record.clone()));
    let queued = queue(&log, 1)?;
    let outcome = commit_round(&log, &slot);
    assert!(matches!(outcome, Some(Ok(ref taken)) if taken.hash == record.hash));
    assert_eq!(syncs(&log)?, 1);
    assert!(queued.iter().all(|pending| take_outcome(pending).is_none()));
    Ok(())
}


#[test]
fn concurrent_appenders_get_one_valid_chain_with_no_more_syncs_than_records() -> TestResult {
    let log = Arc::new(log_with(None, counting_sync));
    thread::scope(|scope| {
        (0..THREADS).for_each(|worker| {
            let shared = Arc::clone(&log);
            scope.spawn(move || {
                (0..APPENDS_PER_THREAD).for_each(|index| {
                    if let Ok(new) = entry(worker * APPENDS_PER_THREAD + index) {
                        assert!(append(&shared, new).is_ok());
                    }
                });
            });
        });
    });
    let state = Arc::try_unwrap(log).map_err(|_| "log still shared")?.state.into_inner()?;
    assert_eq!(
        verify(state.writer.bytes.as_slice(), Some(&state.head))?.records,
        THREADS * APPENDS_PER_THREAD
    );
    assert!(state.writer.syncs >= 1 && state.writer.syncs <= THREADS * APPENDS_PER_THREAD);
    Ok(())
}


#[test]
fn a_waiter_gets_the_outcome_without_the_writer_lock() -> TestResult {
    let log = log_with(None, counting_sync);
    let record = append(&log, entry(0)?)?;
    let slot: Slot = Arc::new(SlotCell::default());
    fill_slot(&slot, Ok(record.clone()));
    let held = log.state.lock().map_err(|_| "poisoned")?;
    let outcome = commit_round(&log, &slot);
    drop(held);
    assert!(matches!(outcome, Some(Ok(ref taken)) if taken.hash == record.hash));
    Ok(())
}


#[test]
fn a_waiter_with_no_outcome_yet_gets_none_and_flushes_nothing() -> TestResult {
    let log = log_with(None, counting_sync);
    let queued = queue(&log, 1)?;
    let slot: Slot = Arc::new(SlotCell::default());
    let held = log.state.lock().map_err(|_| "poisoned")?;
    let outcome = commit_round(&log, &slot);
    drop(held);
    assert!(outcome.is_none());
    assert!(queued.iter().all(|pending| take_outcome(pending).is_none()));
    assert_eq!(log.pending.lock().map_err(|error| error.to_string())?.len(), 1);
    Ok(())
}


#[test]
fn no_waiter_is_answered_before_the_sync_that_covers_its_record() -> TestResult {
    let log = log_with(None, observing_sync);
    let slots = queue(&log, EXTRA_QUEUED)?;
    log.state.lock().map_err(|_| "poisoned")?.writer.watched = slots.clone();
    append(&log, entry(0)?)?;
    let state = log.state.into_inner()?;
    assert_eq!(state.writer.syncs, 1);
    assert_eq!(state.writer.answered_before_sync, 0);
    assert!(slots.iter().all(|slot| matches!(take_outcome(slot), Some(Ok(_)))));
    Ok(())
}


#[test]
fn a_swap_with_entries_queued_chains_them_in_the_new_file_only() -> TestResult {
    let log = log_with(None, counting_sync);
    append(&log, entry(0)?)?;
    let slots = queue(&log, EXTRA_QUEUED)?;
    *log.state.lock().map_err(|_| "poisoned")? = LogState {
        writer: CountingWriter::default(),
        head: GENESIS_HASH.to_owned(),
        poisoned: false,
    };
    append(&log, entry(0)?)?;
    assert!(slots.iter().all(|slot| matches!(take_outcome(slot), Some(Ok(_)))));
    let state = log.state.into_inner()?;
    assert_eq!(state.writer.syncs, 1);
    assert_eq!(verify(state.writer.bytes.as_slice(), Some(&state.head))?.records, EXTRA_QUEUED + 1);
    Ok(())
}
