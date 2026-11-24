#[path = "support/sample.rs"]
mod sample;
#[path = "support/types.rs"]
mod types;


use core_audit::error::AuditError;
use core_audit::log::{append, fill_slot, follow, hand_off, new_log, take_outcome, AuditLog, LogState, Pending, SlotCell, MAX_GROUP_RECORDS};
use core_audit::model::GENESIS_HASH;
use core_audit::types::Slot;
use core_audit::verify::{verify, MAX_RECORD_BYTES};
use sample::entry;
use std::error::Error;
use std::io::{self, Write};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use types::TestResult;


const EXTRA_QUEUED: usize = 3;


const THREADS: usize = 8;


const APPENDS_PER_THREAD: usize = 20;


const SECOND_WRITE: usize = 2;


const TWO_GROUPS: usize = 2;


const YIELDS_WHILE_HELD: usize = 20_000;


const QUEUE_WAIT_YIELDS: usize = 100_000_000;


#[derive(Debug, Default)]
struct Latch {
    raised: Mutex<bool>,
    changed: Condvar,
}


#[derive(Debug, Default)]
struct Gate {
    entered: Latch,
    release: Latch,
}


fn raise(latch: &Latch) {
    *latch.raised.lock().unwrap_or_else(PoisonError::into_inner) = true;
    latch.changed.notify_all();
}


fn await_latch(latch: &Latch) {
    let guard = latch.raised.lock().unwrap_or_else(PoisonError::into_inner);
    drop(latch.changed.wait_while(guard, |raised| !*raised).unwrap_or_else(PoisonError::into_inner));
}


#[derive(Debug, Default)]
struct CountingWriter {
    bytes: Vec<u8>,
    writes: usize,
    fail_at_write: Option<usize>,
    syncs: usize,
    watched: Vec<Slot>,
    answered_before_sync: usize,
    gate: Option<Arc<Gate>>,
    panic_after_gate: bool,
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
        .filter(|slot| slot.state.lock().map(|state| state.outcome.is_some()).unwrap_or(true))
        .count();
    Ok(())
}


fn gated_sync(writer: &mut CountingWriter) -> io::Result<()> {
    if let Some(gate) = writer.gate.take() {
        raise(&gate.entered);
        await_latch(&gate.release);
    }
    writer.syncs += 1;
    assert!(!writer.panic_after_gate, "injected panic in sync");
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


fn spawn_log(
    sync: fn(&mut CountingWriter) -> io::Result<()>,
    panic_after_gate: bool,
) -> Result<(AuditLog<CountingWriter>, Arc<Gate>), Box<dyn Error>> {
    let gate = Arc::new(Gate::default());
    let log = new_log(
        CountingWriter {
            gate: Some(Arc::clone(&gate)),
            panic_after_gate,
            ..CountingWriter::default()
        },
        GENESIS_HASH,
        sync,
    );
    Ok((log, gate))
}


fn wait_until_queued(log: &AuditLog<CountingWriter>) -> bool {
    (0..QUEUE_WAIT_YIELDS).any(|_| {
        thread::yield_now();
        log.pending.lock().map(|queue| !queue.is_empty()).unwrap_or(true)
    })
}


#[test]
fn a_follower_parked_through_a_slow_sync_gets_ok_after_it_never_poisoned() -> TestResult {
    let (log, gate) = spawn_log(gated_sync, false)?;
    let (first, second) = (entry(0)?, entry(1)?);
    let (leader_record, follower_record) = thread::scope(|scope| -> Result<_, Box<dyn Error>> {
        let leader = scope.spawn(|| append(&log, first));
        await_latch(&gate.entered);
        let follower = scope.spawn(|| append(&log, second));
        assert!(wait_until_queued(&log));
        (0..YIELDS_WHILE_HELD).for_each(|_| thread::yield_now());
        raise(&gate.release);
        let leader_record = leader.join().map_err(|_| "leader panicked")??;
        let follower_record = follower.join().map_err(|_| "follower panicked")??;
        Ok((leader_record, follower_record))
    })?;
    assert_eq!(follower_record.previous_hash, leader_record.hash);
    let state = log.state.into_inner()?;
    assert_eq!(state.writer.syncs, TWO_GROUPS);
    assert_eq!(verify(state.writer.bytes.as_slice(), Some(&state.head))?.records, TWO_GROUPS);
    Ok(())
}


#[test]
fn a_leader_that_panics_in_the_writer_refuses_its_followers_instead_of_leaving_them_waiting() -> TestResult {
    let (log, gate) = spawn_log(gated_sync, true)?;
    let (first, second) = (entry(0)?, entry(1)?);
    let (leader_panicked, follower_outcome) = thread::scope(|scope| -> Result<_, Box<dyn Error>> {
        let leader = scope.spawn(|| append(&log, first));
        await_latch(&gate.entered);
        let follower = scope.spawn(|| append(&log, second));
        assert!(wait_until_queued(&log));
        raise(&gate.release);
        let leader_panicked = leader.join().is_err();
        let follower_outcome = follower.join().map_err(|_| "follower panicked")?;
        Ok((leader_panicked, follower_outcome))
    })?;
    assert!(leader_panicked);
    assert!(matches!(follower_outcome, Err(AuditError::LogPoisoned)));
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::LogPoisoned)));
    assert!(log.pending.lock().map_err(|error| error.to_string())?.is_empty());
    Ok(())
}


#[test]
fn a_panicked_writer_lock_refuses_every_queued_entry() -> TestResult {
    let log = log_with(None, counting_sync);
    thread::scope(|scope| {
        let _panicked = scope
            .spawn(|| {
                let _guard = log.state.lock();
                assert!(log.state.is_poisoned(), "poison the writer lock");
            })
            .join();
    });
    let slots = queue(&log, EXTRA_QUEUED)?;
    assert!(matches!(append(&log, entry(0)?), Err(AuditError::LogPoisoned)));
    assert!(slots.iter().all(|slot| matches!(take_outcome(slot), Some(Err(AuditError::LogPoisoned)))));
    assert!(log.pending.lock().map_err(|error| error.to_string())?.is_empty());
    Ok(())
}


#[test]
fn an_answered_follower_returns_its_outcome_without_flushing() -> TestResult {
    let log = log_with(None, counting_sync);
    let record = append(&log, entry(0)?)?;
    let slot: Slot = Arc::new(SlotCell::default());
    fill_slot(&slot, Ok(record.clone()));
    let queued = queue(&log, 1)?;
    assert!(matches!(follow(&log, &slot), Ok(ref taken) if taken.hash == record.hash));
    assert_eq!(syncs(&log)?, 1);
    assert!(queued.iter().all(|pending| take_outcome(pending).is_none()));
    Ok(())
}


#[test]
fn a_promoted_follower_takes_the_lock_and_flushes_what_is_queued() -> TestResult {
    let log = log_with(None, counting_sync);
    let record = append(&log, entry(0)?)?;
    let slot: Slot = Arc::new(SlotCell::default());
    fill_slot(&slot, Ok(record.clone()));
    slot.state.lock().map_err(|_| "poisoned")?.promoted = true;
    let queued = queue(&log, EXTRA_QUEUED)?;
    assert!(matches!(follow(&log, &slot), Ok(ref taken) if taken.hash == record.hash));
    assert_eq!(syncs(&log)?, TWO_GROUPS);
    assert!(queued.iter().all(|pending| matches!(take_outcome(pending), Some(Ok(_)))));
    assert!(!slot.state.lock().map_err(|_| "poisoned")?.promoted);
    Ok(())
}


#[test]
fn a_promoted_follower_finding_the_writer_lock_poisoned_is_refused() -> TestResult {
    let log = log_with(None, counting_sync);
    thread::scope(|scope| {
        let _panicked = scope
            .spawn(|| {
                let _guard = log.state.lock();
                assert!(log.state.is_poisoned(), "poison the writer lock");
            })
            .join();
    });
    let slot: Slot = Arc::new(SlotCell::default());
    slot.state.lock().map_err(|_| "poisoned")?.promoted = true;
    let queued = queue(&log, 1)?;
    fill_slot(&slot, Err(AuditError::LogPoisoned));
    assert!(matches!(follow(&log, &slot), Err(AuditError::LogPoisoned)));
    assert!(queued
        .iter()
        .all(|pending| matches!(take_outcome(pending), Some(Err(AuditError::LogPoisoned)))));
    Ok(())
}


#[test]
fn the_hand_off_promotes_only_the_oldest_queued_entry() -> TestResult {
    let log = log_with(None, counting_sync);
    hand_off(&log);
    let slots = queue(&log, EXTRA_QUEUED)?;
    hand_off(&log);
    let promoted: Vec<bool> = slots
        .iter()
        .map(|slot| slot.state.lock().map(|state| state.promoted).unwrap_or(false))
        .collect();
    assert_eq!(promoted, vec![true, false, false]);
    Ok(())
}
