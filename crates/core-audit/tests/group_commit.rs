#[path = "support/sample.rs"]
mod sample;
#[path = "support/types.rs"]
mod types;


use core_audit::error::AuditError;
use core_audit::log::{
    append, await_answer, head, lead, leave_outcome, new_log, take_outcome, AuditLog, LogState, Pending, SlotCell, MAX_GROUP_RECORDS,
};
use core_audit::model::GENESIS_HASH;
use core_audit::types::Slot;
use core_audit::verify::{verify, MAX_RECORD_BYTES};
use sample::entry;
use std::error::Error;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::Duration;
use types::TestResult;


const HANG_GUARD_SECONDS: u64 = 600;


const EXTRA_QUEUED: usize = 3;


const THREADS: usize = 8;


const APPENDS_PER_THREAD: usize = 20;


const MAX_MISPLACED: usize = TWO_GROUPS * MAX_GROUP_RECORDS + EXTRA_QUEUED;


const SECOND_WRITE: usize = 2;


const TWO_GROUPS: usize = 2;


const YIELDS_WHILE_HELD: usize = 20_000;


const QUEUE_WAIT_YIELDS: usize = 100_000_000;


fn guarded(body: fn() -> TestResult) -> TestResult {
    let (sender, receiver) = mpsc::channel();
    let detached = thread::spawn(move || sender.send(body().map_err(|error| error.to_string())));
    drop(detached);
    receiver
        .recv_timeout(Duration::from_secs(HANG_GUARD_SECONDS))
        .map_err(|error| match error {
            RecvTimeoutError::Timeout => "hang guard expired".to_owned(),
            RecvTimeoutError::Disconnected => "guarded body panicked".to_owned(),
        })??;
    Ok(())
}


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
        .filter(|slot| slot.outcome.lock().map(|outcome| outcome.is_some()).unwrap_or(true))
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
            log.pending.lock().map_err(|error| error.to_string())?.entries.push(Pending {
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
    log.pending.lock().map_err(|error| error.to_string())?.entries.insert(
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


fn wait_until_queued(log: &AuditLog<CountingWriter>, count: usize) -> bool {
    (0..QUEUE_WAIT_YIELDS).any(|_| {
        thread::yield_now();
        log.pending.lock().map(|queue| queue.entries.len() >= count).unwrap_or(true)
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
        assert!(wait_until_queued(&log, 1));
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
fn a_leader_that_panics_in_the_writer_hands_the_lead_to_a_waiter_who_refuses_every_queued_entry() -> TestResult {
    guarded(|| {
        let (log, gate) = spawn_log(gated_sync, true)?;
        let (first, second) = (entry(0)?, entry(1)?);
        let (leader_panicked, follower_outcome) = thread::scope(|scope| -> Result<_, Box<dyn Error>> {
            let leader = scope.spawn(|| append(&log, first));
            await_latch(&gate.entered);
            let follower = scope.spawn(|| append(&log, second));
            assert!(wait_until_queued(&log, 1));
            raise(&gate.release);
            let leader_panicked = leader.join().is_err();
            let follower_outcome = follower.join().map_err(|_| "follower panicked")?;
            Ok((leader_panicked, follower_outcome))
        })?;
        assert!(leader_panicked);
        assert!(matches!(follower_outcome, Err(AuditError::LogPoisoned)));
        assert!(matches!(append(&log, entry(0)?), Err(AuditError::LogPoisoned)));
        assert!(log.pending.lock().map_err(|error| error.to_string())?.entries.is_empty());
        Ok(())
    })
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
    assert!(log.pending.lock().map_err(|error| error.to_string())?.entries.is_empty());
    Ok(())
}


#[test]
fn an_append_queued_behind_a_leader_blocked_on_another_state_holder_is_answered_when_it_lets_go() -> TestResult {
    guarded(|| {
        let log = log_with(None, counting_sync);
        let held = Gate::default();
        let (leader_record, follower_record) = thread::scope(|scope| -> Result<_, Box<dyn Error>> {
            let holder = scope.spawn(|| {
                if let Ok(guard) = log.state.lock() {
                    raise(&held.entered);
                    await_latch(&held.release);
                    drop(guard);
                }
            });
            await_latch(&held.entered);
            let (first, second) = (entry(0)?, entry(1)?);
            let leader = scope.spawn(|| append(&log, first));
            assert!(wait_until_queued(&log, 1));
            let follower = scope.spawn(|| append(&log, second));
            assert!(wait_until_queued(&log, TWO_GROUPS));
            raise(&held.release);
            holder.join().map_err(|_| "holder panicked")?;
            let leader_record = leader.join().map_err(|_| "leader panicked")??;
            let follower_record = follower.join().map_err(|_| "follower panicked")??;
            Ok((leader_record, follower_record))
        })?;
        assert_eq!(follower_record.previous_hash, leader_record.hash);
        Ok(())
    })
}


#[test]
fn head_reads_beside_a_sequential_appender_never_strand_an_append() -> TestResult {
    let log = log_with(None, counting_sync);
    let stop = AtomicBool::new(false);
    thread::scope(|scope| -> TestResult {
        let reader = scope.spawn(|| {
            (0..QUEUE_WAIT_YIELDS)
                .take_while(|_| !stop.load(Ordering::SeqCst))
                .for_each(|_| drop(head(&log)));
        });
        let appended =
            (0..APPENDS_PER_THREAD * THREADS).try_for_each(|index| append(&log, entry(index)?).map(|_| ()).map_err(Box::<dyn Error>::from));
        stop.store(true, Ordering::SeqCst);
        reader.join().map_err(|_| "reader panicked")?;
        appended
    })?;
    assert_eq!(log.state.into_inner()?.writer.syncs, APPENDS_PER_THREAD * THREADS);
    Ok(())
}


#[test]
fn a_filled_caller_returns_while_another_thread_holds_the_writer_lock() -> TestResult {
    guarded(|| {
        let log = log_with(None, counting_sync);
        let held = Gate::default();
        let returned = AtomicBool::new(false);
        let returned_before_release = AtomicBool::new(false);
        let slot: Slot = Arc::new(SlotCell::default());
        let record = append(&log, entry(0)?)?;
        leave_outcome(&slot, Ok(record.clone()));
        thread::scope(|scope| -> TestResult {
            let holder = scope.spawn(|| {
                if let Ok(guard) = log.state.lock() {
                    raise(&held.entered);
                    let seen = (0..QUEUE_WAIT_YIELDS).any(|_| {
                        thread::yield_now();
                        returned.load(Ordering::SeqCst)
                    });
                    returned_before_release.store(seen, Ordering::SeqCst);
                    drop(guard);
                }
            });
            await_latch(&held.entered);
            let mut queue = log.pending.lock().map_err(|error| error.to_string())?;
            queue.leader_active = true;
            let answer = await_answer(&log, queue, &slot);
            returned.store(true, Ordering::SeqCst);
            holder.join().map_err(|_| "holder panicked")?;
            assert!(matches!(answer, Ok(ref taken) if taken.hash == record.hash));
            Ok(())
        })?;
        assert!(returned_before_release.load(Ordering::SeqCst));
        Ok(())
    })
}


#[test]
fn a_waiter_whose_leader_ended_without_answering_it_leads_itself() -> TestResult {
    let log = log_with(None, counting_sync);
    let queued = queue(&log, 1)?;
    let slot = queued.first().ok_or("no slot")?;
    let mut held = log.pending.lock().map_err(|error| error.to_string())?;
    held.leader_active = false;
    assert!(await_answer(&log, held, slot).is_ok());
    assert!(!log.pending.lock().map_err(|error| error.to_string())?.leader_active);
    assert_eq!(syncs(&log)?, 1);
    Ok(())
}


#[test]
fn an_entry_queued_beyond_one_group_is_answered_by_the_bounded_lead() -> TestResult {
    guarded(|| {
        let log = log_with(None, counting_sync);
        let slots = queue(&log, MAX_GROUP_RECORDS)?;
        let own: Slot = Arc::new(SlotCell::default());
        log.pending.lock().map_err(|error| error.to_string())?.entries.push(Pending {
            entry: entry(0)?,
            slot: Arc::clone(&own),
        });
        let mut held = log.pending.lock().map_err(|error| error.to_string())?;
        held.leader_active = false;
        await_answer(&log, held, &own)?;
        assert_eq!(syncs(&log)?, TWO_GROUPS);
        assert!(slots.iter().all(|slot| matches!(take_outcome(slot), Some(Ok(_)))));
        assert!(log.pending.lock().map_err(|error| error.to_string())?.entries.is_empty());
        Ok(())
    })
}


#[test]
fn a_lead_stops_at_its_own_answer_and_leaves_later_entries_queued() -> TestResult {
    let log = log_with(None, counting_sync);
    let own: Slot = Arc::new(SlotCell::default());
    log.pending.lock().map_err(|error| error.to_string())?.entries.push(Pending {
        entry: entry(0)?,
        slot: Arc::clone(&own),
    });
    queue(&log, MAX_MISPLACED)?;
    log.pending.lock().map_err(|error| error.to_string())?.leader_active = true;
    assert!(lead(&log, &own, MAX_MISPLACED).is_ok());
    assert_eq!(syncs(&log)?, 1);
    assert_eq!(
        log.pending.lock().map_err(|error| error.to_string())?.entries.len(),
        MAX_MISPLACED + 1 - MAX_GROUP_RECORDS
    );
    Ok(())
}


#[test]
fn a_waiter_absent_from_the_queue_leads_one_round_and_is_told_nothing_was_left() -> TestResult {
    let log = log_with(None, counting_sync);
    let stranger: Slot = Arc::new(SlotCell::default());
    let mut held = log.pending.lock().map_err(|error| error.to_string())?;
    held.leader_active = false;
    assert!(matches!(await_answer(&log, held, &stranger), Err(AuditError::LogPoisoned)));
    assert!(!log.pending.lock().map_err(|error| error.to_string())?.leader_active);
    Ok(())
}
