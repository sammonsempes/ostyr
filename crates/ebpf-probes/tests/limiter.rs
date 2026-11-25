use ebpf_probes::limiter::{admit, take_dropped, Limiter, MAX_EXEC_EVENTS_PER_SECOND, MAX_FILE_EVENTS_PER_SECOND, NANOS_PER_SECOND};
use std::error::Error;


const BURST: u64 = 100_000;


const SMALL_BUDGET: u32 = 5;


const START_NS: u64 = 5 * NANOS_PER_SECOND;


const STEP_BACK_NS: u64 = 2 * NANOS_PER_SECOND;


fn exhaust(limiter: &mut Limiter, now_ns: u64) {
    (0..BURST).for_each(|_| {
        admit(limiter, now_ns, MAX_EXEC_EVENTS_PER_SECOND);
    });
}


#[test]
fn a_burst_in_one_second_admits_exactly_the_budget() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    let admitted = (0..BURST).filter(|_| admit(&mut limiter, START_NS, MAX_EXEC_EVENTS_PER_SECOND)).count();
    assert_eq!(admitted as u64, u64::from(MAX_EXEC_EVENTS_PER_SECOND));
    assert_eq!(take_dropped(&mut limiter), BURST - u64::from(MAX_EXEC_EVENTS_PER_SECOND));
    assert_eq!(take_dropped(&mut limiter), 0);
    Ok(())
}


#[test]
fn the_budget_refills_each_second() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    exhaust(&mut limiter, START_NS);
    assert!(!admit(&mut limiter, START_NS + NANOS_PER_SECOND - 1, MAX_EXEC_EVENTS_PER_SECOND));
    assert!(admit(&mut limiter, START_NS + NANOS_PER_SECOND, MAX_EXEC_EVENTS_PER_SECOND));
    Ok(())
}


#[test]
fn a_clock_step_backwards_never_refills() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    exhaust(&mut limiter, START_NS);
    let admitted_after_step = (0..BURST)
        .filter(|_| admit(&mut limiter, START_NS - STEP_BACK_NS, MAX_EXEC_EVENTS_PER_SECOND))
        .count();
    let admitted_at_zero = (0..BURST).filter(|_| admit(&mut limiter, 0, MAX_EXEC_EVENTS_PER_SECOND)).count();
    assert_eq!(admitted_after_step, 0);
    assert_eq!(admitted_at_zero, 0);
    Ok(())
}


#[test]
fn the_first_event_at_clock_zero_is_admitted() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    assert!(admit(&mut limiter, 0, MAX_EXEC_EVENTS_PER_SECOND));
    Ok(())
}


#[test]
fn each_probe_budget_is_its_own_and_a_limiter_is_never_shared() -> Result<(), Box<dyn Error>> {
    let small = SMALL_BUDGET;
    let mut exec = Limiter::default();
    let mut file = Limiter::default();
    let file_admitted = (0..BURST).filter(|_| admit(&mut file, START_NS, small)).count();
    let exec_admitted = (0..BURST).filter(|_| admit(&mut exec, START_NS, MAX_EXEC_EVENTS_PER_SECOND)).count();
    assert_eq!(file_admitted, small as usize);
    assert_eq!(take_dropped(&mut file), BURST - u64::from(small));
    assert_eq!(exec_admitted as u64, u64::from(MAX_EXEC_EVENTS_PER_SECOND));
    assert_eq!(take_dropped(&mut exec), BURST - u64::from(MAX_EXEC_EVENTS_PER_SECOND));
    assert_eq!(MAX_FILE_EVENTS_PER_SECOND, MAX_EXEC_EVENTS_PER_SECOND);
    Ok(())
}
