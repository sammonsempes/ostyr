use ebpf_probes::limiter::{admit, take_dropped, Limiter, MAX_EXEC_EVENTS_PER_SECOND, NANOS_PER_SECOND};
use std::error::Error;


const BURST: u64 = 100_000;


const START_NS: u64 = 5 * NANOS_PER_SECOND;


const STEP_BACK_NS: u64 = 2 * NANOS_PER_SECOND;


fn exhaust(limiter: &mut Limiter, now_ns: u64) {
    (0..BURST).for_each(|_| {
        admit(limiter, now_ns);
    });
}


#[test]
fn a_burst_in_one_second_admits_exactly_the_budget() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    let admitted = (0..BURST).filter(|_| admit(&mut limiter, START_NS)).count();
    assert_eq!(admitted as u64, u64::from(MAX_EXEC_EVENTS_PER_SECOND));
    assert_eq!(take_dropped(&mut limiter), BURST - u64::from(MAX_EXEC_EVENTS_PER_SECOND));
    assert_eq!(take_dropped(&mut limiter), 0);
    Ok(())
}


#[test]
fn the_budget_refills_each_second() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    exhaust(&mut limiter, START_NS);
    assert!(!admit(&mut limiter, START_NS + NANOS_PER_SECOND - 1));
    assert!(admit(&mut limiter, START_NS + NANOS_PER_SECOND));
    Ok(())
}


#[test]
fn a_clock_step_backwards_never_refills() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    exhaust(&mut limiter, START_NS);
    let admitted_after_step = (0..BURST).filter(|_| admit(&mut limiter, START_NS - STEP_BACK_NS)).count();
    let admitted_at_zero = (0..BURST).filter(|_| admit(&mut limiter, 0)).count();
    assert_eq!(admitted_after_step, 0);
    assert_eq!(admitted_at_zero, 0);
    Ok(())
}


#[test]
fn the_first_event_at_clock_zero_is_admitted() -> Result<(), Box<dyn Error>> {
    let mut limiter = Limiter::default();
    assert!(admit(&mut limiter, 0));
    Ok(())
}
