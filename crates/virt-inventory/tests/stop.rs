#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use types::TestResult;
use virt_inventory::stop::{arm_stops, follow_stops, joined, note_signals, signal_name, OTHER_SIGNAL, SIGNAL_INTERRUPT, SIGNAL_TERMINATE};


const UNEXPECTED: i32 = 99;


const THREE_SIGNALS: usize = 3;


const PAYLOAD: u8 = 0;


#[test]
fn the_two_stop_signals_are_named_and_anything_else_is_not_mistaken_for_them() -> TestResult {
    assert_eq!(signal_name(SIGNAL_TERMINATE), "SIGTERM");
    assert_eq!(signal_name(SIGNAL_INTERRUPT), "SIGINT");
    assert_eq!(signal_name(UNEXPECTED), OTHER_SIGNAL);
    Ok(())
}


#[test]
fn every_signal_is_counted_the_first_as_the_request_and_the_rest_as_ignored() -> TestResult {
    assert_eq!(note_signals(Vec::new().into_iter()), 0);
    assert_eq!(note_signals([SIGNAL_TERMINATE].into_iter()), 1);
    assert_eq!(note_signals([SIGNAL_INTERRUPT, SIGNAL_TERMINATE, UNEXPECTED].into_iter()), THREE_SIGNALS);
    Ok(())
}


#[test]
fn a_thread_that_panicked_is_reported_and_a_good_one_is_not() -> TestResult {
    assert!(joined(Ok(1)));
    assert!(!joined(Err(Box::new(PAYLOAD))));
    Ok(())
}


#[test]
fn the_stop_thread_reads_a_real_signal_and_ends_when_dropped() -> TestResult {
    let stops = arm_stops()?;
    let thread = follow_stops(stops);
    signal_hook::low_level::raise(signal_hook::consts::SIGTERM)?;
    drop(thread);
    Ok(())
}
