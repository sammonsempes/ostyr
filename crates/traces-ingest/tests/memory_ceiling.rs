mod common;
mod memory_support;
mod worst_support;


use common::types::TestResult;
use traces_ingest::model::Limits;
use traces_ingest::settings::ceiling_limits;
use worst_support::{check, DEFAULT_BUDGET_KIB};


const BUDGET_KIB: u64 = 1_024_000;


const BUDGET_FACTOR: u64 = 10;


const ATTRIBUTES: usize = 3;


const EVENTS: usize = 3;


const LINKS: usize = 3;


#[test]
fn the_worst_shape_at_every_ceiling_stays_within_a_thousand_mib() -> TestResult {
    check(&ceiling_limits(), BUDGET_KIB, ATTRIBUTES, EVENTS, LINKS, 0)
}


#[test]
fn the_ceiling_budget_is_ten_times_the_default_one() -> TestResult {
    assert_eq!(BUDGET_KIB, DEFAULT_BUDGET_KIB * BUDGET_FACTOR);
    Ok(())
}


#[test]
fn the_ceilings_are_above_the_defaults() -> TestResult {
    assert!(ceiling_limits().max_spans > Limits::default().max_spans);
    Ok(())
}
