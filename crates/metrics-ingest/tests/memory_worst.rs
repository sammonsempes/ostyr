mod common;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;


use common::types::TestResult;
use memory_support::framed;
use memory_support::{GAUGE, METRIC, POINTS, RESOURCE, RESOURCE_METRICS, SCOPE_METRICS, VALUE};
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::decode::decode_request;
use metrics_ingest::model::DEFAULT_MAX_TOTAL_ATTRIBUTES;
use metrics_ingest::model::{Limits, DEFAULT_MAX_DATA_POINTS, DEFAULT_MAX_ENTITY_KEYS_TOTAL, DEFAULT_MAX_ENTITY_REFS_TOTAL};
use peak::{high_water_kib, report, reset_high_water};


const BUDGET_KIB: u64 = 102_400;


const STRUCTURES_PER_CHAIN: usize = 3;


const ENTITY_REFS: u8 = 0x1a;


const EXEMPLARS: u8 = 0x2a;


const KEYED_ATTRIBUTE: [u8; 7] = [0x3a, 0x05, 0x0a, 0x01, 0x41, VALUE, 0x00];


const ENTITY_KEY: [u8; 3] = [0x1a, 0x01, 0x41];


fn entity_refs() -> Vec<u8> {
    let keys_per_ref = DEFAULT_MAX_ENTITY_KEYS_TOTAL / DEFAULT_MAX_ENTITY_REFS_TOTAL;
    framed(ENTITY_REFS, &ENTITY_KEY.repeat(keys_per_ref)).repeat(DEFAULT_MAX_ENTITY_REFS_TOTAL)
}


fn chain(point_extra: &[u8]) -> Vec<u8> {
    let point = framed(POINTS, &[point_extra, &framed(EXEMPLARS, &[])].concat());
    framed(SCOPE_METRICS, &framed(METRIC, &framed(GAUGE, &point)))
}


fn request() -> Vec<u8> {
    let chains = DEFAULT_MAX_DATA_POINTS / STRUCTURES_PER_CHAIN;
    let attributes = KEYED_ATTRIBUTE.repeat(DEFAULT_MAX_TOTAL_ATTRIBUTES);
    let first = chain(&attributes);
    let others = chain(&[]).repeat(chains.saturating_sub(1));
    framed(RESOURCE_METRICS, &[framed(RESOURCE, &entity_refs()), first, others].concat())
}


#[test]
fn every_budget_filled_at_once_stays_within_the_memory_budget() -> TestResult {
    let bytes = request();
    reset_high_water()?;
    let before = high_water_kib()?;
    let outcome = decode_request(&bytes, "tenant-a", &Limits::default(), &mut CardinalityState::default());
    let growth = high_water_kib()?.saturating_sub(before);
    report(&format!(
        "worst {} bytes: growth {growth} KiB, rows {}, refusal {:?}",
        bytes.len(),
        outcome.rows.len(),
        outcome.refusal
    ))?;
    assert!(outcome.refusal.is_none());
    assert!(growth < BUDGET_KIB, "{growth} KiB");
    Ok(())
}
