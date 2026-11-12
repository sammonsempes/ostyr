mod common;
mod memory_support;


use common::types::TestResult;
use memory_support::{framed, high_water_kib, report, reset_high_water, NOW, RESOURCE_SPANS_TAG, SCOPE_SPANS_TAG, SPANS_TAG, TENANT};
use traces_ingest::decode::decode_traces;
use traces_ingest::model::Limits;
use traces_ingest::sampling::Sampling;


const BUDGET_KIB: u64 = 131_072;


const SPANS_NEAR_THE_CAP: usize = 40_000;


const ARRAY_ELEMENTS_NEAR_THE_CAP: usize = 150_000;


const EVENTS_PER_SPAN: usize = 2;


const LINKS_PER_SPAN: usize = 2;


const ATTRIBUTES_PER_SPAN: usize = 4;


const ID_BYTES: usize = 8;


const ATTRIBUTE_TAG: u8 = 0x4a;


const EVENT_TAG: u8 = 0x5a;


const LINK_TAG: u8 = 0x6a;


const TRACE_ID_TAG: u8 = 0x0a;


const SPAN_ID_TAG: u8 = 0x12;


const KEY_TAG: u8 = 0x0a;


const VALUE_TAG: u8 = 0x12;


const ARRAY_TAG: u8 = 0x2a;


const ELEMENT_TAG: u8 = 0x0a;


const KEY_VALUE: [u8; 8] = [0x0a, 0x01, b'k', 0x12, 0x03, 0x0a, 0x01, b'v'];


fn span(index: usize, extra: &[u8]) -> Vec<u8> {
    let trace_id = [index.to_le_bytes().to_vec(), vec![1; ID_BYTES]].concat();
    let events = [EVENT_TAG, 0].repeat(EVENTS_PER_SPAN);
    let links = [LINK_TAG, 0].repeat(LINKS_PER_SPAN);
    let attributes = framed(ATTRIBUTE_TAG, &KEY_VALUE).repeat(ATTRIBUTES_PER_SPAN);
    let identity = [framed(TRACE_ID_TAG, &trace_id), framed(SPAN_ID_TAG, &[1; ID_BYTES])].concat();
    framed(SPANS_TAG, &[identity, events, links, attributes, extra.to_vec()].concat())
}


fn array_attribute() -> Vec<u8> {
    let elements = framed(ARRAY_TAG, &[ELEMENT_TAG, 0].repeat(ARRAY_ELEMENTS_NEAR_THE_CAP));
    framed(ATTRIBUTE_TAG, &[framed(KEY_TAG, b"k"), framed(VALUE_TAG, &elements)].concat())
}


#[test]
fn a_request_near_every_default_cap_stays_within_its_budget() -> TestResult {
    let first = span(0, &array_attribute());
    let others = (1..SPANS_NEAR_THE_CAP).flat_map(|index| span(index, &[])).collect::<Vec<u8>>();
    let bytes = framed(RESOURCE_SPANS_TAG, &framed(SCOPE_SPANS_TAG, &[first, others].concat()));
    reset_high_water()?;
    let before = high_water_kib()?;
    let outcome = decode_traces(&bytes, TENANT, &Limits::default(), &Sampling::default(), NOW);
    let growth = high_water_kib()?.saturating_sub(before);
    report(&format!(
        "accepted {} bytes: growth {growth} KiB, rows {}, dropped {:?}, refusal {:?}",
        bytes.len(),
        outcome.rows.len(),
        outcome.dropped,
        outcome.refusal
    ))?;
    assert!(outcome.refusal.is_none());
    assert!(growth < BUDGET_KIB, "{growth} KiB");
    Ok(())
}
