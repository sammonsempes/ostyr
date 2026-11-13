mod common;
mod memory_support;


use common::types::TestResult;
use memory_support::{framed, high_water_kib, report, reset_high_water, NOW, RESOURCE_SPANS_TAG, SCOPE_SPANS_TAG, SPANS_TAG, TENANT};
use traces_ingest::decode::decode_traces;
use traces_ingest::model::{Limits, DEFAULT_MAX_ENTITY_REFS_TOTAL, DEFAULT_MAX_SPANS};
use traces_ingest::sampling::Sampling;


const BUDGET_KIB: u64 = 102_400;


const ID_BYTES: usize = 8;


const SERVICE_BYTES: usize = 256;


const EVENTS_PER_SPAN: usize = 2;


const LINKS_PER_SPAN: usize = 2;


const KEYS_PER_REFERENCE: usize = 4;


const ARRAY_ELEMENTS: usize = 199_000;


const RESOURCE_TAG: u8 = 0x0a;


const RESOURCE_ATTRIBUTE_TAG: u8 = 0x0a;


const ENTITY_REFS_TAG: u8 = 0x1a;


const ID_KEYS_TAG: u8 = 0x1a;


const EVENT_TAG: u8 = 0x5a;


const LINK_TAG: u8 = 0x6a;


const TRACE_ID_TAG: u8 = 0x0a;


const SPAN_ID_TAG: u8 = 0x12;


const KEY_TAG: u8 = 0x0a;


const VALUE_TAG: u8 = 0x12;


const STRING_TAG: u8 = 0x0a;


const ARRAY_TAG: u8 = 0x2a;


const ELEMENT_TAG: u8 = 0x0a;


const TRACE_ID_BYTES: usize = 16;


const RESERVED_ATTRIBUTES: usize = 2;


const SPANS: usize = DEFAULT_MAX_SPANS - 1;


fn span() -> Vec<u8> {
    let identity = [framed(TRACE_ID_TAG, &[1; TRACE_ID_BYTES]), framed(SPAN_ID_TAG, &[1; ID_BYTES])].concat();
    let events = [EVENT_TAG, 0].repeat(EVENTS_PER_SPAN);
    let links = [LINK_TAG, 0].repeat(LINKS_PER_SPAN);
    framed(SPANS_TAG, &[identity, events, links].concat())
}


fn service_attribute() -> Vec<u8> {
    let value = framed(VALUE_TAG, &framed(STRING_TAG, &[b's'; SERVICE_BYTES]));
    framed(RESOURCE_ATTRIBUTE_TAG, &[framed(KEY_TAG, b"service.name"), value].concat())
}


fn array_attribute() -> Vec<u8> {
    let elements = framed(ARRAY_TAG, &[ELEMENT_TAG, 0].repeat(ARRAY_ELEMENTS));
    framed(RESOURCE_ATTRIBUTE_TAG, &[framed(KEY_TAG, b"k"), framed(VALUE_TAG, &elements)].concat())
}


fn entity_reference() -> Vec<u8> {
    framed(ENTITY_REFS_TAG, &[ID_KEYS_TAG, 0].repeat(KEYS_PER_REFERENCE))
}


fn resource(empty_attributes: usize) -> Vec<u8> {
    let parts = [
        service_attribute(),
        array_attribute(),
        [RESOURCE_ATTRIBUTE_TAG, 0].repeat(empty_attributes),
        entity_reference().repeat(DEFAULT_MAX_ENTITY_REFS_TOTAL),
    ];
    framed(RESOURCE_TAG, &parts.concat())
}


#[test]
fn every_budget_filled_at_once_stays_within_its_budget() -> TestResult {
    let limits = Limits::default();
    let attributes = limits.max_total_attributes - RESERVED_ATTRIBUTES;
    let scope = framed(SCOPE_SPANS_TAG, &span().repeat(SPANS));
    let bytes = framed(RESOURCE_SPANS_TAG, &[resource(attributes), scope].concat());
    reset_high_water()?;
    let before = high_water_kib()?;
    let outcome = decode_traces(&bytes, TENANT, &limits, &Sampling::default(), NOW);
    let growth = high_water_kib()?.saturating_sub(before);
    report(&format!(
        "worst {} bytes: growth {growth} KiB, rows {}, dropped {:?}, refusal {:?}",
        bytes.len(),
        outcome.rows.len(),
        outcome.dropped,
        outcome.refusal
    ))?;
    assert!(outcome.refusal.is_none());
    assert_eq!(outcome.rows.len(), SPANS);
    assert!(growth < BUDGET_KIB, "{growth} KiB");
    Ok(())
}
