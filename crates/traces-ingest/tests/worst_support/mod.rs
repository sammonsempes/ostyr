use crate::common::types::TestResult;
use crate::memory_support::{framed, high_water_kib, report, reset_high_water, NOW, RESOURCE_SPANS_TAG, SCOPE_SPANS_TAG, SPANS_TAG, TENANT};
use traces_ingest::decode::decode_traces;
use traces_ingest::model::{Limits, DEFAULT_MAX_ENTITY_REFS_TOTAL, DEFAULT_MAX_SPANS};
use traces_ingest::sampling::Sampling;


const BUDGET_KIB: u64 = 102_400;


const ID_BYTES: usize = 8;


const SERVICE_BYTES: usize = 256;


const SPAN_ATTRIBUTE_TAG: u8 = 0x4a;


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


const KEYED_NAMES: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];


#[derive(Clone, Copy)]
struct Shape {
    attributes: usize,
    events: usize,
    links: usize,
}


fn keyed_attribute(name: &[u8]) -> Vec<u8> {
    framed(SPAN_ATTRIBUTE_TAG, &[framed(KEY_TAG, name), framed(VALUE_TAG, &[STRING_TAG, 0])].concat())
}


fn span(shape: Shape) -> Vec<u8> {
    let identity = [framed(TRACE_ID_TAG, &[1; TRACE_ID_BYTES]), framed(SPAN_ID_TAG, &[1; ID_BYTES])].concat();
    let attributes: Vec<u8> = KEYED_NAMES.iter().take(shape.attributes).flat_map(|name| keyed_attribute(name)).collect();
    let events = [EVENT_TAG, 0].repeat(shape.events);
    let links = [LINK_TAG, 0].repeat(shape.links);
    framed(SPANS_TAG, &[identity, attributes, events, links].concat())
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


pub fn check(attributes: usize, events: usize, links: usize) -> TestResult {
    let shape = &Shape { attributes, events, links };
    let limits = Limits::default();
    {
        let budget = limits.max_total_attributes - RESERVED_ATTRIBUTES;
        let spans = SPANS.min(budget.checked_div(shape.attributes).unwrap_or(SPANS));
        let empty = budget - spans * shape.attributes;
        let scope = framed(SCOPE_SPANS_TAG, &span(*shape).repeat(spans));
        let bytes = framed(RESOURCE_SPANS_TAG, &[resource(empty), scope].concat());
        reset_high_water()?;
        let before = high_water_kib()?;
        let outcome = decode_traces(&bytes, TENANT, &limits, &Sampling::default(), NOW);
        let growth = high_water_kib()?.saturating_sub(before);
        report(&format!(
            "shape {} attributes {} events {} links: {} bytes, growth {growth} KiB, rows {}, refusal {:?}",
            shape.attributes,
            shape.events,
            shape.links,
            bytes.len(),
            outcome.rows.len(),
            outcome.refusal
        ))?;
        assert!(outcome.refusal.is_none());
        assert!(growth < BUDGET_KIB, "{growth} KiB");
        Ok(())
    }
}
