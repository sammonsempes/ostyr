use crate::common::types::TestResult;
use crate::memory_support::{framed, high_water_kib, report, reset_high_water, NOW, RESOURCE_SPANS_TAG, SCOPE_SPANS_TAG, SPANS_TAG, TENANT};
use traces_ingest::decode::decode_traces;
use traces_ingest::model::Limits;
use traces_ingest::sampling::Sampling;


pub const DEFAULT_BUDGET_KIB: u64 = 102_400;


const ID_BYTES: usize = 8;


const SPAN_ATTRIBUTE_TAG: u8 = 0x4a;


const KEYS_PER_REFERENCE: usize = 4;


const ARRAY_MARGIN: usize = 1_000;


const RESOURCE_TAG: u8 = 0x0a;


const RESOURCE_ATTRIBUTE_TAG: u8 = 0x0a;


const ENTITY_REFS_TAG: u8 = 0x1a;


const ID_KEYS_TAG: u8 = 0x1a;


const EVENT_TAG: u8 = 0x5a;


const LINK_TAG: u8 = 0x6a;


const EVENT_ATTRIBUTE_TAG: u8 = 0x1a;


const LINK_ATTRIBUTE_TAG: u8 = 0x22;


const TRACE_ID_TAG: u8 = 0x0a;


const SPAN_ID_TAG: u8 = 0x12;


const KEY_TAG: u8 = 0x0a;


const VALUE_TAG: u8 = 0x12;


const STRING_TAG: u8 = 0x0a;


const ARRAY_TAG: u8 = 0x2a;


const ELEMENT_TAG: u8 = 0x0a;


const TRACE_ID_BYTES: usize = 16;


const RESERVED_ATTRIBUTES: usize = 2;


const KEYED_NAMES: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];


#[derive(Clone, Copy)]
struct Shape {
    attributes: usize,
    events: usize,
    links: usize,
    inner: usize,
}


fn keyed_attribute(name: &[u8]) -> Vec<u8> {
    framed(SPAN_ATTRIBUTE_TAG, &[framed(KEY_TAG, name), framed(VALUE_TAG, &[STRING_TAG, 0])].concat())
}


fn inner_attributes(tag: u8, count: usize) -> Vec<u8> {
    let attribute = framed(tag, &[framed(KEY_TAG, b"a"), framed(VALUE_TAG, &[STRING_TAG, 0])].concat());
    attribute.repeat(count)
}


fn nested(tag: u8, attribute_tag: u8, shape: Shape) -> Vec<u8> {
    framed(tag, &inner_attributes(attribute_tag, shape.inner)).repeat(match tag {
        EVENT_TAG => shape.events,
        _ => shape.links,
    })
}


fn span(shape: Shape) -> Vec<u8> {
    let identity = [framed(TRACE_ID_TAG, &[1; TRACE_ID_BYTES]), framed(SPAN_ID_TAG, &[1; ID_BYTES])].concat();
    let attributes: Vec<u8> = KEYED_NAMES.iter().take(shape.attributes).flat_map(|name| keyed_attribute(name)).collect();
    let events = nested(EVENT_TAG, EVENT_ATTRIBUTE_TAG, shape);
    let links = nested(LINK_TAG, LINK_ATTRIBUTE_TAG, shape);
    framed(SPANS_TAG, &[identity, attributes, events, links].concat())
}


fn service_attribute(limits: &Limits) -> Vec<u8> {
    let value = framed(VALUE_TAG, &framed(STRING_TAG, &vec![b's'; limits.max_name_bytes]));
    framed(RESOURCE_ATTRIBUTE_TAG, &[framed(KEY_TAG, b"service.name"), value].concat())
}


fn array_attribute(limits: &Limits) -> Vec<u8> {
    let elements = framed(ARRAY_TAG, &[ELEMENT_TAG, 0].repeat(limits.max_value_elements_total - ARRAY_MARGIN));
    framed(RESOURCE_ATTRIBUTE_TAG, &[framed(KEY_TAG, b"k"), framed(VALUE_TAG, &elements)].concat())
}


fn entity_reference() -> Vec<u8> {
    framed(ENTITY_REFS_TAG, &[ID_KEYS_TAG, 0].repeat(KEYS_PER_REFERENCE))
}


fn resource(limits: &Limits, empty_attributes: usize) -> Vec<u8> {
    let parts = [
        service_attribute(limits),
        array_attribute(limits),
        [RESOURCE_ATTRIBUTE_TAG, 0].repeat(empty_attributes),
        entity_reference().repeat(limits.max_entity_refs_total),
    ];
    framed(RESOURCE_TAG, &parts.concat())
}


pub fn check(limits: &Limits, budget_kib: u64, attributes: usize, events: usize, links: usize, inner: usize) -> TestResult {
    let shape = &Shape {
        attributes,
        events,
        links,
        inner,
    };
    {
        let budget = limits.max_total_attributes - RESERVED_ATTRIBUTES;
        let per_span = shape.attributes + (shape.events + shape.links) * shape.inner;
        let spans = (limits.max_spans - 1).min(budget.checked_div(per_span).unwrap_or(limits.max_spans - 1));
        let empty = budget - spans * per_span;
        let scope = framed(SCOPE_SPANS_TAG, &span(*shape).repeat(spans));
        let bytes = framed(RESOURCE_SPANS_TAG, &[resource(limits, empty), scope].concat());
        reset_high_water()?;
        let before = high_water_kib()?;
        let outcome = decode_traces(&bytes, TENANT, limits, &Sampling::default(), NOW);
        let growth = high_water_kib()?.saturating_sub(before);
        report(&format!(
            "shape {} attributes {} events {} links {} inner: {} bytes, growth {growth} KiB, rows {}, refusal {:?}",
            shape.attributes,
            shape.events,
            shape.links,
            shape.inner,
            bytes.len(),
            outcome.rows.len(),
            outcome.refusal
        ))?;
        assert!(outcome.refusal.is_none());
        assert!(growth < budget_kib, "{growth} KiB");
        Ok(())
    }
}
