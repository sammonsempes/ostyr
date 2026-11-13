use crate::memory_support::{framed, NOW, RESOURCE_SPANS_TAG, SCOPE_SPANS_TAG, SPANS_TAG};
use traces_ingest::model::Limits;


const ID_BYTES: usize = 8;


const SPAN_ATTRIBUTE_TAG: u8 = 0x4a;


const KEYS_PER_REFERENCE: usize = 4;


const ARRAY_MARGIN: usize = 1_000;


const START_TAG: u8 = 0x39;


const END_TAG: u8 = 0x41;


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
pub struct Shape {
    pub attributes: usize,
    pub events: usize,
    pub links: usize,
    pub inner: usize,
    pub fill: u8,
    pub timed: bool,
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


fn timing(shape: Shape) -> Vec<u8> {
    if shape.timed {
        [&[START_TAG][..], &NOW.to_le_bytes(), &[END_TAG], &(NOW + 1).to_le_bytes()].concat()
    } else {
        Vec::new()
    }
}


fn span(shape: Shape) -> Vec<u8> {
    let identity = [
        framed(TRACE_ID_TAG, &[1; TRACE_ID_BYTES]),
        framed(SPAN_ID_TAG, &[1; ID_BYTES]),
        timing(shape),
    ]
    .concat();
    let attributes: Vec<u8> = KEYED_NAMES.iter().take(shape.attributes).flat_map(|name| keyed_attribute(name)).collect();
    let events = nested(EVENT_TAG, EVENT_ATTRIBUTE_TAG, shape);
    let links = nested(LINK_TAG, LINK_ATTRIBUTE_TAG, shape);
    framed(SPANS_TAG, &[identity, attributes, events, links].concat())
}


fn service_attribute(limits: &Limits, fill: u8) -> Vec<u8> {
    let value = framed(VALUE_TAG, &framed(STRING_TAG, &vec![fill; limits.max_name_bytes]));
    framed(RESOURCE_ATTRIBUTE_TAG, &[framed(KEY_TAG, b"service.name"), value].concat())
}


fn array_attribute(limits: &Limits) -> Vec<u8> {
    let elements = framed(ARRAY_TAG, &[ELEMENT_TAG, 0].repeat(limits.max_value_elements_total - ARRAY_MARGIN));
    framed(RESOURCE_ATTRIBUTE_TAG, &[framed(KEY_TAG, b"k"), framed(VALUE_TAG, &elements)].concat())
}


fn entity_reference() -> Vec<u8> {
    framed(ENTITY_REFS_TAG, &[ID_KEYS_TAG, 0].repeat(KEYS_PER_REFERENCE))
}


fn resource(limits: &Limits, empty_attributes: usize, fill: u8) -> Vec<u8> {
    let parts = [
        service_attribute(limits, fill),
        array_attribute(limits),
        [RESOURCE_ATTRIBUTE_TAG, 0].repeat(empty_attributes),
        entity_reference().repeat(limits.max_entity_refs_total),
    ];
    framed(RESOURCE_TAG, &parts.concat())
}


/// The worst accepted request for `shape` at `limits`: one resource, one scope, the whole span and attribute budget used.
pub fn build_request(limits: &Limits, shape: Shape) -> Vec<u8> {
    let budget = limits.max_total_attributes - RESERVED_ATTRIBUTES;
    let per_span = shape.attributes + (shape.events + shape.links) * shape.inner;
    let spans = (limits.max_spans - 1).min(budget.checked_div(per_span).unwrap_or(limits.max_spans - 1));
    let empty = budget - spans * per_span;
    let scope = framed(SCOPE_SPANS_TAG, &span(shape).repeat(spans));
    framed(RESOURCE_SPANS_TAG, &[resource(limits, empty, shape.fill), scope].concat())
}
