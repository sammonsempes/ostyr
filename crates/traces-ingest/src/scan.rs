use crate::model::{Limits, Refusal, Totals};
use crate::types::WireField;
use prost::encoding::{decode_key, decode_varint, skip_field, DecodeContext, WireType};
use prost::DecodeError;


pub const RESOURCE_SPANS_FIELD: u32 = 1;


pub const RESOURCE_FIELD: u32 = 1;


pub const RESOURCE_ATTRIBUTES_FIELD: u32 = 1;


pub const RESOURCE_ENTITY_REFS_FIELD: u32 = 3;


pub const ENTITY_ID_KEYS_FIELD: u32 = 3;


pub const ENTITY_DESCRIPTION_KEYS_FIELD: u32 = 4;


pub const SCOPE_SPANS_FIELD: u32 = 2;


pub const SCOPE_FIELD: u32 = 1;


pub const SCOPE_ATTRIBUTES_FIELD: u32 = 3;


pub const SPANS_FIELD: u32 = 2;


pub const SPAN_ATTRIBUTES_FIELD: u32 = 9;


pub const SPAN_EVENTS_FIELD: u32 = 11;


pub const SPAN_LINKS_FIELD: u32 = 13;


pub const EVENT_ATTRIBUTES_FIELD: u32 = 3;


pub const LINK_ATTRIBUTES_FIELD: u32 = 4;


pub const KEY_VALUE_VALUE_FIELD: u32 = 2;


pub const ANY_ARRAY_FIELD: u32 = 5;


pub const ANY_KVLIST_FIELD: u32 = 6;


pub const ELEMENTS_FIELD: u32 = 1;


pub const MAX_VALUE_DEPTH: usize = 100;


pub fn read_field<'a>(buf: &mut &'a [u8]) -> WireField<'a> {
    let (tag, wire_type) = decode_key(buf)?;
    let context = DecodeContext::default();
    if wire_type == WireType::LengthDelimited {
        let mut peek = *buf;
        let declared = decode_varint(&mut peek)?;
        skip_field(wire_type, tag, buf, context)?;
        Ok((tag, usize::try_from(declared).ok().and_then(|size| peek.get(..size))))
    } else {
        skip_field(wire_type, tag, buf, context)?;
        Ok((tag, None))
    }
}


/// The fields of one message, in order; each step consumes at least one byte, so the walk ends with the buffer.
pub fn fields(bytes: &[u8]) -> impl Iterator<Item = WireField<'_>> {
    let mut rest = bytes;
    std::iter::from_fn(move || if rest.is_empty() { None } else { Some(read_field(&mut rest)) })
}


/// Calls `visit` on the payload of every length-delimited field `tag` of one message.
pub fn for_each_nested(bytes: &[u8], tag: u32, visit: &mut dyn FnMut(&[u8]) -> Result<(), Refusal>) -> Result<(), Refusal> {
    fields(bytes).try_for_each(|field| {
        let (found, payload) = field?;
        match payload {
            Some(nested) if found == tag => visit(nested),
            _ => Ok(()),
        }
    })
}


pub fn nested_payloads(bytes: &[u8], tag: u32) -> Result<Vec<&[u8]>, DecodeError> {
    fields(bytes).try_fold(Vec::new(), |mut found, field| {
        let (current, payload) = field?;
        if let Some(nested) = payload.filter(|_| current == tag) {
            found.push(nested);
        }
        Ok(found)
    })
}


pub fn count_nested(bytes: &[u8], tag: u32) -> Result<usize, DecodeError> {
    fields(bytes).try_fold(usize::default(), |total, field| {
        let (current, payload) = field?;
        Ok(if payload.is_some() && current == tag {
            total.saturating_add(1)
        } else {
            total
        })
    })
}


/// Elements of the array or key-value list held by one `AnyValue`, counted without decoding.
pub fn container_elements(value: &[u8]) -> Result<usize, DecodeError> {
    fields(value).try_fold(usize::default(), |total, field| {
        let (tag, payload) = field?;
        match payload {
            Some(container) if tag == ANY_ARRAY_FIELD || tag == ANY_KVLIST_FIELD => {
                count_nested(container, ELEMENTS_FIELD).map(|count| total.saturating_add(count))
            }
            _ => Ok(total),
        }
    })
}


/// The `AnyValue`s one level below `value`: array elements, and the value of every key-value list entry.
pub fn children_of(value: &[u8]) -> Result<Vec<&[u8]>, DecodeError> {
    fields(value).try_fold(Vec::new(), |mut children, field| {
        let (tag, payload) = field?;
        match payload {
            Some(array) if tag == ANY_ARRAY_FIELD => children.extend(nested_payloads(array, ELEMENTS_FIELD)?),
            Some(list) if tag == ANY_KVLIST_FIELD => {
                for entry in nested_payloads(list, ELEMENTS_FIELD)? {
                    children.extend(nested_payloads(entry, KEY_VALUE_VALUE_FIELD)?);
                }
            }
            _ => {}
        }
        Ok(children)
    })
}


/// Counts one level of nested values and refuses over the cap before collecting the children, so a level never exceeds the cap.
pub fn next_level<'a>(level: &[&'a [u8]], totals: &mut Totals, limits: &Limits) -> Result<Vec<&'a [u8]>, Refusal> {
    let added = level.iter().try_fold(usize::default(), |sum, value| {
        container_elements(value).map(|count| sum.saturating_add(count))
    })?;
    totals.elements = totals.elements.saturating_add(added);
    if totals.elements > limits.max_value_elements_total {
        Err(Refusal::TooManyValueElements { count: totals.elements })
    } else {
        let mut children = Vec::new();
        for value in level {
            children.extend(children_of(value)?);
        }
        Ok(children)
    }
}


/// Walks the arrays and key-value lists of one value level by level, no recursion, to the depth prost accepts.
pub fn scan_value(value: &[u8], totals: &mut Totals, limits: &Limits) -> Result<(), Refusal> {
    let levels = std::iter::successors(Some(Ok(vec![value])), |previous| match previous {
        Ok(level) if !level.is_empty() => Some(next_level(level, totals, limits)),
        _ => None,
    });
    levels.take(MAX_VALUE_DEPTH).try_for_each(|level| level.map(|_| ()))
}


pub fn scan_attributes(owner: &[u8], tag: u32, totals: &mut Totals, limits: &Limits) -> Result<(), Refusal> {
    for_each_nested(owner, tag, &mut |pair| {
        totals.attributes = totals.attributes.saturating_add(1);
        for_each_nested(pair, KEY_VALUE_VALUE_FIELD, &mut |value| scan_value(value, totals, limits))
    })
}


pub fn scan_entity_refs(resource: &[u8], totals: &mut Totals) -> Result<(), Refusal> {
    for_each_nested(resource, RESOURCE_ENTITY_REFS_FIELD, &mut |entity_ref| {
        totals.entity_refs = totals.entity_refs.saturating_add(1);
        let keys = count_nested(entity_ref, ENTITY_ID_KEYS_FIELD)?.saturating_add(count_nested(entity_ref, ENTITY_DESCRIPTION_KEYS_FIELD)?);
        totals.entity_keys = totals.entity_keys.saturating_add(keys);
        Ok(())
    })
}


pub fn scan_span(span: &[u8], totals: &mut Totals, limits: &Limits) -> Result<(), Refusal> {
    totals.spans = totals.spans.saturating_add(1);
    scan_attributes(span, SPAN_ATTRIBUTES_FIELD, totals, limits)?;
    for_each_nested(span, SPAN_EVENTS_FIELD, &mut |event| {
        totals.events = totals.events.saturating_add(1);
        scan_attributes(event, EVENT_ATTRIBUTES_FIELD, totals, limits)
    })?;
    for_each_nested(span, SPAN_LINKS_FIELD, &mut |link| {
        totals.links = totals.links.saturating_add(1);
        scan_attributes(link, LINK_ATTRIBUTES_FIELD, totals, limits)
    })
}


pub fn scan_scope(scope: &[u8], totals: &mut Totals, limits: &Limits) -> Result<(), Refusal> {
    totals.scopes = totals.scopes.saturating_add(1);
    for_each_nested(scope, SCOPE_FIELD, &mut |described| {
        scan_attributes(described, SCOPE_ATTRIBUTES_FIELD, totals, limits)
    })?;
    for_each_nested(scope, SPANS_FIELD, &mut |span| scan_span(span, totals, limits))
}


pub fn scan_resource_spans(resource_spans: &[u8], totals: &mut Totals, limits: &Limits) -> Result<(), Refusal> {
    totals.resources = totals.resources.saturating_add(1);
    for_each_nested(resource_spans, RESOURCE_FIELD, &mut |described| {
        scan_attributes(described, RESOURCE_ATTRIBUTES_FIELD, totals, limits)?;
        scan_entity_refs(described, totals)
    })?;
    for_each_nested(resource_spans, SCOPE_SPANS_FIELD, &mut |scope| scan_scope(scope, totals, limits))
}


pub fn check_totals(totals: &Totals, limits: &Limits) -> Result<(), Refusal> {
    let widest = totals.scopes.max(totals.spans);
    if totals.resources > limits.max_resource_spans {
        Err(Refusal::TooManyResourceSpans { count: totals.resources })
    } else if widest > limits.max_spans {
        Err(Refusal::TooManySpans { count: widest })
    } else if totals.events > limits.max_events_total {
        Err(Refusal::TooManyEvents { count: totals.events })
    } else if totals.links > limits.max_links_total {
        Err(Refusal::TooManyLinks { count: totals.links })
    } else if totals.attributes > limits.max_total_attributes {
        Err(Refusal::TooManyAttributes { count: totals.attributes })
    } else if totals.entity_refs > limits.max_entity_refs_total {
        Err(Refusal::TooManyEntityRefs { count: totals.entity_refs })
    } else if totals.entity_keys > limits.max_entity_keys_total {
        Err(Refusal::TooManyEntityKeys { count: totals.entity_keys })
    } else {
        Ok(())
    }
}


/// Counts every repeated field prost would allocate for (the whole message tree is checked) on the wire, then refuses.
pub fn scan_request(bytes: &[u8], limits: &Limits) -> Result<Totals, Refusal> {
    let mut totals = Totals::default();
    for_each_nested(bytes, RESOURCE_SPANS_FIELD, &mut |resource_spans| {
        scan_resource_spans(resource_spans, &mut totals, limits)
    })?;
    check_totals(&totals, limits)?;
    Ok(totals)
}
