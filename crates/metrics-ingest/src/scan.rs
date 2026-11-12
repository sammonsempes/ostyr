use crate::model::{Limits, PointKind, Refusal, Totals};
use crate::types::WireField;
use prost::encoding::{decode_key, decode_varint, skip_field, DecodeContext, WireType};
use prost::DecodeError;


pub const RESOURCE_METRICS_FIELD: u32 = 1;


pub const RESOURCE_FIELD: u32 = 1;


pub const RESOURCE_ATTRIBUTES_FIELD: u32 = 1;


pub const RESOURCE_ENTITY_REFS_FIELD: u32 = 3;


pub const ENTITY_ID_KEYS_FIELD: u32 = 3;


pub const ENTITY_DESCRIPTION_KEYS_FIELD: u32 = 4;


pub const SCOPE_METRICS_FIELD: u32 = 2;


pub const SCOPE_FIELD: u32 = 1;


pub const SCOPE_ATTRIBUTES_FIELD: u32 = 3;


pub const METRICS_FIELD: u32 = 2;


pub const METRIC_METADATA_FIELD: u32 = 12;


pub const DATA_POINTS_FIELD: u32 = 1;


pub const EXEMPLAR_ATTRIBUTES_FIELD: u32 = 7;


pub const KEY_VALUE_VALUE_FIELD: u32 = 2;


pub const ANY_ARRAY_FIELD: u32 = 5;


pub const ANY_KVLIST_FIELD: u32 = 6;


pub const ELEMENTS_FIELD: u32 = 1;


pub const MAX_VALUE_DEPTH: usize = 100;


pub const KIND_COUNT: usize = 5;


pub const GAUGE_KIND: PointKind = PointKind {
    data_field: 5,
    attributes_field: 7,
    extras_field: 5,
};


pub const SUM_KIND: PointKind = PointKind {
    data_field: 7,
    attributes_field: 7,
    extras_field: 5,
};


pub const HISTOGRAM_KIND: PointKind = PointKind {
    data_field: 9,
    attributes_field: 9,
    extras_field: 8,
};


pub const EXPONENTIAL_KIND: PointKind = PointKind {
    data_field: 10,
    attributes_field: 1,
    extras_field: 11,
};


pub const SUMMARY_KIND: PointKind = PointKind {
    data_field: 11,
    attributes_field: 7,
    extras_field: 6,
};


pub const POINT_KINDS: [PointKind; KIND_COUNT] = [GAUGE_KIND, SUM_KIND, HISTOGRAM_KIND, EXPONENTIAL_KIND, SUMMARY_KIND];


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
    totals.attributes = totals.attributes.saturating_add(added);
    if totals.attributes > limits.max_total_attributes {
        Err(Refusal::TooManyAttributes { count: totals.attributes })
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
        let keys = count_nested(entity_ref, ENTITY_ID_KEYS_FIELD)?.saturating_add(count_nested(entity_ref, ENTITY_DESCRIPTION_KEYS_FIELD)?);
        totals.attributes = totals.attributes.saturating_add(keys).saturating_add(1);
        Ok(())
    })
}


pub fn scan_point(point: &[u8], kind: &PointKind, totals: &mut Totals, limits: &Limits) -> Result<(), Refusal> {
    totals.points = totals.points.saturating_add(1);
    scan_attributes(point, kind.attributes_field, totals, limits)?;
    for_each_nested(point, kind.extras_field, &mut |extra| {
        totals.extras = totals.extras.saturating_add(1);
        scan_attributes(extra, EXEMPLAR_ATTRIBUTES_FIELD, totals, limits)
    })
}


/// A metric counts as at least one data point, whether its data is absent or holds no points.
pub fn scan_metric(metric: &[u8], totals: &mut Totals, limits: &Limits) -> Result<(), Refusal> {
    let before = totals.points;
    scan_attributes(metric, METRIC_METADATA_FIELD, totals, limits)?;
    POINT_KINDS.iter().try_for_each(|kind| {
        for_each_nested(metric, kind.data_field, &mut |container| {
            for_each_nested(container, DATA_POINTS_FIELD, &mut |point| scan_point(point, kind, totals, limits))
        })
    })?;
    if totals.points == before {
        totals.points = totals.points.saturating_add(1);
    }
    Ok(())
}


pub fn scan_scope(scope: &[u8], totals: &mut Totals, limits: &Limits) -> Result<(), Refusal> {
    totals.scopes = totals.scopes.saturating_add(1);
    for_each_nested(scope, SCOPE_FIELD, &mut |described| {
        scan_attributes(described, SCOPE_ATTRIBUTES_FIELD, totals, limits)
    })?;
    for_each_nested(scope, METRICS_FIELD, &mut |metric| scan_metric(metric, totals, limits))
}


pub fn scan_resource_metrics(resource_metrics: &[u8], totals: &mut Totals, limits: &Limits) -> Result<(), Refusal> {
    totals.resources = totals.resources.saturating_add(1);
    for_each_nested(resource_metrics, RESOURCE_FIELD, &mut |described| {
        scan_attributes(described, RESOURCE_ATTRIBUTES_FIELD, totals, limits)?;
        scan_entity_refs(described, totals)
    })?;
    for_each_nested(resource_metrics, SCOPE_METRICS_FIELD, &mut |scope| scan_scope(scope, totals, limits))
}


pub fn check_totals(totals: &Totals, limits: &Limits) -> Result<(), Refusal> {
    let widest = totals.scopes.max(totals.extras);
    if totals.resources > limits.max_resources {
        Err(Refusal::TooManyResources { count: totals.resources })
    } else if totals.points > limits.max_data_points {
        Err(Refusal::TooManyDataPoints { count: totals.points })
    } else if widest > limits.max_data_points {
        Err(Refusal::TooManyDataPoints { count: widest })
    } else if totals.attributes > limits.max_total_attributes {
        Err(Refusal::TooManyAttributes { count: totals.attributes })
    } else {
        Ok(())
    }
}


/// Counts every repeated field prost would allocate for on the wire, then refuses; nothing is decoded.
pub fn scan_request(bytes: &[u8], limits: &Limits) -> Result<Totals, Refusal> {
    let mut totals = Totals::default();
    for_each_nested(bytes, RESOURCE_METRICS_FIELD, &mut |resource_metrics| {
        scan_resource_metrics(resource_metrics, &mut totals, limits)
    })?;
    check_totals(&totals, limits)?;
    Ok(totals)
}
