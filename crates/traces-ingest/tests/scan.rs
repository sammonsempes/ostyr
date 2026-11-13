mod common;


use common::types::TestResult;
use traces_ingest::decode::decode_traces;
use traces_ingest::model::{Limits, Refusal, Totals};
use traces_ingest::sampling::Sampling;
use traces_ingest::scan::{entry_weight, list_weight, scan_request};


const TENANT: &str = "tenant-a";


const NOW: u64 = 1_700_000_000_000_000_000;


const TWO: usize = 2;


const THREE: usize = 3;


const FIVE: usize = 5;


const SEVEN: usize = 7;


const VALUE: [u8; 2] = [0x12, 0];


const EMPTY_ENTRY: [u8; 2] = [0x0a, 0];


const ONE_VALUE_ENTRY: [u8; 7] = [0x0a, 5, 0x0a, 1, b'k', 0x12, 0];


const TWO_VALUE_ENTRY: [u8; 6] = [0x0a, 4, 0x12, 0, 0x12, 0];


const OTHER_FIELD: [u8; 2] = [0x10, 1];


const LENGTH_PAST_END: [u8; 2] = [0x0a, 0x7f];


const DEEP: usize = 150;


const FOUR: usize = 4;


const DEEP_COUNT: usize = 151;


const RESOURCE_SPANS_TAG: u8 = 0x0a;


const RESOURCE_TAG: u8 = 0x0a;


const RESOURCE_ATTRIBUTE_TAG: u8 = 0x0a;


const SCOPE_SPANS_TAG: u8 = 0x12;


const SCOPE_TAG: u8 = 0x0a;


const SCOPE_ATTRIBUTE_TAG: u8 = 0x1a;


const SPAN_TAG: u8 = 0x12;


const SPAN_ATTRIBUTE_TAG: u8 = 0x4a;


const EVENT_TAG: u8 = 0x5a;


const EVENT_ATTRIBUTE_TAG: u8 = 0x1a;


const LINK_TAG: u8 = 0x6a;


const LINK_ATTRIBUTE_TAG: u8 = 0x22;


const KEY_TAG: u8 = 0x0a;


const VALUE_TAG: u8 = 0x12;


const ARRAY_TAG: u8 = 0x2a;


const KVLIST_TAG: u8 = 0x32;


const ELEMENT_TAG: u8 = 0x0a;


const VARINT_FIELD_FIVE: u8 = 0x28;


const TRUNCATED_LENGTH: u8 = 0x7f;


#[derive(Clone, Copy, Default)]
struct Shape {
    resource_attributes: usize,
    scope_attributes: usize,
    span_attributes: usize,
    events: usize,
    event_attributes: usize,
    links: usize,
    link_attributes: usize,
}


fn framed(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    prost::encoding::encode_varint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}


fn key_value(value: &[u8]) -> Vec<u8> {
    [framed(KEY_TAG, b"k"), framed(VALUE_TAG, value)].concat()
}


fn attributes(tag: u8, count: usize) -> Vec<u8> {
    framed(tag, &key_value(&framed(KEY_TAG, b"v"))).repeat(count)
}


fn owned(owner_tag: u8, attribute_tag: u8, count: usize) -> Vec<u8> {
    if count == 0 {
        Vec::new()
    } else {
        framed(owner_tag, &attributes(attribute_tag, count))
    }
}


fn request(shape: Shape) -> Vec<u8> {
    let events = framed(EVENT_TAG, &attributes(EVENT_ATTRIBUTE_TAG, shape.event_attributes)).repeat(shape.events);
    let links = framed(LINK_TAG, &attributes(LINK_ATTRIBUTE_TAG, shape.link_attributes)).repeat(shape.links);
    let span = framed(SPAN_TAG, &[attributes(SPAN_ATTRIBUTE_TAG, shape.span_attributes), events, links].concat());
    let scope_spans = framed(
        SCOPE_SPANS_TAG,
        &[owned(SCOPE_TAG, SCOPE_ATTRIBUTE_TAG, shape.scope_attributes), span].concat(),
    );
    framed(
        RESOURCE_SPANS_TAG,
        &[owned(RESOURCE_TAG, RESOURCE_ATTRIBUTE_TAG, shape.resource_attributes), scope_spans].concat(),
    )
}


fn run(bytes: &[u8], limits: &Limits) -> Option<Refusal> {
    decode_traces(bytes, TENANT, limits, &Sampling::default(), NOW).refusal
}


fn array_value(elements: usize) -> Vec<u8> {
    framed(ARRAY_TAG, &[ELEMENT_TAG, 0].repeat(elements))
}


fn span_holding(value: &[u8]) -> Vec<u8> {
    let attribute = framed(SPAN_ATTRIBUTE_TAG, &key_value(value));
    let scope_spans = framed(SCOPE_SPANS_TAG, &framed(SPAN_TAG, &attribute));
    framed(RESOURCE_SPANS_TAG, &scope_spans)
}


fn elements_limit(max: usize) -> Limits {
    Limits {
        max_value_elements_total: max,
        ..Limits::default()
    }
}


#[test]
fn the_scan_counts_every_level_of_one_request() -> TestResult {
    let shape = Shape {
        resource_attributes: 1,
        scope_attributes: 1,
        span_attributes: TWO,
        events: 1,
        event_attributes: 1,
        links: 1,
        link_attributes: TWO,
    };
    let totals = scan_request(&request(shape), &Limits::default())?;
    let expected = Totals {
        resources: 1,
        scopes: 1,
        spans: 1,
        events: 1,
        links: 1,
        attributes: SEVEN,
        elements: 0,
        entity_refs: 0,
        entity_keys: 0,
    };
    assert_eq!(totals, expected);
    Ok(())
}


#[test]
fn events_are_capped_at_n_and_n_plus_one() -> TestResult {
    let limits = Limits {
        max_events_total: TWO,
        ..Limits::default()
    };
    let at = Shape {
        events: TWO,
        ..Shape::default()
    };
    let over = Shape {
        events: THREE,
        ..Shape::default()
    };
    assert!(run(&request(at), &limits).is_none());
    assert!(matches!(run(&request(over), &limits), Some(Refusal::TooManyEvents { count: THREE })));
    Ok(())
}


#[test]
fn links_are_capped_at_n_and_n_plus_one() -> TestResult {
    let limits = Limits {
        max_links_total: TWO,
        ..Limits::default()
    };
    let at = Shape {
        links: TWO,
        ..Shape::default()
    };
    let over = Shape {
        links: THREE,
        ..Shape::default()
    };
    assert!(run(&request(at), &limits).is_none());
    assert!(matches!(run(&request(over), &limits), Some(Refusal::TooManyLinks { count: THREE })));
    Ok(())
}


#[test]
fn attributes_are_counted_at_each_of_the_five_owners() -> TestResult {
    let limits = Limits {
        max_total_attributes: 1,
        ..Limits::default()
    };
    let shapes = [
        Shape {
            resource_attributes: TWO,
            ..Shape::default()
        },
        Shape {
            scope_attributes: TWO,
            ..Shape::default()
        },
        Shape {
            span_attributes: TWO,
            ..Shape::default()
        },
        Shape {
            events: 1,
            event_attributes: TWO,
            ..Shape::default()
        },
        Shape {
            links: 1,
            link_attributes: TWO,
            ..Shape::default()
        },
    ];
    shapes.iter().try_for_each(|shape| -> TestResult {
        assert!(matches!(run(&request(*shape), &limits), Some(Refusal::TooManyAttributes { count: TWO })));
        Ok(())
    })?;
    let one_each = Shape {
        resource_attributes: 1,
        scope_attributes: 1,
        span_attributes: 1,
        events: 1,
        event_attributes: 1,
        links: 1,
        link_attributes: 1,
    };
    let five = Limits {
        max_total_attributes: FIVE,
        ..Limits::default()
    };
    assert!(run(&request(one_each), &five).is_none());
    assert!(matches!(
        run(&request(one_each), &limits),
        Some(Refusal::TooManyAttributes { count: FIVE })
    ));
    Ok(())
}


#[test]
fn array_elements_are_capped_at_n_and_n_plus_one() -> TestResult {
    let limits = elements_limit(THREE);
    assert!(run(&span_holding(&array_value(THREE)), &limits).is_none());
    assert!(matches!(
        run(&span_holding(&array_value(THREE + 1)), &limits),
        Some(Refusal::TooManyValueElements { count: FOUR })
    ));
    Ok(())
}


#[test]
fn key_value_list_entries_and_nested_levels_are_counted() -> TestResult {
    let nested_array = framed(ARRAY_TAG, &framed(ELEMENT_TAG, &array_value(TWO)));
    let list = framed(KVLIST_TAG, &framed(ELEMENT_TAG, &framed(VALUE_TAG, &array_value(TWO))));
    let wrong_wire_type = framed(KVLIST_TAG, &[VARINT_FIELD_FIVE, 1]);
    [nested_array, list].iter().try_for_each(|value| -> TestResult {
        let totals = scan_request(&span_holding(value), &elements_limit(THREE))?;
        assert_eq!(totals.elements, THREE);
        assert!(matches!(
            run(&span_holding(value), &elements_limit(TWO)),
            Some(Refusal::TooManyValueElements { count: THREE })
        ));
        Ok(())
    })?;
    assert_eq!(scan_request(&span_holding(&wrong_wire_type), &elements_limit(0))?.elements, 0);
    Ok(())
}


#[test]
fn an_oversized_second_level_is_refused_before_it_is_collected() -> TestResult {
    let wide = framed(ARRAY_TAG, &framed(ELEMENT_TAG, &array_value(DEEP)));
    assert!(matches!(
        run(&span_holding(&wide), &elements_limit(TWO)),
        Some(Refusal::TooManyValueElements { count: DEEP_COUNT })
    ));
    Ok(())
}


#[test]
fn malformed_values_are_refused_at_each_walk() -> TestResult {
    let truncated_container = framed(ARRAY_TAG, &[ELEMENT_TAG]);
    let truncated_value = [ARRAY_TAG];
    let truncated_entry = framed(KVLIST_TAG, &framed(ELEMENT_TAG, &[VALUE_TAG, TRUNCATED_LENGTH]));
    [truncated_container, truncated_value.to_vec(), truncated_entry]
        .iter()
        .try_for_each(|value| -> TestResult {
            assert!(matches!(run(&span_holding(value), &Limits::default()), Some(Refusal::Malformed(_))));
            Ok(())
        })
}


#[test]
fn values_deeper_than_the_decoder_accepts_are_left_to_it() -> TestResult {
    let deepest = (0..DEEP).fold(array_value(0), |inner, _| framed(ARRAY_TAG, &framed(ELEMENT_TAG, &inner)));
    assert!(matches!(run(&span_holding(&deepest), &Limits::default()), Some(Refusal::Malformed(_))));
    Ok(())
}


const UNKNOWN_LENGTH_DELIMITED_TAG: u8 = 0x1a;


const VARINT_TAG: u8 = 0x38;


const CONTINUATION: u8 = 0xff;


const OVERLONG_VARINT: usize = 10;


#[test]
fn other_length_delimited_fields_of_a_container_are_not_elements() -> TestResult {
    let array = framed(ARRAY_TAG, &[UNKNOWN_LENGTH_DELIMITED_TAG, 0, ELEMENT_TAG, 0].repeat(TWO));
    assert_eq!(scan_request(&span_holding(&array), &Limits::default())?.elements, TWO);
    Ok(())
}


#[test]
fn an_overlong_varint_field_is_malformed() -> TestResult {
    let bytes = [&[VARINT_TAG][..], &[CONTINUATION; OVERLONG_VARINT]].concat();
    assert!(matches!(run(&bytes, &Limits::default()), Some(Refusal::Malformed(_))));
    Ok(())
}


#[test]
fn an_event_that_fails_its_scan_fails_the_request() -> TestResult {
    let event = framed(EVENT_TAG, &framed(EVENT_ATTRIBUTE_TAG, &key_value(&array_value(THREE))));
    let bytes = framed(RESOURCE_SPANS_TAG, &framed(SCOPE_SPANS_TAG, &framed(SPAN_TAG, &event)));
    assert!(matches!(
        run(&bytes, &elements_limit(TWO)),
        Some(Refusal::TooManyValueElements { count: THREE })
    ));
    Ok(())
}


const ENTITY_REFS_TAG: u8 = 0x1a;


const ID_KEYS_TAG: u8 = 0x1a;


const DESCRIPTION_KEYS_TAG: u8 = 0x22;


fn resource_holding(resource: &[u8]) -> Vec<u8> {
    framed(RESOURCE_SPANS_TAG, &framed(RESOURCE_TAG, resource))
}


fn entity_ref(keys: &[u8]) -> Vec<u8> {
    framed(ENTITY_REFS_TAG, keys)
}


#[test]
fn entity_refs_are_counted_and_capped_at_n_and_n_plus_one() -> TestResult {
    let limits = Limits {
        max_entity_refs_total: TWO,
        ..Limits::default()
    };
    let at = resource_holding(&entity_ref(&[]).repeat(TWO));
    let over = resource_holding(&entity_ref(&[]).repeat(THREE));
    assert_eq!(scan_request(&at, &limits)?.entity_refs, TWO);
    assert!(matches!(run(&over, &limits), Some(Refusal::TooManyEntityRefs { count: THREE })));
    Ok(())
}


#[test]
fn entity_keys_of_both_kinds_are_counted_and_capped_at_n_and_n_plus_one() -> TestResult {
    let limits = Limits {
        max_entity_keys_total: THREE,
        ..Limits::default()
    };
    let at = resource_holding(&entity_ref(&[[ID_KEYS_TAG, 0].repeat(TWO), vec![DESCRIPTION_KEYS_TAG, 0]].concat()));
    let over = resource_holding(&entity_ref(
        &[[ID_KEYS_TAG, 0].repeat(TWO), [DESCRIPTION_KEYS_TAG, 0].repeat(TWO)].concat(),
    ));
    assert_eq!(scan_request(&at, &limits)?.entity_keys, THREE);
    assert!(matches!(run(&over, &limits), Some(Refusal::TooManyEntityKeys { count: FOUR })));
    Ok(())
}


#[test]
fn entity_keys_add_up_across_references() -> TestResult {
    let two_refs = entity_ref(&[ID_KEYS_TAG, 0]).repeat(TWO);
    let totals = scan_request(&resource_holding(&two_refs), &Limits::default())?;
    assert_eq!((totals.entity_refs, totals.entity_keys), (TWO, TWO));
    Ok(())
}


#[test]
fn a_malformed_entity_reference_is_malformed() -> TestResult {
    [ID_KEYS_TAG, DESCRIPTION_KEYS_TAG].iter().try_for_each(|tag| -> TestResult {
        let broken = resource_holding(&entity_ref(&[*tag, TRUNCATED_LENGTH]));
        assert!(matches!(run(&broken, &Limits::default()), Some(Refusal::Malformed(_))));
        Ok(())
    })?;
    let id_ok_description_broken = resource_holding(&entity_ref(&[ID_KEYS_TAG, 0, DESCRIPTION_KEYS_TAG, TRUNCATED_LENGTH]));
    assert!(matches!(run(&id_ok_description_broken, &Limits::default()), Some(Refusal::Malformed(_))));
    Ok(())
}


#[test]
fn a_list_entry_weighs_its_value_fields_at_least_one() -> TestResult {
    assert_eq!(entry_weight(&[])?, 1);
    assert_eq!(entry_weight(&VALUE)?, 1);
    assert_eq!(entry_weight(&OTHER_FIELD)?, 1);
    assert_eq!(entry_weight(&VALUE.repeat(FIVE))?, FIVE);
    let entries = [EMPTY_ENTRY.to_vec(), ONE_VALUE_ENTRY.to_vec(), TWO_VALUE_ENTRY.to_vec()].concat();
    assert_eq!(list_weight(&entries)?, 1 + 1 + TWO);
    assert_eq!(list_weight(&OTHER_FIELD)?, 0);
    assert_eq!(list_weight(&VALUE)?, 0);
    assert!(list_weight(&LENGTH_PAST_END).is_err());
    Ok(())
}
