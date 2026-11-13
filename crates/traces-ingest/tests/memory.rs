mod common;
mod memory_support;


use common::types::TestResult;
use memory_support::{framed, high_water_kib, report, reset_high_water, NOW, RESOURCE_SPANS_TAG, SCOPE_SPANS_TAG, SPANS_TAG, TENANT};
use traces_ingest::decode::decode_traces;
use traces_ingest::model::Limits;
use traces_ingest::sampling::Sampling;


struct Attack {
    name: &'static str,
    build: fn() -> Vec<u8>,
    expected: &'static str,
}


const EMPTY_FIELD_BYTES: usize = 2;


const BUDGET_KIB: u64 = 1_024;


const FOUR_MEBIBYTES: usize = 4_194_304;


const FRAMING_SLACK: usize = 16;


const TWO_BYTE_SCOPE: usize = 4;


const LENGTH_CONTINUATION: u8 = 0x80;


const HUGE_LENGTH: u8 = 0x7f;


const RESOURCE_TAG: u8 = 0x0a;


const RESOURCE_ATTRIBUTE_TAG: u8 = 0x0a;


const EVENT_TAG: u8 = 0x5a;


const EVENT_ATTRIBUTE_TAG: u8 = 0x1a;


const LINK_TAG: u8 = 0x6a;


const LINK_ATTRIBUTE_TAG: u8 = 0x22;


const VALUE_TAG: u8 = 0x12;


const ARRAY_TAG: u8 = 0x2a;


const KVLIST_TAG: u8 = 0x32;


const ELEMENT_TAG: u8 = 0x0a;


const ATTRIBUTE_FIELD: u8 = 0x4a;


const ENTITY_REFS_TAG: u8 = 0x1a;


const ID_KEYS_TAG: u8 = 0x1a;


const DESCRIPTION_KEYS_TAG: u8 = 0x22;


fn many() -> usize {
    FOUR_MEBIBYTES / EMPTY_FIELD_BYTES - FRAMING_SLACK
}


fn in_span(parts: &[u8]) -> Vec<u8> {
    framed(RESOURCE_SPANS_TAG, &framed(SCOPE_SPANS_TAG, &framed(SPANS_TAG, parts)))
}


fn empty_fields(tag: u8) -> Vec<u8> {
    [tag, 0].repeat(many())
}


fn held_value(value_field: &[u8]) -> Vec<u8> {
    in_span(&framed(ATTRIBUTE_FIELD, &framed(VALUE_TAG, value_field)))
}


fn empty_spans() -> Vec<u8> {
    framed(RESOURCE_SPANS_TAG, &framed(SCOPE_SPANS_TAG, &empty_fields(SPANS_TAG)))
}


fn empty_resource_spans() -> Vec<u8> {
    empty_fields(RESOURCE_SPANS_TAG)
}


fn scopes_with_one_span() -> Vec<u8> {
    let scope = framed(SCOPE_SPANS_TAG, &[SPANS_TAG, 0]);
    framed(RESOURCE_SPANS_TAG, &scope.repeat(FOUR_MEBIBYTES / TWO_BYTE_SCOPE - FRAMING_SLACK))
}


fn empty_scopes() -> Vec<u8> {
    framed(RESOURCE_SPANS_TAG, &empty_fields(SCOPE_SPANS_TAG))
}


fn truncated_length() -> Vec<u8> {
    vec![RESOURCE_SPANS_TAG, LENGTH_CONTINUATION]
}


fn length_over_the_rest() -> Vec<u8> {
    vec![RESOURCE_SPANS_TAG, HUGE_LENGTH, SCOPE_SPANS_TAG]
}


fn empty_links() -> Vec<u8> {
    in_span(&empty_fields(LINK_TAG))
}


fn empty_events() -> Vec<u8> {
    in_span(&empty_fields(EVENT_TAG))
}


fn span_attributes() -> Vec<u8> {
    in_span(&empty_fields(ATTRIBUTE_FIELD))
}


fn resource_attributes() -> Vec<u8> {
    framed(RESOURCE_SPANS_TAG, &framed(RESOURCE_TAG, &empty_fields(RESOURCE_ATTRIBUTE_TAG)))
}


fn event_attributes() -> Vec<u8> {
    in_span(&framed(EVENT_TAG, &empty_fields(EVENT_ATTRIBUTE_TAG)))
}


fn link_attributes() -> Vec<u8> {
    in_span(&framed(LINK_TAG, &empty_fields(LINK_ATTRIBUTE_TAG)))
}


fn empty_entries() -> Vec<u8> {
    held_value(&framed(KVLIST_TAG, &empty_fields(ELEMENT_TAG)))
}


fn duplicate_values() -> Vec<u8> {
    [VALUE_TAG, 0].repeat(many() - FRAMING_SLACK)
}


fn duplicate_entry_values() -> Vec<u8> {
    held_value(&framed(KVLIST_TAG, &framed(ELEMENT_TAG, &duplicate_values())))
}


fn duplicate_attribute_values() -> Vec<u8> {
    in_span(&framed(ATTRIBUTE_FIELD, &duplicate_values()))
}


fn empty_values() -> Vec<u8> {
    held_value(&framed(ARRAY_TAG, &empty_fields(ELEMENT_TAG)))
}


fn empty_entity_refs() -> Vec<u8> {
    framed(RESOURCE_SPANS_TAG, &framed(RESOURCE_TAG, &empty_fields(ENTITY_REFS_TAG)))
}


fn empty_id_keys() -> Vec<u8> {
    framed(
        RESOURCE_SPANS_TAG,
        &framed(RESOURCE_TAG, &framed(ENTITY_REFS_TAG, &empty_fields(ID_KEYS_TAG))),
    )
}


fn empty_description_keys() -> Vec<u8> {
    framed(
        RESOURCE_SPANS_TAG,
        &framed(RESOURCE_TAG, &framed(ENTITY_REFS_TAG, &empty_fields(DESCRIPTION_KEYS_TAG))),
    )
}


fn attacks() -> Vec<Attack> {
    vec![
        Attack {
            name: "empty spans",
            build: empty_spans,
            expected: "TooManySpans",
        },
        Attack {
            name: "empty resource spans",
            build: empty_resource_spans,
            expected: "TooManyResourceSpans",
        },
        Attack {
            name: "scopes with one span each",
            build: scopes_with_one_span,
            expected: "TooManySpans",
        },
        Attack {
            name: "empty scopes",
            build: empty_scopes,
            expected: "TooManySpans",
        },
        Attack {
            name: "truncated length",
            build: truncated_length,
            expected: "Malformed",
        },
        Attack {
            name: "length over the rest",
            build: length_over_the_rest,
            expected: "Malformed",
        },
        Attack {
            name: "empty links",
            build: empty_links,
            expected: "TooManyLinks",
        },
        Attack {
            name: "empty events",
            build: empty_events,
            expected: "TooManyEvents",
        },
        Attack {
            name: "span attributes",
            build: span_attributes,
            expected: "TooManyAttributes",
        },
        Attack {
            name: "resource attributes",
            build: resource_attributes,
            expected: "TooManyAttributes",
        },
        Attack {
            name: "event attributes",
            build: event_attributes,
            expected: "TooManyAttributes",
        },
        Attack {
            name: "link attributes",
            build: link_attributes,
            expected: "TooManyAttributes",
        },
        Attack {
            name: "empty key-value entries",
            build: empty_entries,
            expected: "TooManyValueElements",
        },
        Attack {
            name: "one list entry with duplicate value fields",
            build: duplicate_entry_values,
            expected: "TooManyValueElements",
        },
        Attack {
            name: "one attribute with duplicate value fields",
            build: duplicate_attribute_values,
            expected: "TooManyAttributes",
        },
        Attack {
            name: "empty array values",
            build: empty_values,
            expected: "TooManyValueElements",
        },
        Attack {
            name: "empty entity references",
            build: empty_entity_refs,
            expected: "TooManyEntityRefs",
        },
        Attack {
            name: "empty entity id keys",
            build: empty_id_keys,
            expected: "TooManyEntityKeys",
        },
        Attack {
            name: "empty entity description keys",
            build: empty_description_keys,
            expected: "TooManyEntityKeys",
        },
    ]
}


#[test]
fn attacks_are_refused_before_prost_builds_a_message_per_element() -> TestResult {
    attacks().iter().try_for_each(|Attack { name, build, expected }| -> TestResult {
        let bytes = build();
        reset_high_water()?;
        let before = high_water_kib()?;
        let outcome = decode_traces(&bytes, TENANT, &Limits::default(), &Sampling::default(), NOW);
        let growth = high_water_kib()?.saturating_sub(before);
        report(&format!("{name}: growth {growth} KiB, refusal {:?}", outcome.refusal))?;
        assert!(format!("{:?}", outcome.refusal).starts_with(&format!("Some({expected}")), "{name}");
        assert!(growth < BUDGET_KIB, "{name}: {growth} KiB");
        Ok(())
    })
}
