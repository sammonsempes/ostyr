mod common;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;


use common::types::TestResult;
use memory_support::{framed, GAUGE, METRIC, POINTS, RESOURCE, RESOURCE_METRICS};
use memory_support::{SCOPE_METRICS, VALUE};
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::decode::decode_request;
use metrics_ingest::model::{Limits, Refusal};
use peak::{high_water_kib, report, reset_high_water};


const BUDGET_KIB: u64 = 1_024;


const FOUR_MEBIBYTES: usize = 4_194_304;


const FRAMING_SLACK: usize = 16;


const EMPTY_FIELD_BYTES: usize = 2;


const NUMBER_EXEMPLARS: u8 = 0x2a;


const NUMBER_ATTRIBUTES: u8 = 0x3a;


const RESOURCE_ATTRIBUTES: u8 = 0x0a;


const ENTITY_REFS: u8 = 0x1a;


const ID_KEYS: u8 = 0x1a;


const KVLIST: u8 = 0x32;


const ELEMENT: u8 = 0x0a;


struct Attack {
    name: &'static str,
    build: fn() -> Vec<u8>,
    expected: &'static str,
}


fn many(tag: u8) -> Vec<u8> {
    [tag, 0].repeat(FOUR_MEBIBYTES / EMPTY_FIELD_BYTES - FRAMING_SLACK)
}


fn empty_points() -> Vec<u8> {
    framed(RESOURCE_METRICS, &framed(SCOPE_METRICS, &framed(METRIC, &framed(GAUGE, &many(POINTS)))))
}


fn empty_metrics() -> Vec<u8> {
    framed(RESOURCE_METRICS, &framed(SCOPE_METRICS, &many(METRIC)))
}


fn empty_resource_metrics() -> Vec<u8> {
    many(RESOURCE_METRICS)
}


fn empty_scopes() -> Vec<u8> {
    framed(RESOURCE_METRICS, &many(SCOPE_METRICS))
}


fn empty_exemplars() -> Vec<u8> {
    framed(
        RESOURCE_METRICS,
        &framed(SCOPE_METRICS, &framed(METRIC, &framed(GAUGE, &framed(POINTS, &many(NUMBER_EXEMPLARS))))),
    )
}


fn empty_entity_refs() -> Vec<u8> {
    framed(RESOURCE_METRICS, &framed(RESOURCE, &many(ENTITY_REFS)))
}


fn empty_entity_keys() -> Vec<u8> {
    framed(RESOURCE_METRICS, &framed(RESOURCE, &framed(ENTITY_REFS, &many(ID_KEYS))))
}


fn empty_resource_attributes() -> Vec<u8> {
    framed(RESOURCE_METRICS, &framed(RESOURCE, &many(RESOURCE_ATTRIBUTES)))
}


fn empty_point_attributes() -> Vec<u8> {
    framed(
        RESOURCE_METRICS,
        &framed(SCOPE_METRICS, &framed(METRIC, &framed(GAUGE, &framed(POINTS, &many(NUMBER_ATTRIBUTES))))),
    )
}


fn duplicate_list_values() -> Vec<u8> {
    let list = framed(KVLIST, &framed(ELEMENT, &many(VALUE)));
    framed(RESOURCE_METRICS, &framed(RESOURCE, &framed(RESOURCE_ATTRIBUTES, &framed(VALUE, &list))))
}


fn attacks() -> Vec<Attack> {
    vec![
        Attack {
            name: "empty entity references",
            build: empty_entity_refs,
            expected: "TooManyEntityRefs",
        },
        Attack {
            name: "empty entity keys",
            build: empty_entity_keys,
            expected: "TooManyEntityKeys",
        },
        Attack {
            name: "empty resource attributes",
            build: empty_resource_attributes,
            expected: "TooManyAttributes",
        },
        Attack {
            name: "empty point attributes",
            build: empty_point_attributes,
            expected: "TooManyAttributes",
        },
        Attack {
            name: "duplicate list entry values",
            build: duplicate_list_values,
            expected: "TooManyAttributes",
        },
        Attack {
            name: "empty data points",
            build: empty_points,
            expected: "TooManyDataPoints",
        },
        Attack {
            name: "empty metrics",
            build: empty_metrics,
            expected: "TooManyDataPoints",
        },
        Attack {
            name: "empty resource metrics",
            build: empty_resource_metrics,
            expected: "TooManyResources",
        },
        Attack {
            name: "empty scopes",
            build: empty_scopes,
            expected: "TooManyDataPoints",
        },
        Attack {
            name: "empty exemplars",
            build: empty_exemplars,
            expected: "TooManyDataPoints",
        },
    ]
}


fn refusal_name(refusal: &Option<Refusal>) -> String {
    format!("{refusal:?}")
}


#[test]
fn hostile_requests_are_refused_without_decoding() -> TestResult {
    attacks().iter().try_for_each(|attack| -> TestResult {
        let bytes = (attack.build)();
        reset_high_water()?;
        let before = high_water_kib()?;
        let outcome = decode_request(&bytes, "tenant-a", &Limits::default(), &mut CardinalityState::default());
        let growth = high_water_kib()?.saturating_sub(before);
        report(&format!("{}: {} bytes, peak growth {growth} KiB", attack.name, bytes.len()))?;
        assert!(
            refusal_name(&outcome.refusal).contains(attack.expected),
            "{}: {:?}",
            attack.name,
            outcome.refusal
        );
        assert!(growth <= BUDGET_KIB, "{} grew the peak by {growth} KiB", attack.name);
        Ok(())
    })
}
