mod common;
mod memory_support;
#[path = "common/peak.rs"]
mod peak;


use common::types::TestResult;
use memory_support::framed;
use memory_support::{GAUGE, METRIC, POINTS, RESOURCE, RESOURCE_METRICS, SCOPE_METRICS, VALUE};
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::decode::decode_request;
use metrics_ingest::model::Limits;
use peak::{high_water_kib, report, reset_high_water};


const BUDGET_KIB: u64 = 102_400;


const POINTS_NEAR_THE_CAP: usize = 40_000;


const ARRAY_ELEMENTS_NEAR_THE_CAP: usize = 150_000;


const HOSTS: usize = 10_000;


const ENTITY_REFS_NEAR_THE_CAP: usize = 1_000;


const KEYS_PER_ENTITY_REF: usize = 4;


const KEY: u8 = 0x0a;


const STRING: u8 = 0x0a;


const NAME: u8 = 0x0a;


const UNIT: u8 = 0x12;


const METADATA: u8 = 0x62;


const ARRAY: u8 = 0x2a;


const ELEMENT: u8 = 0x0a;


const NUMBER_ATTRIBUTES: u8 = 0x3a;


const NUMBER_TIME: u8 = 0x19;


const NUMBER_VALUE: u8 = 0x31;


const ENTITY_REFS: u8 = 0x1a;


const ID_KEYS: u8 = 0x1a;


const POINT_VALUE: i64 = 1;


const STAMP: u64 = 1_700_000_000_000_000_000;


fn pair(tag: u8, key: &str, value: &str) -> Vec<u8> {
    framed(
        tag,
        &[framed(KEY, key.as_bytes()), framed(VALUE, &framed(STRING, value.as_bytes()))].concat(),
    )
}


fn point(index: usize) -> Vec<u8> {
    let attributes = [
        pair(NUMBER_ATTRIBUTES, "host", &format!("h{}", index % HOSTS)),
        pair(NUMBER_ATTRIBUTES, "tenant", "evil"),
    ]
    .concat();
    let value = [NUMBER_VALUE].into_iter().chain(POINT_VALUE.to_le_bytes()).collect::<Vec<u8>>();
    let stamp = [NUMBER_TIME].into_iter().chain(STAMP.to_le_bytes()).collect::<Vec<u8>>();
    framed(POINTS, &[attributes, stamp, value].concat())
}


fn entity_ref() -> Vec<u8> {
    framed(ENTITY_REFS, &[ID_KEYS, 0].repeat(KEYS_PER_ENTITY_REF))
}


fn array_metadata() -> Vec<u8> {
    let elements = [ELEMENT, 0].repeat(ARRAY_ELEMENTS_NEAR_THE_CAP);
    framed(METADATA, &[framed(KEY, b"k"), framed(VALUE, &framed(ARRAY, &elements))].concat())
}


fn request() -> Vec<u8> {
    let points = (0..POINTS_NEAR_THE_CAP).flat_map(point).collect::<Vec<u8>>();
    let metric = [framed(NAME, b"cpu"), framed(UNIT, b"1"), framed(GAUGE, &points), array_metadata()].concat();
    let resource = framed(RESOURCE, &entity_ref().repeat(ENTITY_REFS_NEAR_THE_CAP));
    framed(RESOURCE_METRICS, &[resource, framed(SCOPE_METRICS, &framed(METRIC, &metric))].concat())
}


#[test]
fn a_request_near_every_default_cap_stays_within_its_budget() -> TestResult {
    let bytes = request();
    reset_high_water()?;
    let before = high_water_kib()?;
    let outcome = decode_request(&bytes, "tenant-a", &Limits::default(), &mut CardinalityState::default());
    let growth = high_water_kib()?.saturating_sub(before);
    report(&format!(
        "accepted {} bytes: growth {growth} KiB, rows {}, dropped {:?}, refusal {:?}",
        bytes.len(),
        outcome.rows.len(),
        outcome.dropped,
        outcome.refusal
    ))?;
    assert!(outcome.refusal.is_none());
    assert_eq!(outcome.rows.len(), POINTS_NEAR_THE_CAP);
    assert!(growth < BUDGET_KIB, "{growth} KiB");
    Ok(())
}
