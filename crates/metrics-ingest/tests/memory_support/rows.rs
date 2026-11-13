use crate::memory_support::framed;
use crate::memory_support::{GAUGE, METRIC, POINTS, RESOURCE, RESOURCE_METRICS, SCOPE_METRICS, VALUE};
use crate::peak::{high_water_kib, report, reset_high_water};
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::decode::decode_request;
use metrics_ingest::model::Limits;


const BUDGET_KIB: u64 = 102_400;


const KEY: u8 = 0x0a;


const STRING: u8 = 0x0a;


const ATTRIBUTES: u8 = 0x0a;


const POINT_ATTRIBUTES: u8 = 0x3a;


const NAME: u8 = 0x0a;


const NUMBER_VALUE: u8 = 0x31;


const POINT_VALUE: i64 = 1;


fn pair(tag: u8, index: usize, key_width: usize, value_width: usize) -> Vec<u8> {
    let key = format!("{index:0>width$}", width = key_width);
    let value = if value_width == 0 {
        String::new()
    } else {
        format!("{index:0>width$}", width = value_width)
    };
    framed(
        tag,
        &[framed(KEY, key.as_bytes()), framed(VALUE, &framed(STRING, value.as_bytes()))].concat(),
    )
}


fn labels(tag: u8, count: usize, key_width: usize, value_width: usize) -> Vec<u8> {
    (0..count).flat_map(|index| pair(tag, index, key_width, value_width)).collect()
}


pub fn request(points: usize, count: usize, on_resource: bool, key_width: usize, value_width: usize) -> Vec<u8> {
    let point_labels = if on_resource {
        Vec::new()
    } else {
        labels(POINT_ATTRIBUTES, count, key_width, value_width)
    };
    let value = [NUMBER_VALUE].into_iter().chain(POINT_VALUE.to_le_bytes()).collect::<Vec<u8>>();
    let one_point = framed(POINTS, &[point_labels, value].concat());
    let metric = [framed(NAME, b"cpu"), framed(GAUGE, &one_point.repeat(points))].concat();
    let resource = if on_resource {
        framed(RESOURCE, &labels(ATTRIBUTES, count, key_width, value_width))
    } else {
        Vec::new()
    };
    framed(RESOURCE_METRICS, &[resource, framed(SCOPE_METRICS, &framed(METRIC, &metric))].concat())
}


pub fn measure(name: &str, bytes: &[u8], limits: &Limits, factor: u64) -> Result<(usize, bool), Box<dyn std::error::Error>> {
    reset_high_water()?;
    let before = high_water_kib()?;
    let outcome = decode_request(bytes, "tenant-a", limits, &mut CardinalityState::default());
    let growth = high_water_kib()?.saturating_sub(before);
    report(&format!(
        "{name} {} bytes: growth {growth} KiB, rows {}, row bytes {}, refusal {:?}",
        bytes.len(),
        outcome.rows.len(),
        outcome.row_bytes,
        outcome.refusal
    ))?;
    assert!(outcome.row_bytes <= limits.max_row_bytes_total);
    assert!(growth < BUDGET_KIB * factor, "{growth} KiB");
    Ok((outcome.rows.len(), outcome.refusal.is_none()))
}
