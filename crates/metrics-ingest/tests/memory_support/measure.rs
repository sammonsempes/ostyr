use crate::memory_support::framed;
use crate::memory_support::{GAUGE, METRIC, RESOURCE_METRICS, SCOPE_METRICS};
use crate::peak::{high_water_kib, report, reset_high_water};
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::decode::decode_request;
use metrics_ingest::model::Limits;
use prost::encoding::encode_varint;


const BUDGET_KIB: u64 = 102_400;


const NAME: u8 = 0x0a;


pub fn header(tag: u8, length: usize) -> Vec<u8> {
    let mut out = vec![tag];
    encode_varint(length as u64, &mut out);
    out
}


pub fn assemble(points: usize, resource: &[u8], scope_attributes: &[u8], point: impl Fn(usize) -> Vec<u8>) -> Vec<u8> {
    let point_length = point(0).len();
    let name = framed(NAME, b"cpu");
    let points_length = points * point_length;
    let gauge = header(GAUGE, points_length);
    let metric_length = name.len() + gauge.len() + points_length;
    let metric = header(METRIC, metric_length);
    let scope_length = scope_attributes.len() + metric.len() + metric_length;
    let scope = header(SCOPE_METRICS, scope_length);
    let outer_length = resource.len() + scope.len() + scope_length;
    let outer = header(RESOURCE_METRICS, outer_length);
    let mut out = Vec::with_capacity(outer.len() + outer_length);
    [outer, resource.to_vec(), scope, scope_attributes.to_vec(), metric, name, gauge]
        .iter()
        .for_each(|part| out.extend_from_slice(part));
    (0..points).for_each(|index| out.extend_from_slice(&point(index)));
    out
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
