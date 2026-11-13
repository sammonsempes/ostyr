use crate::common::types::TestResult;
use crate::memory_support::{high_water_kib, report, reset_high_water, NOW, TENANT};
use crate::worst_build::{build_request, Shape};
use traces_ingest::decode::decode_traces;
use traces_ingest::model::Limits;
use traces_ingest::sampling::Sampling;


pub const DEFAULT_BUDGET_KIB: u64 = 102_400;


const SERVICE_FILL: u8 = b's';


pub fn check(limits: &Limits, budget_kib: u64, attributes: usize, events: usize, links: usize, inner: usize) -> TestResult {
    let shape = Shape {
        attributes,
        events,
        links,
        inner,
        fill: SERVICE_FILL,
        timed: false,
    };
    let bytes = build_request(limits, shape);
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
