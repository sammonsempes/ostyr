mod common;
#[path = "common/peak.rs"]
mod peak;


use common::types::TestResult;
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::decode::decode_request;
use metrics_ingest::model::Limits;
use peak::{high_water_kib, report, reset_high_water};
use prost::encoding::encode_varint;


const RESOURCE_METRICS: u8 = 0x0a;


const SCOPE_METRICS: u8 = 0x12;


const METRIC: u8 = 0x12;


const POINTS: u8 = 0x0a;


const BUDGET_KIB: u64 = 65_536;


const FOUR_MEBIBYTES: usize = 4_194_304;


const PACKED_SLACK: usize = 64;


const HISTOGRAM: u8 = 0x4a;


const EXPONENTIAL: u8 = 0x52;


const HISTOGRAM_BUCKET_COUNTS: u8 = 0x32;


const EXPONENTIAL_POSITIVE: u8 = 0x42;


const EXPONENTIAL_BUCKET_COUNTS: u8 = 0x12;


fn header(tag: u8, length: usize) -> Vec<u8> {
    let mut out = vec![tag];
    encode_varint(length as u64, &mut out);
    out
}


fn packed_buckets(data_tag: u8, bucket_path: &[u8]) -> Vec<u8> {
    let tags = [&[RESOURCE_METRICS, SCOPE_METRICS, METRIC, data_tag, POINTS], bucket_path].concat();
    let payload = FOUR_MEBIBYTES - PACKED_SLACK;
    let headers = tags.iter().rev().fold((Vec::new(), payload), |(mut collected, inner), tag| {
        let head = header(*tag, inner);
        let total = inner + head.len();
        collected.push(head);
        (collected, total)
    });
    let mut out = Vec::with_capacity(headers.1 + payload);
    headers.0.iter().rev().for_each(|head| out.extend_from_slice(head));
    out.resize(out.len() + payload, 1);
    out
}


fn histogram_counts() -> Vec<u8> {
    packed_buckets(HISTOGRAM, &[HISTOGRAM_BUCKET_COUNTS])
}


fn exponential_counts() -> Vec<u8> {
    packed_buckets(EXPONENTIAL, &[EXPONENTIAL_POSITIVE, EXPONENTIAL_BUCKET_COUNTS])
}


#[test]
fn packed_bucket_counts_stay_within_their_budget() -> TestResult {
    [("histogram", histogram_counts()), ("exponential histogram", exponential_counts())]
        .iter()
        .try_for_each(|(name, bytes)| -> TestResult {
            reset_high_water()?;
            let before = high_water_kib()?;
            let outcome = decode_request(bytes, "tenant-a", &Limits::default(), &mut CardinalityState::default());
            let growth = high_water_kib()?.saturating_sub(before);
            report(&format!(
                "packed {name} bucket counts: {} bytes, growth {growth} KiB, refusal {:?}",
                bytes.len(),
                outcome.refusal
            ))?;
            assert!(outcome.refusal.is_none(), "{name}");
            assert!(growth < BUDGET_KIB, "{name}: {growth} KiB");
            Ok(())
        })
}
