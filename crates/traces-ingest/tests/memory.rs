mod common;


use common::types::TestResult;
use std::fs::read_to_string;
use traces_ingest::decode::decode_traces;
use traces_ingest::model::{Limits, Refusal};
use traces_ingest::sampling::Sampling;


const TENANT: &str = "tenant-a";


const NOW: u64 = 1_700_000_000_000_000_000;


const EMPTY_FIELD_BYTES: usize = 2;


const BUDGET_KIB: u64 = 65_536;


const RESOURCE_SPANS_TAG: u8 = 0x0a;


const SCOPE_SPANS_TAG: u8 = 0x12;


const SPANS_TAG: u8 = 0x12;


const FOUR_MEBIBYTES: usize = 4_194_304;


const FRAMING_SLACK: usize = 16;


const TWO_BYTE_SCOPE: usize = 4;


const LENGTH_CONTINUATION: u8 = 0x80;


const HUGE_LENGTH: u8 = 0x7f;


fn framed(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    prost::encoding::encode_varint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}


fn high_water_kib() -> Result<u64, Box<dyn std::error::Error>> {
    let status = read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM line")?;
    let digits: String = line.chars().filter(char::is_ascii_digit).collect();
    Ok(digits.parse()?)
}


fn attacks() -> Vec<(&'static str, Vec<u8>)> {
    let spans = FOUR_MEBIBYTES / EMPTY_FIELD_BYTES - FRAMING_SLACK;
    vec![
        (
            "empty spans",
            framed(RESOURCE_SPANS_TAG, &framed(SCOPE_SPANS_TAG, &[SPANS_TAG, 0].repeat(spans))),
        ),
        ("empty resource spans", [RESOURCE_SPANS_TAG, 0].repeat(spans)),
        (
            "scopes with one span each",
            framed(
                RESOURCE_SPANS_TAG,
                &framed(SCOPE_SPANS_TAG, &[SPANS_TAG, 0]).repeat(FOUR_MEBIBYTES / TWO_BYTE_SCOPE - FRAMING_SLACK),
            ),
        ),
        ("empty scopes", framed(RESOURCE_SPANS_TAG, &[SCOPE_SPANS_TAG, 0].repeat(spans))),
        ("truncated length", vec![RESOURCE_SPANS_TAG, LENGTH_CONTINUATION]),
        ("length over the rest", vec![RESOURCE_SPANS_TAG, HUGE_LENGTH, SCOPE_SPANS_TAG]),
    ]
}


const ACCEPTED_BUDGET_KIB: u64 = 262_144;


const ATTRIBUTE_FIELD: u8 = 0x4a;


const KEY_VALUE: [u8; 8] = [0x0a, 0x01, b'k', 0x12, 0x03, 0x0a, 0x01, b'v'];


const ATTRIBUTES_PER_SPAN: usize = 128;


const SPANS_FILLING_THE_LIMIT: usize = 3_000;


fn accepted_request_stays_within_its_budget() -> TestResult {
    let attribute = framed(ATTRIBUTE_FIELD, &KEY_VALUE);
    let span = framed(SPANS_TAG, &attribute.repeat(ATTRIBUTES_PER_SPAN));
    let bytes = framed(RESOURCE_SPANS_TAG, &framed(SCOPE_SPANS_TAG, &span.repeat(SPANS_FILLING_THE_LIMIT)));
    let before = high_water_kib()?;
    let outcome = decode_traces(&bytes, TENANT, &Limits::default(), &Sampling::default(), NOW);
    let growth = high_water_kib()?.saturating_sub(before);
    let line = format!("accepted {} bytes: growth {growth} KiB, refusal {:?}\n", bytes.len(), outcome.refusal);
    std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes())?;
    assert!(outcome.refusal.is_none());
    assert!(growth < ACCEPTED_BUDGET_KIB, "{growth} KiB");
    Ok(())
}


#[test]
fn attacks_are_refused_without_a_message_per_span() -> TestResult {
    attacks().iter().try_for_each(|(name, bytes)| -> TestResult {
        let before = high_water_kib()?;
        let outcome = decode_traces(bytes, TENANT, &Limits::default(), &Sampling::default(), NOW);
        let after = high_water_kib()?;
        let growth = after.saturating_sub(before);
        let counted = matches!(
            outcome.refusal,
            Some(Refusal::TooManySpans { .. } | Refusal::TooManyResourceSpans { .. } | Refusal::Malformed(_))
        );
        std::io::Write::write_all(
            &mut std::io::stdout(),
            format!("{name}: growth {growth} KiB, refusal {:?}\n", outcome.refusal).as_bytes(),
        )?;
        assert!(counted, "{name}");
        assert!(growth < BUDGET_KIB, "{name}: {growth} KiB");
        Ok(())
    })?;
    accepted_request_stays_within_its_budget()
}
