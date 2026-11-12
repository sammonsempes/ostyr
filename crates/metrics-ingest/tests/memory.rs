mod common;


use common::types::TestResult;
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::decode::decode_request;
use metrics_ingest::model::{Limits, Refusal};
use prost::encoding::encode_varint;
use std::fs::{read_to_string, write};
use std::io::Write;


const BUDGET_KIB: u64 = 1_024;


const FOUR_MEBIBYTES: usize = 4_194_304;


const FRAMING_SLACK: usize = 16;


const EMPTY_FIELD_BYTES: usize = 2;


const RESOURCE_METRICS: u8 = 0x0a;


const SCOPE_METRICS: u8 = 0x12;


const METRIC: u8 = 0x12;


const GAUGE: u8 = 0x2a;


const POINTS: u8 = 0x0a;


const NUMBER_EXEMPLARS: u8 = 0x2a;


const RESET_PEAK: &str = "5";


struct Attack {
    name: &'static str,
    build: fn() -> Vec<u8>,
    expected: &'static str,
}


fn framed(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    encode_varint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
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


fn attacks() -> Vec<Attack> {
    vec![
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


fn high_water_kib() -> Result<u64, Box<dyn std::error::Error>> {
    let status = read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM line")?;
    let digits: String = line.chars().filter(char::is_ascii_digit).collect();
    Ok(digits.parse()?)
}


fn report(line: &str) -> TestResult {
    Ok(std::io::stdout().write_all(format!("{line}\n").as_bytes())?)
}


fn refusal_name(refusal: &Option<Refusal>) -> String {
    format!("{refusal:?}")
}


#[test]
fn hostile_requests_are_refused_without_decoding() -> TestResult {
    attacks().iter().try_for_each(|attack| -> TestResult {
        let bytes = (attack.build)();
        write("/proc/self/clear_refs", RESET_PEAK)?;
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
