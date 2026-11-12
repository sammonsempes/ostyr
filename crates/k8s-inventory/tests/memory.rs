#[path = "common/types.rs"]
mod types;


use k8s_inventory::error::ParseError;
use k8s_inventory::limits::{Limits, DEFAULT_MAX_BYTES};
use k8s_inventory::model::Skipped;
use k8s_inventory::parse::{parse_nodes, parse_pods};
use std::error::Error;
use types::TestResult;


const PEAK_BOUND_KIB: u64 = 65_536;


const NEST_DEPTH: usize = 100;


const POD_HEAD: &str = r#"{"kind":"PodList","items":[{"metadata":{"name":"p","namespace":"n","uid":"u"}"#;


const NODE_HEAD: &str = r#"{"kind":"NodeList","items":[{"metadata":{"name":"p","uid":"u"},"status":{"addresses":"#;


fn peak_kib() -> Result<u64, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM")?;
    Ok(line.split_whitespace().nth(1).ok_or("no value")?.parse()?)
}


fn repeated(head: &str, unit: &str, tail: &str) -> Result<String, Box<dyn Error>> {
    let count = (usize::try_from(DEFAULT_MAX_BYTES)? - head.len() - tail.len()) / unit.len();
    Ok(format!("{head}{}{tail}", unit.repeat(count)))
}


fn nested() -> String {
    format!("{}{}", "[".repeat(NEST_DEPTH), "]".repeat(NEST_DEPTH))
}


const OWNER_HEAD: &str = r#"{"kind":"PodList","items":[{"metadata":{"name":"p","namespace":"n","uid":"u","ownerReferences":"#;


const LABEL_HEAD: &str = r#"{"kind":"PodList","items":[{"metadata":{"name":"p","namespace":"n","uid":"u","labels":"#;


fn root_items() -> Result<String, Box<dyn Error>> {
    repeated(r#"{"kind":"PodList","items":["#, "0,", "0]}")
}


fn containers() -> Result<String, Box<dyn Error>> {
    repeated(&format!(r#"{POD_HEAD},"spec":{{"containers":["#), "{},", "{}]}}]}")
}


fn unknown_field() -> Result<String, Box<dyn Error>> {
    repeated(&format!(r#"{POD_HEAD},"x":["#), "0,", "0]}]}")
}


fn owners() -> Result<String, Box<dyn Error>> {
    repeated(&format!("{OWNER_HEAD}["), "{},", "{}]}}]}")
}


fn labels() -> Result<String, Box<dyn Error>> {
    repeated(&format!("{LABEL_HEAD}{{"), r#""k":"v","#, r#""z":"v"}}}]}"#)
}


fn addresses() -> Result<String, Box<dyn Error>> {
    repeated(&format!("{NODE_HEAD}["), "{},", "{}]}}]}")
}


fn pod_peak(build: fn() -> Result<String, Box<dyn Error>>) -> Result<(Result<Skipped, ParseError>, u64), Box<dyn Error>> {
    let input = build()?;
    let outcome = parse_pods(input.as_bytes(), &Limits::default()).map(|parsed| parsed.skipped);
    Ok((outcome, peak_kib()?))
}


#[test]
fn hostile_shapes_at_the_byte_cap_stay_within_the_peak_bound() -> TestResult {
    let nest = nested();
    let skipped_one = Skipped {
        unparsable: 0,
        bad_field: 1,
        duplicate: 0,
    };
    let (root, root_peak) = pod_peak(root_items)?;
    assert!(matches!(root, Err(ParseError::TooManyItems { .. })));
    let (many_containers, containers_peak) = pod_peak(containers)?;
    assert_eq!(many_containers?, skipped_one);
    let (unknown, unknown_peak) = pod_peak(unknown_field)?;
    assert_eq!(unknown?, Skipped::default());
    let (many_owners, owners_peak) = pod_peak(owners)?;
    assert_eq!(many_owners?, skipped_one);
    let (many_labels, labels_peak) = pod_peak(labels)?;
    assert_eq!(many_labels?, skipped_one);
    let addresses_input = addresses()?;
    let many_addresses = parse_nodes(addresses_input.as_bytes(), &Limits::default())?.skipped;
    assert_eq!(many_addresses, skipped_one);
    let nested_shapes = [
        format!("{POD_HEAD},\"spec\":{{\"containers\":{nest}}}}}]}}"),
        format!("{OWNER_HEAD}{nest}}}}}]}}"),
        format!("{LABEL_HEAD}{nest}}}}}]}}"),
    ];
    nested_shapes
        .iter()
        .try_for_each(|shape| parse_pods(shape.as_bytes(), &Limits::default()).map(|parsed| assert_eq!(parsed.skipped.unparsable, 1)))?;
    let nested_addresses = format!("{NODE_HEAD}{nest}}}}}]}}");
    assert_eq!(parse_nodes(nested_addresses.as_bytes(), &Limits::default())?.skipped.unparsable, 1);
    let final_peak = peak_kib()?;
    [root_peak, containers_peak, unknown_peak, owners_peak, labels_peak, final_peak]
        .iter()
        .for_each(|peak| assert!(*peak < PEAK_BOUND_KIB, "peak {peak} KiB"));
    Ok(())
}
