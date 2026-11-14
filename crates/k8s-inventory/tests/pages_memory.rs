#[path = "common/types.rs"]
mod types;


use k8s_inventory::error::ParseError;
use k8s_inventory::limits::Limits;
use k8s_inventory::parse::parse_pods_page;
use std::error::Error;
use types::TestResult;


const CHILD_ENV: &str = "K8S_PAGES_MEMORY_CHILD";


const CHILD_TEST: &str = "the_crossing_page_is_refused_without_building_its_items";


const PODS_PER_PAGE: usize = 2_000;


const LABELS_PER_POD: usize = 128;


const GROWTH_BOUND_KIB: u64 = 16_384;


const UID_TAIL: usize = 12;


fn peak_kib() -> Result<u64, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM")?;
    Ok(line.split_whitespace().nth(1).ok_or("no value")?.parse()?)
}


fn labelled_pod(index: usize) -> String {
    let labels = (0..LABELS_PER_POD)
        .map(|label| format!("\"l{label:03}\":\"v\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"metadata\":{{\"name\":\"p{index}\",\"namespace\":\"n\",\"uid\":\"00000000-0000-4000-8000-{index:0>UID_TAIL$x}\",\"labels\":{{{labels}}}}}}}"
    )
}


fn hostile_page() -> String {
    let pods = (0..PODS_PER_PAGE).map(labelled_pod).collect::<Vec<_>>().join(",");
    format!("{{\"kind\":\"PodList\",\"items\":[{pods}]}}")
}


#[test]
fn the_crossing_page_is_refused_without_building_its_items() -> TestResult {
    if std::env::var_os(CHILD_ENV).is_some() {
        let page = hostile_page();
        let before = peak_kib()?;
        let outcome = parse_pods_page(page.as_bytes(), &Limits::default(), 0);
        let growth = peak_kib()?.saturating_sub(before);
        assert!(matches!(
            outcome,
            Err(ParseError::TooManyItems {
                count: PODS_PER_PAGE,
                max: 0
            })
        ));
        assert!(growth < GROWTH_BOUND_KIB, "grew {growth} KiB");
    }
    Ok(())
}


#[test]
fn a_child_process_proves_the_peak_of_the_crossing_page() -> TestResult {
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", CHILD_TEST, "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"), "the child test did not run");
    Ok(())
}
