mod common;


use common::types::TestResult;
use metric_alerts::fingerprint::fingerprint;


const SHA256_HEX_LEN: usize = 64;


fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items.iter().map(|(key, value)| (key.to_string(), value.to_string())).collect()
}


#[test]
fn label_order_does_not_change_the_fingerprint() -> TestResult {
    let first = fingerprint("disk-high", &pairs(&[("host", "web-1"), ("mount", "/")]));
    let second = fingerprint("disk-high", &pairs(&[("mount", "/"), ("host", "web-1")]));
    assert_eq!(first, second);
    assert_eq!(first.len(), SHA256_HEX_LEN);
    Ok(())
}


#[test]
fn rule_or_label_changes_the_fingerprint() -> TestResult {
    let base = fingerprint("disk-high", &pairs(&[("host", "web-1")]));
    assert_ne!(base, fingerprint("disk-low", &pairs(&[("host", "web-1")])));
    assert_ne!(base, fingerprint("disk-high", &pairs(&[("host", "web-2")])));
    assert_ne!(base, fingerprint("disk-high", &pairs(&[("host", "web-1"), ("mount", "/")])));
    Ok(())
}


#[test]
fn concatenation_cannot_collide() -> TestResult {
    let joined = fingerprint("a", &pairs(&[("bc", "d")]));
    let moved = fingerprint("a", &pairs(&[("b", "cd")]));
    assert_ne!(joined, moved);
    Ok(())
}
