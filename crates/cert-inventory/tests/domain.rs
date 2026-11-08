#[path = "common/record.rs"]
mod record;
#[path = "common/types.rs"]
mod types;


use cert_inventory::domain::{matches_domain, name_matches};
use record::record_with;
use types::TestResult;


fn owned(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_string()).collect()
}


#[test]
fn exact_names_match_case_insensitively() -> TestResult {
    assert!(name_matches("www.example.com", "WWW.Example.COM"));
    assert!(!name_matches("www.example.com", "example.com"));
    Ok(())
}


#[test]
fn wildcard_covers_exactly_one_label() -> TestResult {
    assert!(name_matches("*.example.com", "www.example.com"));
    assert!(name_matches("*.EXAMPLE.com", "WWW.example.com"));
    assert!(!name_matches("*.example.com", "example.com"));
    assert!(!name_matches("*.example.com", "a.b.example.com"));
    assert!(!name_matches("*.example.com", ".example.com"));
    assert!(!name_matches("*.example.com", "localhost"));
    Ok(())
}


#[test]
fn wildcard_needs_two_fixed_labels_and_a_whole_leftmost_label() -> TestResult {
    assert!(!name_matches("*.com", "example.com"));
    assert!(!name_matches("*.*.example.com", "a.b.example.com"));
    assert!(!name_matches("w*.example.com", "www.example.com"));
    assert!(!name_matches("www.*.com", "www.example.com"));
    Ok(())
}


#[test]
fn record_matches_when_any_name_covers_any_owned_domain() -> TestResult {
    let record = record_with(&["other.test", "*.example.com"], 0);
    assert!(matches_domain(&record, &owned(&["nothing.test", "api.example.com"])));
    assert!(!matches_domain(&record, &owned(&["example.com"])));
    assert!(!matches_domain(&record, &[]));
    assert!(!matches_domain(&record_with(&[], 0), &owned(&["example.com"])));
    Ok(())
}
