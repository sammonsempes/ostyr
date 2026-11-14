#[path = "common/types.rs"]
mod types;


use k8s_inventory::text::{
    alphanumeric_edges, is_hidden, valid_dns_label, valid_label_key, valid_label_value, valid_prefix, valid_segment, valid_subdomain, valid_text,
    valid_uid,
};
use types::TestResult;


const CAP: usize = 16;


const SEGMENT_MAX: usize = 63;


const OVER_SEGMENT: usize = 64;


const PARTS: usize = 30;


#[test]
fn hidden_characters_are_control_format_and_separators() -> TestResult {
    assert!(is_hidden('\u{202e}'));
    assert!(is_hidden('\n'));
    assert!(is_hidden('\u{200b}'));
    assert!(is_hidden('\u{2028}'));
    assert!(is_hidden('\u{2029}'));
    assert!(!is_hidden('a'));
    assert!(!is_hidden(' '));
    Ok(())
}


#[test]
fn text_is_non_empty_bounded_without_leading_dash_or_hidden() -> TestResult {
    assert!(valid_text("nginx:1.27", CAP));
    assert!(valid_text("Ubuntu 24.04 LTS", CAP));
    assert!(!valid_text("", CAP));
    assert!(!valid_text("0123456789abcdefg", CAP));
    assert!(!valid_text("-rf", CAP));
    assert!(!valid_text("a\u{202e}b", CAP));
    assert!(!valid_text("a\nb", CAP));
    Ok(())
}


#[test]
fn edges_need_alphanumerics() -> TestResult {
    assert!(alphanumeric_edges("a"));
    assert!(alphanumeric_edges("a-b"));
    assert!(!alphanumeric_edges(""));
    assert!(!alphanumeric_edges("-a"));
    assert!(!alphanumeric_edges("a-"));
    Ok(())
}


#[test]
fn segments_follow_the_kubernetes_grammar() -> TestResult {
    assert!(valid_segment("app"));
    assert!(valid_segment("a_b-c.d"));
    assert!(valid_segment(&"a".repeat(SEGMENT_MAX)));
    assert!(!valid_segment(&"a".repeat(OVER_SEGMENT)));
    assert!(!valid_segment("_a"));
    assert!(!valid_segment("a_"));
    assert!(!valid_segment("a b"));
    assert!(!valid_segment("a/b"));
    assert!(!valid_segment(""));
    Ok(())
}


#[test]
fn prefixes_are_lowercase_dns_subdomains() -> TestResult {
    assert!(valid_prefix("app.kubernetes.io"));
    assert!(valid_prefix("a"));
    assert!(valid_prefix("my-app.k8s.io"));
    assert!(!valid_prefix("App.io"));
    assert!(!valid_prefix("a..io"));
    assert!(!valid_prefix("-a.io"));
    assert!(!valid_prefix(""));
    assert!(!valid_prefix(&format!("{}.io", "a".repeat(OVER_SEGMENT))));
    assert!(!valid_prefix(&["abcdefghi"; PARTS].join(".")));
    Ok(())
}


#[test]
fn label_keys_and_values_follow_the_grammar() -> TestResult {
    assert!(valid_label_key("app"));
    assert!(valid_label_key("app.kubernetes.io/name"));
    assert!(!valid_label_key("-app"));
    assert!(!valid_label_key("a/b/c"));
    assert!(!valid_label_key("/name"));
    assert!(!valid_label_key("Bad.io/name"));
    assert!(!valid_label_key("app\u{202e}"));
    assert!(valid_label_value(""));
    assert!(valid_label_value("v1.2"));
    assert!(!valid_label_value("-v"));
    assert!(!valid_label_value("v\u{202e}"));
    assert!(!valid_label_value(&"v".repeat(OVER_SEGMENT)));
    Ok(())
}


const LIVE_UID: &str = "070d5076-c236-4f29-b589-e60176370304";


const SUBDOMAIN_LABELS: usize = 127;


#[test]
fn uids_are_lowercase_ascii_uuids() -> TestResult {
    assert!(valid_uid(LIVE_UID));
    assert!(!valid_uid(&format!("{LIVE_UID}\u{3164}")));
    assert!(!valid_uid(&LIVE_UID.to_uppercase()));
    assert!(!valid_uid(&LIVE_UID.replacen('-', "", 1)));
    assert!(!valid_uid(&format!("{LIVE_UID}a")));
    assert!(!valid_uid(&LIVE_UID.replacen('0', "g", 1)));
    assert!(!valid_uid(&LIVE_UID.replacen('-', "0", 1)));
    assert!(!valid_uid(""));
    Ok(())
}


#[test]
fn names_are_dns_subdomains_and_namespaces_dns_labels() -> TestResult {
    assert!(valid_subdomain("web-1.example"));
    assert!(!valid_subdomain("web\u{3164}"));
    assert!(!valid_subdomain("Web"));
    assert!(!valid_subdomain("-web"));
    let at_cap = vec!["a"; SUBDOMAIN_LABELS].join(".");
    assert!(valid_subdomain(&at_cap));
    assert!(!valid_subdomain(&format!("{at_cap}b")));
    assert!(valid_dns_label("kube-system"));
    assert!(!valid_dns_label("kube-system\u{200b}"));
    assert!(!valid_dns_label("a.b"));
    assert!(!valid_dns_label(&"a".repeat(OVER_SEGMENT)));
    Ok(())
}
