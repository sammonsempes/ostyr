#[path = "common/types.rs"]
mod types;


use intel_feeds::limits::{MAX_COMPARISONS_PER_PATTERN, MAX_PATTERN_BYTES};
use intel_feeds::stix::parse_pattern;
use types::TestResult;


fn terms_of(pattern: &str) -> Option<Vec<(&'static str, String)>> {
    parse_pattern(pattern).map(|terms| terms.into_iter().map(|term| (term.type_name, term.value)).collect())
}


fn pair(type_name: &'static str, value: &str) -> (&'static str, String) {
    (type_name, value.to_owned())
}


#[test]
fn simple_comparisons_joined_by_or_are_supported() -> TestResult {
    assert_eq!(terms_of("[ipv4-addr:value = '192.0.2.1']"), Some(vec![pair("ip", "192.0.2.1")]));
    assert_eq!(
        terms_of("[ipv6-addr:value = '::1'] OR [domain-name:value = 'a.example']"),
        Some(vec![pair("ip", "::1"), pair("domain", "a.example")])
    );
    assert_eq!(
        terms_of(
            "[url:value = 'http://a.example/x'] OR [file:hashes.MD5 = 'abc'] OR [file:hashes.'SHA-1' = 'def'] OR [file:hashes.'SHA-256' = 'ghi']"
        ),
        Some(vec![
            pair("url", "http://a.example/x"),
            pair("md5", "abc"),
            pair("sha1", "def"),
            pair("sha256", "ghi")
        ])
    );
    assert_eq!(
        terms_of("[domain-name:value = 'a.example' OR domain-name:value = 'b.example']"),
        Some(vec![pair("domain", "a.example"), pair("domain", "b.example")])
    );
    assert_eq!(terms_of("  [ ipv4-addr:value   =   '1.1.1.1' ]  "), Some(vec![pair("ip", "1.1.1.1")]));
    assert_eq!(
        terms_of("[domain-name:value = 'x'] OR [domain-name:value = '] OR [ip']"),
        Some(vec![pair("domain", "x"), pair("domain", "] OR [ip")])
    );
    Ok(())
}


#[test]
fn everything_else_is_unsupported() -> TestResult {
    let unsupported = [
        "[ipv4-addr:value = '1.1.1.1' AND domain-name:value = 'x.example']",
        "[ipv4-addr:value = '1.1.1.1'] FOLLOWEDBY [domain-name:value = 'x.example']",
        "[ipv4-addr:value IN ('1.1.1.1', '2.2.2.2')]",
        "[ipv4-addr:value != '1.1.1.1']",
        "[process:name = 'cmd.exe']",
        "[file:hashes.'SHA-512' = 'abc']",
        "[domain-name:value = 'a\\'b']",
        "[domain-name:value = 'a.example]",
        "domain-name:value = 'a.example'",
        "[domain-name:value = 'a.example'] [domain-name:value = 'b.example']",
        "[domain-name:value = $]",
        "[domain-name:va'x'ue = 'a.example']",
        "[domain-name:value = 'a\u{1}b']",
        "[file:hashes.'SHA-1' = 'a'] AND",
        "",
    ];
    unsupported
        .iter()
        .for_each(|pattern| assert_eq!(parse_pattern(pattern), None, "{pattern}"));
    Ok(())
}


#[test]
fn caps_on_size_and_comparison_count_apply() -> TestResult {
    let comparison = "[domain-name:value = 'a.example']";
    let at_cap = vec![comparison; MAX_COMPARISONS_PER_PATTERN].join(" OR ");
    assert_eq!(parse_pattern(&at_cap).map(|terms| terms.len()), Some(MAX_COMPARISONS_PER_PATTERN));
    let above_cap = vec![comparison; MAX_COMPARISONS_PER_PATTERN + 1].join(" OR ");
    assert_eq!(parse_pattern(&above_cap), None);
    let oversized = format!("[domain-name:value = '{}']", "a".repeat(MAX_PATTERN_BYTES));
    assert_eq!(parse_pattern(&oversized), None);
    Ok(())
}
