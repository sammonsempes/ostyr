use attack_surface::error::{Refusal, ScopeError};
use attack_surface::model::{PortRange, Scope, ScopeKind, MAX_FILE_BYTES, MAX_PORT_ENTRIES, MAX_TARGETS};
use attack_surface::scope::{in_ranges, load_scope, parse_scope, port_allowed, validate_scope};
use ipnet::IpNet;
use std::error::Error;
use std::fs;
use std::io::{Cursor, Read};
use std::net::IpAddr;
use tempfile::tempdir;
use types::TestResult;


#[path = "support/types.rs"]
mod types;


const RATE: u32 = 10;


const DEFAULT_RATE: u32 = 100;


const CUSTOM_RATE: u32 = 250;


const MIN_RATE: u32 = 1;


const MAX_RATE: u32 = 1000;


const SSH: u16 = 22;


const BELOW_SSH: u16 = 21;


const HTTP: u16 = 80;


const HTTP_NEXT: u16 = 81;


const HIGH_FIRST: u16 = 8000;


const HIGH_LAST: u16 = 8100;


const MAX_PORTS_U16: u16 = 1024;


const HUNDRED: u16 = 100;


const TOP_PORT: u16 = 65535;


const FOUR: usize = 4;


const SHOWN: usize = 64;


const INVALID_FIRST: u8 = 0xff;


const INVALID_SECOND: u8 = 0xfe;


const FILE: &str = "scope.yaml";


const DEFAULT_PORTS: &str = "[22, \"80\"]";


const ADJACENT_SLASH_24_COUNT: usize = 256;


const LONG_VALUE_BYTES: usize = 200;


const OVERLONG_REFERENCE_BYTES: usize = 129;


const MAX_REFERENCE_FITTING: usize = 128;


const OVERSIZED_PORT: u32 = 70_000;


const ONE_OVER_RATE: u32 = 1001;


fn block(value: &str) -> String {
    format!("  - value: \"{value}\"\n    ownership: {{method: dns_txt, reference: TICKET-1}}\n")
}


fn document(kind: &str, rate: u32, ports: &str, targets: &str) -> String {
    format!("kind: {kind}\nrate_per_second: {rate}\nports: {ports}\ntargets:\n{targets}")
}


fn scope_text(kind: &str, values: &[&str]) -> String {
    document(
        kind,
        DEFAULT_RATE,
        DEFAULT_PORTS,
        &values.iter().map(|value| block(value)).collect::<String>(),
    )
}


fn scope_of(text: &str) -> Result<Scope, Box<dyn Error>> {
    let mut bytes = text.as_bytes();
    Ok(parse_scope(&mut bytes, FILE)?)
}


fn refused(text: &str) -> Result<(ScopeError, String), Box<dyn Error>> {
    let mut bytes = text.as_bytes();
    let error = parse_scope(&mut bytes, FILE).err().ok_or("the scope was accepted")?;
    let message = error.to_string();
    Ok((error, message))
}


fn field_of(error: &ScopeError) -> &str {
    match error {
        ScopeError::Refused { field, .. } => field,
        ScopeError::Config(_) => "config",
    }
}


fn refusal_name(error: &ScopeError) -> &'static str {
    match error {
        ScopeError::Refused { refusal, .. } => match refusal {
            Refusal::Empty => "empty",
            Refusal::TooMany { .. } => "too_many",
            Refusal::BadTarget { .. } => "bad_target",
            Refusal::TooBroad { .. } => "too_broad",
            Refusal::WrongClass { .. } => "wrong_class",
            Refusal::TooWide { .. } => "too_wide",
            Refusal::BadPort { .. } => "bad_port",
            Refusal::TooManyPorts { .. } => "too_many_ports",
            Refusal::Outside { .. } => "outside",
            Refusal::BadReference { .. } => "bad_reference",
        },
        ScopeError::Config(_) => "config",
    }
}


fn assert_refused(kind: &str, value: &str, expected: &str) -> TestResult {
    let (error, message) = refused(&scope_text(kind, &[value]))?;
    assert_eq!(refusal_name(&error), expected, "{kind} {value}: {message}");
    assert_eq!(field_of(&error), "targets[0].value", "{kind} {value}");
    assert!(message.starts_with(FILE), "{message}");
    Ok(())
}


fn ranges_of(scope: &Scope) -> Vec<String> {
    scope.ranges.iter().map(IpNet::to_string).collect()
}


#[test]
fn a_valid_external_scope_is_masked_merged_and_sorted() -> TestResult {
    let text = document(
        "external",
        CUSTOM_RATE,
        "[\"8000-8100\", 22, \"80\", \"81\", \"22\"]",
        &["8.8.8.9/24", "8.8.8.8", "2606:4700::/48", "8.8.9.0/24"]
            .iter()
            .map(|value| block(value))
            .collect::<String>(),
    );
    let scope = scope_of(&text)?;
    assert_eq!(scope.kind, ScopeKind::External);
    assert_eq!(scope.rate_per_second, CUSTOM_RATE);
    assert_eq!(ranges_of(&scope), vec!["8.8.8.0/23", "2606:4700::/48"]);
    assert_eq!(scope.targets, vec!["2606:4700::/48", "8.8.8.0/24", "8.8.8.8/32", "8.8.9.0/24"]);
    assert_eq!(
        scope.ports,
        vec![
            PortRange { first: SSH, last: SSH },
            PortRange {
                first: HTTP,
                last: HTTP_NEXT
            },
            PortRange {
                first: HIGH_FIRST,
                last: HIGH_LAST
            }
        ]
    );
    assert_eq!(ScopeKind::External.to_string(), "external");
    assert_eq!(ScopeKind::Internal.to_string(), "internal");
    Ok(())
}


#[test]
fn an_internal_scope_accepts_private_ranges_only() -> TestResult {
    let scope = scope_of(&scope_text("internal", &["10.1.2.0/24", "192.168.5.0/24", "172.16.0.0/24", "fd00::/48"]))?;
    assert_eq!(scope.kind, ScopeKind::Internal);
    assert_eq!(scope.ranges.len(), FOUR);
    Ok(())
}


#[test]
fn an_external_scope_refuses_every_non_public_range() -> TestResult {
    let table = [
        ("10.0.0.0/8", "too_broad"),
        ("10.1.0.0/24", "wrong_class"),
        ("100.64.0.0/24", "wrong_class"),
        ("0.0.0.0/0", "too_broad"),
        ("0.1.0.0/24", "wrong_class"),
        ("127.0.0.1", "wrong_class"),
        ("169.254.1.0/24", "wrong_class"),
        ("172.16.0.0/16", "wrong_class"),
        ("192.0.0.0/24", "wrong_class"),
        ("192.0.2.0/24", "wrong_class"),
        ("192.168.1.0/24", "wrong_class"),
        ("198.18.0.0/16", "wrong_class"),
        ("198.51.100.0/24", "wrong_class"),
        ("203.0.113.0/24", "wrong_class"),
        ("224.0.0.0/4", "too_broad"),
        ("224.0.0.0/24", "wrong_class"),
        ("240.0.0.0/24", "wrong_class"),
        ("255.255.255.255", "wrong_class"),
        ("::ffff:1.2.3.4/128", "wrong_class"),
        ("::ffff:0:0/96", "wrong_class"),
        ("::1/128", "wrong_class"),
        ("::/0", "too_broad"),
        ("2606::/32", "too_broad"),
        ("2001:db8::/48", "wrong_class"),
        ("3fff::/48", "wrong_class"),
        ("3fff:fff::/48", "wrong_class"),
        ("2002:7f00:1::/48", "wrong_class"),
        ("2002::/16", "too_broad"),
        ("2001:0:7f00::/48", "wrong_class"),
        ("2001::/32", "too_broad"),
        ("fe80::/64", "wrong_class"),
        ("fc00::/48", "wrong_class"),
        ("ff02::/48", "wrong_class"),
    ];
    table.iter().try_for_each(|(value, expected)| assert_refused("external", value, expected))
}


#[test]
fn an_internal_scope_refuses_public_loopback_multicast_and_mapped_ranges() -> TestResult {
    let table = [
        ("8.8.8.0/24", "wrong_class"),
        ("10.0.0.0/8", "too_broad"),
        ("172.32.0.0/24", "wrong_class"),
        ("127.0.0.1", "wrong_class"),
        ("224.0.0.1", "wrong_class"),
        ("::ffff:10.0.0.1/128", "wrong_class"),
        ("::1/128", "wrong_class"),
        ("fe80::/64", "wrong_class"),
        ("2606:4700::/48", "wrong_class"),
        ("fc00::/7", "too_broad"),
    ];
    table
        .iter()
        .try_for_each(|(value, expected)| assert_refused("internal", value, expected))?;
    let (error, _) = refused(&scope_text("internal", &["10.1.0.0/24", "8.8.8.0/24"]))?;
    assert_eq!(refusal_name(&error), "wrong_class");
    assert_eq!(field_of(&error), "targets[1].value");
    Ok(())
}


#[test]
fn a_value_that_would_become_an_option_is_refused_as_a_target() -> TestResult {
    ["-iL /etc/shadow", "--config", "-x.example.org", "", "10.0.0.0/8x", "8.8.8.0/33"]
        .iter()
        .try_for_each(|value| assert_refused("external", value, "bad_target"))
}


#[test]
fn a_hostname_is_not_a_target_yet_in_either_kind() -> TestResult {
    let names = [
        "scan.example.com",
        "localtest.me",
        "app.example.org",
        "localhost",
        "0x7f.0x1",
        "*.example.org",
        "1.2.3",
    ];
    names.iter().try_for_each(|value| -> TestResult {
        assert_refused("external", value, "bad_target")?;
        assert_refused("internal", value, "bad_target")
    })?;
    let (_, message) = refused(&scope_text("internal", &["10.1.0.0/24", "scan.example.com"]))?;
    assert!(message.contains("hostnames are not supported yet"), "{message}");
    Ok(())
}


#[test]
fn breadth_is_checked_after_merging_adjacent_ranges() -> TestResult {
    let merged = scope_of(&scope_text("external", &["8.8.0.0/17", "8.8.128.0/17"]))?;
    assert_eq!(ranges_of(&merged), vec!["8.8.0.0/16"]);
    let (error, message) = refused(&scope_text("external", &["8.8.0.0/16", "8.9.0.0/16"]))?;
    assert_eq!(refusal_name(&error), "too_wide", "{message}");
    assert_eq!(field_of(&error), "targets");
    let (v6_error, _) = refused(&scope_text("external", &["2606:4700::/48", "2606:4700:1::/48"]))?;
    assert_eq!(refusal_name(&v6_error), "too_wide");
    let single_v6 = scope_of(&scope_text("external", &["2606:4700::/48", "2606:4700::/49"]))?;
    assert_eq!(single_v6.ranges.len(), 1);
    Ok(())
}


#[test]
fn two_hundred_fifty_six_adjacent_slash_24_make_one_slash_16_and_one_more_is_refused() -> TestResult {
    let all: Vec<String> = (0..ADJACENT_SLASH_24_COUNT).map(|third| format!("8.8.{third}.0/24")).collect();
    let mut values: Vec<&str> = all.iter().map(String::as_str).collect();
    let exact = scope_of(&scope_text("external", &values))?;
    assert_eq!(ranges_of(&exact), vec!["8.8.0.0/16"]);
    values.push("8.9.0.0/24");
    let (error, _) = refused(&scope_text("external", &values))?;
    assert_eq!(refusal_name(&error), "too_wide");
    Ok(())
}


#[test]
fn ports_are_validated_merged_and_counted() -> TestResult {
    let accepted_text = document("external", RATE, "[\"1-1024\"]", &block("8.8.8.8"));
    assert_eq!(
        scope_of(&accepted_text)?.ports,
        vec![PortRange {
            first: 1,
            last: MAX_PORTS_U16
        }]
    );
    let contained = document("external", RATE, "[\"1-100\", \"50-60\", 65535]", &block("8.8.8.8"));
    assert_eq!(
        scope_of(&contained)?.ports,
        vec![
            PortRange { first: 1, last: HUNDRED },
            PortRange {
                first: TOP_PORT,
                last: TOP_PORT
            }
        ]
    );
    let too_many = document("external", RATE, "[\"1-1025\"]", &block("8.8.8.8"));
    let (error, message) = refused(&too_many)?;
    assert_eq!(refusal_name(&error), "too_many_ports", "{message}");
    assert_eq!(field_of(&error), "ports");
    Ok(())
}


#[test]
fn a_bad_port_entry_is_refused_with_its_index() -> TestResult {
    let table = [
        "\"0\"",
        "0",
        "65536",
        "70000",
        "\"70000\"",
        "\"abc\"",
        "\"-5\"",
        "\"5-\"",
        "\"10-5\"",
        "\"+80\"",
        "\"80-90-100\"",
        "\"0-5\"",
        "\"-iL\"",
        "\"\"",
    ];
    table.iter().try_for_each(|entry| -> TestResult {
        let text = document("external", RATE, &format!("[22, {entry}]"), &block("8.8.8.8"));
        let (error, message) = refused(&text)?;
        assert_eq!(refusal_name(&error), "bad_port", "{entry}: {message}");
        assert_eq!(field_of(&error), "ports[1]");
        Ok(())
    })?;
    let number_text = document("external", RATE, &format!("[{OVERSIZED_PORT}]"), &block("8.8.8.8"));
    let (number_error, number_message) = refused(&number_text)?;
    assert!(number_message.contains("70000"), "{number_message}");
    assert_eq!(refusal_name(&number_error), "bad_port");
    Ok(())
}


#[test]
fn port_entries_and_targets_are_counted_and_must_not_be_empty() -> TestResult {
    let (empty_ports, _) = refused(&document("external", RATE, "[]", &block("8.8.8.8")))?;
    assert_eq!((refusal_name(&empty_ports), field_of(&empty_ports)), ("empty", "ports"));
    let entries = vec!["80"; MAX_PORT_ENTRIES + 1].join(", ");
    let (many_ports, _) = refused(&document("external", RATE, &format!("[{entries}]"), &block("8.8.8.8")))?;
    assert_eq!((refusal_name(&many_ports), field_of(&many_ports)), ("too_many", "ports"));
    let (empty_targets, _) = refused("kind: external\nrate_per_second: 10\nports: [22]\ntargets: []\n")?;
    assert_eq!((refusal_name(&empty_targets), field_of(&empty_targets)), ("empty", "targets"));
    let many: String = (0..=MAX_TARGETS).map(|_| block("8.8.8.8")).collect();
    let (many_targets, message) = refused(&document("external", RATE, "[22]", &many))?;
    assert_eq!((refusal_name(&many_targets), field_of(&many_targets)), ("too_many", "targets"));
    assert!(message.contains("1025"), "{message}");
    Ok(())
}


#[test]
fn the_rate_is_between_one_and_one_thousand() -> TestResult {
    [MIN_RATE, MAX_RATE].iter().try_for_each(|rate| -> TestResult {
        scope_of(&document("external", *rate, DEFAULT_PORTS, &block("8.8.8.8")))?;
        Ok(())
    })?;
    [0, ONE_OVER_RATE].iter().try_for_each(|rate| -> TestResult {
        let (error, message) = refused(&document("external", *rate, DEFAULT_PORTS, &block("8.8.8.8")))?;
        assert_eq!((refusal_name(&error), field_of(&error)), ("outside", "rate_per_second"), "{message}");
        Ok(())
    })
}


fn reference_block(reference: &str) -> String {
    format!("  - value: \"8.8.8.8\"\n    ownership: {{method: attestation, reference: \"{reference}\"}}\n")
}


#[test]
fn an_ownership_reference_is_a_short_plain_text() -> TestResult {
    let fitting = "r".repeat(MAX_REFERENCE_FITTING);
    scope_of(&document("external", RATE, "[22]", &reference_block(&fitting)))?;
    ["CHG-1234", "dns:_ostyr.example.com", "a/b_c.d"]
        .iter()
        .try_for_each(|reference| scope_of(&document("external", RATE, "[22]", &reference_block(reference))).map(|_| ()))?;
    let overlong = "r".repeat(OVERLONG_REFERENCE_BYTES);
    let table = [
        "",
        "-ticket",
        "-T1",
        "T 1",
        "two words",
        "tab\\there",
        "bidi\\u202e",
        "alice\\u3164approved",
        "a\\u2800b",
        "TICKET-\\u0421\\u0031",
        "_x",
        "a;b",
        &overlong,
    ];
    table.iter().try_for_each(|reference| -> TestResult {
        let (error, message) = refused(&document("external", RATE, "[22]", &reference_block(reference)))?;
        assert_eq!(refusal_name(&error), "bad_reference", "{message}");
        assert_eq!(field_of(&error), "targets[0].ownership.reference");
        Ok(())
    })
}


#[test]
fn a_missing_or_unknown_ownership_field_is_a_config_error() -> TestResult {
    let bodies = [
        "  - value: \"8.8.8.8\"\n",
        "  - value: \"8.8.8.8\"\n    ownership: {method: whois, reference: x}\n",
        "  - value: \"8.8.8.8\"\n    ownership: {method: dns_txt, reference: x, extra: 1}\n",
        "  - value: \"8.8.8.8\"\n    ownership: {method: dns_txt}\n",
    ];
    bodies.iter().try_for_each(|body| -> TestResult {
        let (error, message) = refused(&document("external", RATE, "[22]", body))?;
        assert_eq!(refusal_name(&error), "config", "{message}");
        assert!(message.starts_with(FILE), "{message}");
        Ok(())
    })?;
    let (kind_error, _) = refused(&document("both", RATE, "[22]", &block("8.8.8.8")))?;
    assert_eq!(refusal_name(&kind_error), "config");
    let (field_error, _) = refused(&format!("{}extra: 1\n", document("external", RATE, "[22]", &block("8.8.8.8"))))?;
    assert_eq!(refusal_name(&field_error), "config");
    Ok(())
}


#[test]
fn an_error_names_the_file_and_the_field_and_cuts_a_long_value_visibly() -> TestResult {
    let long = "z".repeat(LONG_VALUE_BYTES);
    let (_, message) = refused(&scope_text("external", &[&long]))?;
    assert!(message.starts_with("scope.yaml: targets[0].value: "), "{message}");
    assert!(message.contains(&format!("{}...", "z".repeat(SHOWN))), "{message}");
    assert!(!message.contains(&"z".repeat(SHOWN + 1)), "{message}");
    let (_, hidden) = refused(&scope_text("external", &["a\\u202eb\\nc"]))?;
    assert!(hidden.contains("\\u{202e}") && hidden.contains("\\u{a}"), "{hidden}");
    assert!(!hidden.contains('\u{202e}') && !hidden.contains('\n'), "{hidden}");
    Ok(())
}


#[test]
fn an_oversized_or_unreadable_file_is_refused_as_a_config_error() -> TestResult {
    let mut oversized = Cursor::new(vec![b' '; usize::try_from(MAX_FILE_BYTES)? + 1]);
    let error = parse_scope(&mut oversized, FILE).err().ok_or("accepted")?;
    assert_eq!(refusal_name(&error), "config");
    assert!(error.to_string().contains("larger than"), "{error}");
    let mut invalid_utf8: &[u8] = &[INVALID_FIRST, INVALID_SECOND];
    let utf8_error = parse_scope(&mut invalid_utf8, FILE).err().ok_or("accepted")?;
    assert_eq!(refusal_name(&utf8_error), "config");
    let exact = Cursor::new(scope_text("external", &["8.8.8.8"]).into_bytes());
    let mut limited = exact.take(MAX_FILE_BYTES);
    assert!(parse_scope(&mut limited, FILE).is_ok());
    Ok(())
}


#[test]
fn load_scope_reads_a_file_and_names_a_missing_one() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join(FILE);
    fs::write(&path, scope_text("external", &["8.8.8.8"]))?;
    assert_eq!(load_scope(&path)?.targets, vec!["8.8.8.8/32"]);
    let error = load_scope(&directory.path().join("missing.yaml")).err().ok_or("accepted")?;
    assert_eq!(refusal_name(&error), "config");
    assert!(error.source().is_none() || error.to_string().contains("missing.yaml"), "{error}");
    Ok(())
}


#[test]
fn a_refused_error_keeps_its_cause() -> TestResult {
    let (error, _) = refused(&scope_text("external", &["10.0.0.0/8"]))?;
    assert!(error.source().is_some());
    Ok(())
}


#[test]
fn in_ranges_and_port_allowed_answer_for_canonical_addresses() -> TestResult {
    let scope = scope_of(&scope_text("external", &["8.8.8.0/24", "9.9.9.0/24", "2606:4700::/48"]))?;
    let inside = ["8.8.8.8", "9.9.9.9", "::ffff:8.8.8.8", "2606:4700::1"];
    let outside = ["8.8.7.255", "8.8.9.0", "9.9.10.1", "1.1.1.1", "255.1.1.1", "2606:4701::1", "::1"];
    inside.iter().try_for_each(|text| -> TestResult {
        assert!(in_ranges(&scope, text.parse::<IpAddr>()?), "{text}");
        Ok(())
    })?;
    outside.iter().try_for_each(|text| -> TestResult {
        assert!(!in_ranges(&scope, text.parse::<IpAddr>()?), "{text}");
        Ok(())
    })?;
    assert!(port_allowed(&scope, SSH) && port_allowed(&scope, HTTP));
    assert!(!port_allowed(&scope, BELOW_SSH) && !port_allowed(&scope, HTTP_NEXT) && !port_allowed(&scope, 0));
    Ok(())
}


#[test]
fn validate_scope_works_on_a_parsed_file() -> TestResult {
    let parsed = core_config_parse(&scope_text("external", &["8.8.8.8"]))?;
    assert_eq!(validate_scope(&parsed, FILE)?.targets, vec!["8.8.8.8/32"]);
    Ok(())
}


fn core_config_parse(text: &str) -> Result<attack_surface::model::ScopeFile, Box<dyn Error>> {
    Ok(core_config::parse::parse_document(text, FILE)?)
}
