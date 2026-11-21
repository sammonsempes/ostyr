#[path = "common/types.rs"]
mod types;


use hardware_health::error::SmartError;
use hardware_health::model::{UpsReport, UpsTarget};
use hardware_health::ups_assess::ups_target_measures;
use hardware_health::ups_settings::parse_ups_settings;
use hardware_health::ups_target::{is_dns_name, is_ipv4, is_port, is_ups_name, parse_target, target_key};
use types::TestResult;


const OVER_SETTINGS: usize = 40_000;


const LABEL_MAX: usize = 63;


const NAME_MAX: usize = 32;


const TARGET_MAX: usize = 300;


const HOST_MAX: usize = 253;


const THREE: usize = 3;


const DEFAULT_DEADLINE: u64 = 30;


const DEFAULT_ROUND: u64 = 600;


const MAX_TARGETS: usize = 64;


const CHARGE: f64 = 90.0;


const HALF_HOST: usize = 40;


#[test]
fn accepted_targets() -> TestResult {
    let accepted = [
        "ups@localhost",
        "ups@host:3493",
        "My_UPS-1@ups.example.com:65535",
        "u@10.0.0.1",
        "u@0.0.0.0:1",
        "u@255.255.255.255",
        "a@a",
    ];
    accepted.iter().for_each(|text| assert!(parse_target(text).is_some(), "{text}"));
    let target = parse_target("Ups@host:3493").ok_or("refused")?;
    assert_eq!(
        (target.text.as_str(), target.ups.as_str(), target.host.as_str()),
        ("Ups@host:3493", "Ups", "host:3493")
    );
    Ok(())
}


#[test]
fn refused_targets() -> TestResult {
    let refused = [
        "-l@localhost",
        "ups@-h",
        "ups@host-",
        "ups@-a.example",
        "ups@a-.example",
        "ups@host:0",
        "ups@host:65536",
        "ups@host:",
        "ups@host:99999",
        "ups@host:123456",
        "default@host",
        "DEFAULT@host",
        "ups@127.1",
        "ups@2130706433",
        "ups@0x7f.1",
        "ups@010.0.0.1",
        "ups@256.0.0.1",
        "ups@1.2.3",
        "ups@1.2.3.4.5",
        "ups@1.2.3.",
        "ups@host:+3493",
        "ups@host:03493",
        "ups@host: 3493",
        "ups@host:3493x",
        "ups@host:1:2",
        "ups@[::1]",
        "ups@[::1]:3493",
        "a@b@c",
        "ups",
        "ups@",
        "@host",
        "ups@host.",
        "ups@.host",
        "ups@a..b",
        "ups@a.1",
        "ups@Host",
        "ups@ho st",
        "ups@host\u{2003}",
        "up.s@host",
        "up s@host",
        "_ups@host",
        "ups@host\n",
        "ups@h\u{fc}st",
        "",
    ];
    refused.iter().for_each(|text| assert!(parse_target(text).is_none(), "{text:?}"));
    Ok(())
}


#[test]
fn length_bounds() -> TestResult {
    assert!(is_ups_name(&"a".repeat(NAME_MAX)) && !is_ups_name(&"a".repeat(NAME_MAX + 1)) && !is_ups_name(""));
    assert!(is_dns_name(&"a".repeat(LABEL_MAX)) && !is_dns_name(&"a".repeat(LABEL_MAX + 1)));
    let long_host = format!("{0}.{0}.{0}.{1}", "a".repeat(LABEL_MAX), "a".repeat(HOST_MAX - THREE * LABEL_MAX - THREE));
    assert_eq!(long_host.len(), HOST_MAX);
    assert!(is_dns_name(&long_host));
    assert!(!is_dns_name(&format!("{long_host}a")));
    assert!(parse_target(&format!("ups@{}", "a".repeat(LABEL_MAX))).is_some());
    let too_long = format!("u@{0}.{0}.{0}.{0}", "a".repeat(LABEL_MAX));
    assert!(parse_target(&too_long).is_none());
    let longest = format!(
        "{}@{0}.{0}.{0}.{1}:65535",
        "a".repeat(NAME_MAX),
        "a".repeat(HOST_MAX - THREE * NAME_MAX - THREE)
    );
    assert!(parse_target(&longest).is_none());
    assert!(parse_target(&format!("u@host:{}", "1".repeat(TARGET_MAX))).is_none());
    Ok(())
}


#[test]
fn small_grammars() -> TestResult {
    assert!(is_ipv4("0.0.0.0") && is_ipv4("192.168.1.10") && !is_ipv4("1.2.3.04") && !is_ipv4("1.2.3.x") && !is_ipv4("1.2.3.1000"));
    assert!(!is_ipv4("1.2.3.") && !is_ipv4("1..3.4"));
    assert!(is_port("1") && is_port("65535") && is_port("3493") && !is_port("") && !is_port("0") && !is_port("65536") && !is_port("-1"));
    assert!(is_dns_name("localhost") && is_dns_name("a-b.c1.example") && !is_dns_name("") && !is_dns_name("a.b.1"));
    assert!(!is_dns_name("a.B"));
    assert!(is_ups_name("a") && is_ups_name("a_b-9") && !is_ups_name("-a") && !is_ups_name("a b") && !is_ups_name("default"));
    Ok(())
}


#[test]
fn duplicate_keys() -> TestResult {
    let key = |text: &str| parse_target(text).map(|target| target_key(&target)).ok_or("refused");
    assert_eq!(key("ups@h")?, key("ups@h:3493")?);
    assert_eq!(key("UPS@h")?, key("ups@h")?);
    assert_ne!(key("ups@h")?, key("ups@h:3494")?);
    assert_ne!(key("ups@h")?, key("ups@i")?);
    assert_ne!(key("ups1@h")?, key("ups2@h")?);
    Ok(())
}


#[test]
fn settings_file_bounds() -> TestResult {
    let ok = parse_ups_settings("ups_targets: [ups@h]\n")?;
    assert_eq!((ok.deadline_seconds, ok.round_deadline_seconds), (DEFAULT_DEADLINE, DEFAULT_ROUND));
    let many = |count: usize| format!("ups_targets: [{}]\n", vec!["ups@h"; count].join(","));
    assert_eq!(parse_ups_settings(&many(MAX_TARGETS))?.ups_targets.len(), MAX_TARGETS);
    assert!(matches!(
        parse_ups_settings(&many(MAX_TARGETS + 1)),
        Err(SmartError::SettingsField { field: "ups_targets" })
    ));
    assert!(matches!(
        parse_ups_settings("ups_targets: []\n"),
        Err(SmartError::SettingsField { field: "ups_targets" })
    ));
    assert!(matches!(parse_ups_settings("{}"), Err(SmartError::Settings(_))));
    assert!(matches!(
        parse_ups_settings("ups_targets: [a@b]\nprogram: /usr/sbin/reboot\n"),
        Err(SmartError::Settings(_))
    ));
    assert!(matches!(
        parse_ups_settings("ups_targets: [a@b]\ndeadline_seconds: 0\n"),
        Err(SmartError::SettingsField { field: "deadline_seconds" })
    ));
    assert!(matches!(
        parse_ups_settings("ups_targets: [a@b]\ndeadline_seconds: 121\n"),
        Err(SmartError::SettingsField { field: "deadline_seconds" })
    ));
    assert!(matches!(
        parse_ups_settings("ups_targets: [a@b]\nround_deadline_seconds: 3601\n"),
        Err(SmartError::SettingsField {
            field: "round_deadline_seconds"
        })
    ));
    assert!(matches!(
        parse_ups_settings(&format!("ups_targets: [a@b]\n{}", "#".repeat(OVER_SETTINGS))),
        Err(SmartError::SettingsTooLarge { .. })
    ));
    let marker = parse_ups_settings("ups_targets: [a@b]\nsurprise-MARKER: 1").err().ok_or("accepted")?;
    assert!(!format!("{marker}{marker:?}").contains("MARKER"));
    Ok(())
}


fn report() -> UpsReport {
    UpsReport {
        status: None,
        battery_charge: Some(CHARGE),
        battery_runtime: None,
        input_voltage: None,
        output_voltage: None,
        load: None,
        temperature: None,
        rejected_fields: 0,
        unreadable: Vec::new(),
    }
}


fn labels_of(text: &str) -> Result<Vec<Vec<(String, String)>>, &'static str> {
    let target: UpsTarget = parse_target(text).ok_or("refused")?;
    Ok(ups_target_measures(&report(), &target)
        .into_iter()
        .map(|measure| measure.labels)
        .collect())
}


#[test]
fn two_hosts_with_one_ups_name_give_distinct_series() -> TestResult {
    let first = labels_of("ups@alpha:3493")?;
    let second = labels_of("ups@beta")?;
    assert_eq!(
        first,
        vec![vec![("ups".to_owned(), "ups".to_owned()), ("host".to_owned(), "alpha:3493".to_owned())]]
    );
    assert_eq!(
        second,
        vec![vec![("ups".to_owned(), "ups".to_owned()), ("host".to_owned(), "beta".to_owned())]]
    );
    let unclean = format!("u@{0}.{0}", "a".repeat(HALF_HOST));
    assert!(labels_of(&unclean)?.is_empty());
    Ok(())
}
