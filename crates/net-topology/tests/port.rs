#[path = "common/types.rs"]
mod types;


use net_topology::error::{ListError, ParseError};
use net_topology::limits::Limits;
use net_topology::lldp::{bounded_list, parse_lldpd, parse_lldpd_port};
use net_topology::model::Parsed;
use serde_json::value::RawValue;
use types::TestResult;


const NOW: i64 = 1_700_000_000;


const HOST: &str = "server";


const MARKER: &str = "SECRETMARKER";


const MAC_ID: &str = r#"[{"type":"mac","value":"52:54:00:AA:BB:CC"}]"#;


const FOREIGN_COUNT: usize = 2;


const PORT_CAP: u64 = 2;


const HOST_CAP: u64 = 1;


const SMALL_LIST_MAX: usize = 4;


fn interface(name: &str, name_list: &str) -> String {
    format!(r#"{{"name":"{name}","chassis":[{{"id":{MAC_ID},"name":{name_list}}}],"port":[{{"id":{MAC_ID}}}]}}"#)
}


fn report(interfaces: &[String]) -> String {
    format!(r#"{{"lldp":[{{"interface":[{}]}}]}}"#, interfaces.join(","))
}


fn parse_port(text: &str, port: &str, limits: &Limits) -> Result<Parsed, ParseError> {
    parse_lldpd_port(text.as_bytes(), HOST, port, NOW, limits)
}


#[test]
fn the_live_fixture_of_one_port_parses_for_that_port_only() -> TestResult {
    let live = include_bytes!("fixtures/lldpd-json0.json");
    let parsed = parse_lldpd_port(live.as_slice(), HOST, "vx0", NOW, &Limits::default())?;
    assert_eq!(parsed.observations.len(), 1);
    let other = parse_lldpd_port(live.as_slice(), HOST, "eth0", NOW, &Limits::default());
    assert!(matches!(other, Err(ParseError::WrongPort { count: 1 })));
    Ok(())
}


#[test]
fn a_forged_two_port_report_is_refused_and_counted_without_text() -> TestResult {
    let text = report(&[interface("eth0", "[]"), interface("eth1", "[]"), interface("eth1", "[]")]);
    let outcome = parse_port(&text, "eth0", &Limits::default());
    assert!(matches!(outcome, Err(ParseError::WrongPort { count: FOREIGN_COUNT })));
    let message = format!("{}", outcome.err().ok_or("no error")?);
    assert!(!message.contains("eth1"));
    Ok(())
}


#[test]
fn a_report_above_the_port_cap_is_too_large_for_that_port_only() -> TestResult {
    let small = report(&[interface("eth0", "[]")]);
    let big = report(&[interface("eth1", "[]"), interface("eth1", "[]")]);
    let small_length = u64::try_from(small.len())?;
    let limits = Limits {
        max_port_bytes: small_length,
        max_bytes: u64::try_from(big.len())?,
        ..Limits::default()
    };
    assert!(parse_port(&small, "eth0", &limits).is_ok());
    let refused = parse_port(&big, "eth1", &limits);
    assert!(matches!(refused, Err(ParseError::TooLarge { max }) if max == small_length));
    assert!(parse_lldpd(big.as_bytes(), HOST, NOW, &limits).is_ok());
    Ok(())
}


#[test]
fn a_port_cap_above_the_host_cap_is_refused() -> TestResult {
    let limits = Limits {
        max_port_bytes: PORT_CAP,
        max_bytes: HOST_CAP,
        ..Limits::default()
    };
    let outcome = parse_port(&report(&[interface("eth0", "[]")]), "eth0", &limits);
    assert!(matches!(
        outcome,
        Err(ParseError::InvalidPortBytes {
            per_port: PORT_CAP,
            per_host: HOST_CAP
        })
    ));
    let bad_host = parse_lldpd_port("{}".as_bytes(), "", "eth0", NOW, &Limits::default());
    assert!(matches!(bad_host, Err(ParseError::InvalidHost)));
    Ok(())
}


#[test]
fn a_wrongly_typed_list_leaks_no_input_text() -> TestResult {
    let raw: Box<RawValue> = serde_json::from_str(&format!("\"{MARKER}\""))?;
    let error = bounded_list(Some(&raw), SMALL_LIST_MAX).err().ok_or("no error")?;
    assert!(matches!(error, ListError::Shape { .. }));
    assert!(!format!("{error}").contains(MARKER));
    assert!(!format!("{error:?}").contains(MARKER));
    let text = format!(r#"{{"lldp":[{{"interface":"{MARKER}"}}]}}"#);
    let outcome = parse_lldpd(text.as_bytes(), HOST, NOW, &Limits::default());
    let refused = outcome.err().ok_or("no error")?;
    assert!(matches!(refused, ParseError::Malformed { .. }));
    assert!(!format!("{refused}").contains(MARKER));
    assert!(!format!("{refused:?}").contains(MARKER));
    Ok(())
}


#[test]
fn an_empty_name_list_is_empty_whatever_its_spacing() -> TestResult {
    ["[]", "[ ]", "[\n]"].iter().try_for_each(|spelling| -> TestResult {
        let parsed = parse_port(&report(&[interface("eth0", spelling)]), "eth0", &Limits::default())?;
        assert_eq!(parsed.skipped.dropped_display, 0);
        assert_eq!(parsed.observations.len(), 1);
        Ok(())
    })?;
    let hostile = parse_port(&report(&[interface("eth0", r#"[{"value":"-x"}]"#)]), "eth0", &Limits::default())?;
    assert_eq!(hostile.skipped.dropped_display, 1);
    Ok(())
}
