#[path = "common/reader.rs"]
mod reader;
#[path = "common/types.rs"]
mod types;


use net_topology::error::ParseError;
use net_topology::limits::Limits;
use net_topology::lldp::parse_lldpd_port;
use net_topology::ports::{parse_ports, valid_port};
use reader::FailingReader;
use types::TestResult;


const NOW: i64 = 1_700_000_000;


const TWO_REFUSED: usize = 2;


const THREE_REFUSED: usize = 3;


const SMALL_INTERFACES: usize = 2;


const TOO_LONG: usize = 16;


const LONGEST: usize = 15;


const SMALL_BYTES: u64 = 8;


fn names(list: &[&str]) -> String {
    let entries = list
        .iter()
        .map(|name| format!(r#"{{"name":"{name}","via":"unknown"}}"#))
        .collect::<Vec<_>>();
    format!(r#"{{"lldp":[{{"interface":[{}]}}]}}"#, entries.join(","))
}


fn parse(text: &str) -> Result<net_topology::ports::PortList, ParseError> {
    parse_ports(text.as_bytes(), &Limits::default())
}


#[test]
fn the_live_interfaces_report_parses() -> TestResult {
    let live = include_bytes!("fixtures/lldpd-json0-interfaces.json");
    let list = parse_ports(live.as_slice(), &Limits::default())?;
    assert!(list.ports.iter().any(|port| port == "vx0"));
    assert_eq!(list.refused_ports, 0);
    list.ports.iter().for_each(|port| assert!(valid_port(port)));
    Ok(())
}


#[test]
fn refused_names_are_not_ports() -> TestResult {
    let sixteen = "a".repeat(TOO_LONG);
    let refused = [
        "eth0,eth1",
        "-x",
        "a b",
        "a/b",
        ".",
        "..",
        sixteen.as_str(),
        "eth0\u{3164}",
        "",
        "a:b",
        "--help",
        "a\nb",
    ];
    refused.iter().for_each(|name| assert!(!valid_port(name), "{name:?}"));
    let fifteen = "a".repeat(LONGEST);
    let accepted = ["eth0", "vx0", "ens3", "br-lan", "a.b_c@d+e", "x-", ".x", fifteen.as_str()];
    accepted.iter().for_each(|name| assert!(valid_port(name), "{name:?}"));
    Ok(())
}


#[test]
fn refused_and_repeated_entries_are_counted_or_merged() -> TestResult {
    let list = parse(&names(&["eth1", "eth0", "eth1", "eth0,eth1", "-x"]))?;
    assert_eq!(list.ports, vec!["eth0".to_string(), "eth1".to_string()]);
    assert_eq!(list.refused_ports, TWO_REFUSED);
    let odd = parse(r#"{"lldp":[{"interface":[{"via":"x"},"text",{"name":5}]}]}"#)?;
    assert_eq!(odd.refused_ports, THREE_REFUSED);
    assert!(parse(r#"{"lldp":[{}]}"#)?.ports.is_empty());
    Ok(())
}


#[test]
fn a_hostile_interface_report_is_refused_by_size_count_or_shape() -> TestResult {
    let many = names(&["a", "b", "c"]);
    let limits = Limits {
        max_interfaces: SMALL_INTERFACES,
        ..Limits::default()
    };
    assert!(matches!(
        parse_ports(many.as_bytes(), &limits),
        Err(ParseError::TooMany { list: "interface", .. })
    ));
    let tiny = Limits {
        max_bytes: SMALL_BYTES,
        max_port_bytes: SMALL_BYTES,
        max_host_read_bytes: SMALL_BYTES,
        ..Limits::default()
    };
    assert!(matches!(parse_ports(many.as_bytes(), &tiny), Err(ParseError::TooLarge { .. })));
    assert!(matches!(parse("[]"), Err(ParseError::Malformed { .. })));
    assert!(matches!(parse(r#"{"lldp":[[]]}"#), Err(ParseError::Malformed { .. })));
    assert!(matches!(parse(r#"{"lldp":[{"interface":"x"}]}"#), Err(ParseError::Malformed { .. })));
    assert!(matches!(parse(r#"{"lldp":[{},{}]}"#), Err(ParseError::TooMany { list: "lldp", .. })));
    assert!(matches!(parse(r#"{"lldp":{}}"#), Err(ParseError::Malformed { .. })));
    assert!(matches!(parse_ports(FailingReader, &Limits::default()), Err(ParseError::Read(_))));
    Ok(())
}


#[test]
fn a_port_name_with_a_comma_is_refused_before_reading() -> TestResult {
    let outcome = parse_lldpd_port(FailingReader, "server", "eth0,eth1", NOW, &Limits::default());
    assert!(matches!(outcome, Err(ParseError::InvalidPort)));
    let flag = parse_lldpd_port(FailingReader, "server", "--help", NOW, &Limits::default());
    assert!(matches!(flag, Err(ParseError::InvalidPort)));
    let valid = parse_lldpd_port(FailingReader, "server", "eth0", NOW, &Limits::default());
    assert!(matches!(valid, Err(ParseError::Read(_))));
    Ok(())
}
