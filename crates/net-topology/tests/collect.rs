#[path = "common/types.rs"]
mod types;


use net_topology::collect::{collect_host, failure_of, PortFailure};
use net_topology::error::ParseError;
use net_topology::limits::{Limits, MAX_HOST_READ_BYTES_CEILING};
use types::TestResult;


const NOW: i64 = 1_700_000_000;


const HOST: &str = "server";


const MAC_ID: &str = r#"[{"type":"mac","value":"52:54:00:AA:BB:CC"}]"#;


const NEIGHBOURS_OVER_CAP: usize = 17;


const TRUNCATED_BYTES: usize = 20;


const TWO: usize = 2;


const TWO_AS_U64: u64 = 2;


const THREE_PORTS: usize = 3;


const FIVE_PORTS: usize = 5;


const LARGE_PORT_COUNT: usize = 20;


const SMALL_INTERFACES: usize = 2;


fn interface(name: &str, name_list: &str) -> String {
    format!(r#"{{"name":"{name}","chassis":[{{"id":{MAC_ID},"name":{name_list}}}],"port":[{{"id":{MAC_ID}}}]}}"#)
}


fn report(interfaces: &[String]) -> String {
    format!(r#"{{"lldp":[{{"interface":[{}]}}]}}"#, interfaces.join(","))
}


fn crowded() -> String {
    let chassis = vec![format!(r#"{{"id":{MAC_ID}}}"#); NEIGHBOURS_OVER_CAP].join(",");
    let ports = vec![format!(r#"{{"id":{MAC_ID}}}"#); NEIGHBOURS_OVER_CAP].join(",");
    format!(r#"{{"lldp":[{{"interface":[{{"name":"eth5","chassis":[{chassis}],"port":[{ports}]}}]}}]}}"#)
}


fn good(port: &str) -> String {
    report(&[interface(port, "[]")])
}


fn dispatch(port: &str, cap: u64) -> std::io::Result<Vec<u8>> {
    match port {
        "eth1" => Err(std::io::Error::other("injected")),
        "eth2" => Ok(good("eth0").into_bytes()),
        "eth3" => Ok(good("eth3").bytes().take(TRUNCATED_BYTES).collect()),
        "eth4" => Ok(vec![b' '; usize::try_from(cap).map_err(std::io::Error::other)? + 1]),
        "eth5" => Ok(crowded().into_bytes()),
        "eth6" => Ok(report(&[interface("eth6", "[{\"value\":\"a\u{1f}b\"}]")]).into_bytes()),
        other => Ok(good(other).into_bytes()),
    }
}


fn ports(list: &[&str]) -> Vec<String> {
    list.iter().map(|port| port.to_string()).collect()
}


#[test]
fn a_failed_port_keeps_the_links_of_the_others() -> TestResult {
    let read = collect_host(HOST, &ports(&["eth0", "eth1", "eth7"]), NOW, &Limits::default(), dispatch)?;
    assert_eq!(read.observations.len(), TWO);
    assert_eq!(read.failed_ports, vec![("eth1".to_string(), PortFailure::Io)]);
    assert_eq!(read.ports_run, THREE_PORTS);
    assert_eq!(read.skipped_budget, 0);
    Ok(())
}


#[test]
fn every_failure_kind_is_recorded_for_its_port_only() -> TestResult {
    let all = ports(&["eth2", "eth3", "eth4", "eth5", "eth0"]);
    let read = collect_host(HOST, &all, NOW, &Limits::default(), dispatch)?;
    let expected = vec![
        ("eth2".to_string(), PortFailure::WrongPort),
        ("eth3".to_string(), PortFailure::Malformed),
        ("eth4".to_string(), PortFailure::TooLarge),
        ("eth5".to_string(), PortFailure::TooMany),
    ];
    assert_eq!(read.failed_ports, expected);
    assert_eq!(read.observations.len(), 1);
    assert_eq!(read.ports_run, FIVE_PORTS);
    Ok(())
}


#[test]
fn skipped_counts_are_summed() -> TestResult {
    let read = collect_host(HOST, &ports(&["eth6", "eth6", "eth7"]), NOW, &Limits::default(), dispatch)?;
    assert_eq!(read.skipped.control_bytes, 1);
    assert_eq!(read.skipped.dropped_display, 1);
    assert_eq!(read.observations.len(), TWO);
    Ok(())
}


#[test]
fn the_budget_stops_the_remaining_ports() -> TestResult {
    let length = u64::try_from(good("eth0").len())?;
    let limits = Limits {
        max_port_bytes: length,
        max_host_read_bytes: TWO_AS_U64 * length,
        ..Limits::default()
    };
    let read = collect_host(HOST, &ports(&["eth0", "eth7", "eth8"]), NOW, &limits, dispatch)?;
    assert_eq!(read.ports_run, TWO);
    assert_eq!(read.skipped_budget, 1);
    assert_eq!(read.observations.len(), TWO);
    Ok(())
}


#[test]
fn a_repeated_name_runs_once() -> TestResult {
    let read = collect_host(HOST, &ports(&["eth0", "eth0"]), NOW, &Limits::default(), dispatch)?;
    assert_eq!(read.ports_run, 1);
    assert_eq!(read.observations.len(), 1);
    assert_eq!(read.refused_ports, 0);
    Ok(())
}


#[test]
fn refused_names_and_excess_ports_are_never_run() -> TestResult {
    let hostile = ports(&["vx0,eth0", "--help", "eth0"]);
    let read = collect_host(HOST, &hostile, NOW, &Limits::default(), dispatch)?;
    assert_eq!(read.ports_run, 1);
    assert_eq!(read.refused_ports, TWO);
    let limits = Limits {
        max_interfaces: SMALL_INTERFACES,
        ..Limits::default()
    };
    let many = (0..LARGE_PORT_COUNT).map(|i| format!("p{i}")).collect::<Vec<_>>();
    let capped = collect_host(HOST, &many, NOW, &limits, dispatch)?;
    assert_eq!(capped.ports_run, SMALL_INTERFACES);
    assert_eq!(capped.refused_ports, LARGE_PORT_COUNT - SMALL_INTERFACES);
    Ok(())
}


#[test]
fn only_a_bad_host_or_bad_limits_fail_the_host() -> TestResult {
    let all = ports(&["eth1"]);
    assert!(matches!(
        collect_host("", &all, NOW, &Limits::default(), dispatch),
        Err(ParseError::InvalidHost)
    ));
    let low = Limits {
        max_host_read_bytes: 1,
        ..Limits::default()
    };
    assert!(matches!(
        collect_host(HOST, &all, NOW, &low, dispatch),
        Err(ParseError::InvalidHostBytes { .. })
    ));
    let high = Limits {
        max_bytes: MAX_HOST_READ_BYTES_CEILING,
        max_host_read_bytes: MAX_HOST_READ_BYTES_CEILING + 1,
        ..Limits::default()
    };
    assert!(matches!(
        collect_host(HOST, &all, NOW, &high, dispatch),
        Err(ParseError::InvalidHostBytes { .. })
    ));
    let port_over_host = Limits {
        max_port_bytes: Limits::default().max_bytes + 1,
        ..Limits::default()
    };
    assert!(matches!(
        collect_host(HOST, &all, NOW, &port_over_host, dispatch),
        Err(ParseError::InvalidPortBytes { .. })
    ));
    Ok(())
}


#[test]
fn every_parse_error_maps_to_a_category() -> TestResult {
    let rejected = [ParseError::InvalidHost, ParseError::InvalidPort];
    rejected.iter().for_each(|error| assert_eq!(failure_of(error), PortFailure::Rejected));
    assert_eq!(failure_of(&ParseError::Read(std::io::Error::other("x"))), PortFailure::Io);
    Ok(())
}


const MEMORY_LIMIT_ENV: &str = "T409_MEMORY_CHILD";


const MEMORY_LIMIT_ARGUMENT: &str = "--as=419430400";


const FULL_PORT_COUNT: usize = 512;


const BUDGET_PORTS: usize = 8;


fn full_report(_port: &str, cap: u64) -> std::io::Result<Vec<u8>> {
    Ok(vec![b' '; usize::try_from(cap).map_err(std::io::Error::other)?])
}


fn every_port_answers_its_cap() -> TestResult {
    let all = (0..FULL_PORT_COUNT).map(|i| format!("p{i}")).collect::<Vec<_>>();
    let read = collect_host(HOST, &all, NOW, &Limits::default(), full_report)?;
    assert_eq!(read.ports_run, BUDGET_PORTS);
    assert_eq!(read.skipped_budget, FULL_PORT_COUNT - BUDGET_PORTS);
    assert_eq!(read.failed_ports.len(), BUDGET_PORTS);
    Ok(())
}


#[test]
fn memory_limited_child_stops_at_the_host_budget() -> TestResult {
    std::env::var(MEMORY_LIMIT_ENV).map_or(Ok(()), |_marker| every_port_answers_its_cap())
}


#[test]
fn five_hundred_full_ports_stop_at_the_budget_under_an_address_space_limit() -> TestResult {
    let output = std::process::Command::new("prlimit")
        .arg(MEMORY_LIMIT_ARGUMENT)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args(["--exact", "memory_limited_child_stops_at_the_host_budget", "--test-threads=1"])
        .env(MEMORY_LIMIT_ENV, "1")
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"), "the child test did not run");
    Ok(())
}
