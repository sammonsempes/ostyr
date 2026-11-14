#[path = "common/types.rs"]
mod types;


use net_topology::collect::{charge_of, collect_host, failure_of, run_failure_category, PortFailure};
use net_topology::error::ParseError;
use net_topology::limits::{Limits, MAX_HOST_READ_BYTES_CEILING};
use net_topology::model::RunFailure;
use std::time::{Duration, Instant};
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


fn frozen() -> impl FnMut() -> Instant {
    let now = Instant::now();
    move || now
}


fn dispatch(port: &str, cap: u64, _timeout: Duration) -> Result<Vec<u8>, RunFailure> {
    match port {
        "eth1" => Err(RunFailure::Io),
        "eth2" => Ok(good("eth0").into_bytes()),
        "eth3" => Ok(good("eth3").bytes().take(TRUNCATED_BYTES).collect()),
        "eth4" => usize::try_from(cap).map_or(Err(RunFailure::Io), |size| Ok(vec![b' '; size + 1])),
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
    let read = collect_host(HOST, &ports(&["eth0", "eth1", "eth7"]), NOW, &Limits::default(), dispatch, &mut frozen())?;
    assert_eq!(read.observations.len(), TWO);
    assert_eq!(read.failed_ports, vec![("eth1".to_string(), PortFailure::Io)]);
    assert_eq!(read.ports_run, THREE_PORTS);
    assert_eq!(read.skipped_budget, 0);
    Ok(())
}


#[test]
fn every_failure_kind_is_recorded_for_its_port_only() -> TestResult {
    let all = ports(&["eth2", "eth3", "eth4", "eth5", "eth0"]);
    let read = collect_host(HOST, &all, NOW, &Limits::default(), dispatch, &mut frozen())?;
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
    let read = collect_host(HOST, &ports(&["eth6", "eth6", "eth7"]), NOW, &Limits::default(), dispatch, &mut frozen())?;
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
    let read = collect_host(HOST, &ports(&["eth0", "eth7", "eth8"]), NOW, &limits, dispatch, &mut frozen())?;
    assert_eq!(read.ports_run, TWO);
    assert_eq!(read.skipped_budget, 1);
    assert_eq!(read.observations.len(), TWO);
    Ok(())
}


#[test]
fn a_repeated_name_runs_once() -> TestResult {
    let read = collect_host(HOST, &ports(&["eth0", "eth0"]), NOW, &Limits::default(), dispatch, &mut frozen())?;
    assert_eq!(read.ports_run, 1);
    assert_eq!(read.observations.len(), 1);
    assert_eq!(read.refused_ports, 0);
    Ok(())
}


#[test]
fn refused_names_and_excess_ports_are_never_run() -> TestResult {
    let hostile = ports(&["vx0,eth0", "--help", "eth0"]);
    let read = collect_host(HOST, &hostile, NOW, &Limits::default(), dispatch, &mut frozen())?;
    assert_eq!(read.ports_run, 1);
    assert_eq!(read.refused_ports, TWO);
    let limits = Limits {
        max_interfaces: SMALL_INTERFACES,
        ..Limits::default()
    };
    let many = (0..LARGE_PORT_COUNT).map(|i| format!("p{i}")).collect::<Vec<_>>();
    let capped = collect_host(HOST, &many, NOW, &limits, dispatch, &mut frozen())?;
    assert_eq!(capped.ports_run, SMALL_INTERFACES);
    assert_eq!(capped.refused_ports, 0);
    assert_eq!(capped.excess_ports, LARGE_PORT_COUNT - SMALL_INTERFACES);
    Ok(())
}


#[test]
fn only_a_bad_host_or_bad_limits_fail_the_host() -> TestResult {
    let all = ports(&["eth1"]);
    assert!(matches!(
        collect_host("", &all, NOW, &Limits::default(), dispatch, &mut frozen()),
        Err(ParseError::InvalidHost)
    ));
    let low = Limits {
        max_host_read_bytes: 1,
        ..Limits::default()
    };
    assert!(matches!(
        collect_host(HOST, &all, NOW, &low, dispatch, &mut frozen()),
        Err(ParseError::InvalidHostBytes { .. })
    ));
    let high = Limits {
        max_bytes: MAX_HOST_READ_BYTES_CEILING,
        max_host_read_bytes: MAX_HOST_READ_BYTES_CEILING + 1,
        ..Limits::default()
    };
    assert!(matches!(
        collect_host(HOST, &all, NOW, &high, dispatch, &mut frozen()),
        Err(ParseError::InvalidHostBytes { .. })
    ));
    let port_over_host = Limits {
        max_port_bytes: Limits::default().max_bytes + 1,
        ..Limits::default()
    };
    assert!(matches!(
        collect_host(HOST, &all, NOW, &port_over_host, dispatch, &mut frozen()),
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


fn full_report(_port: &str, cap: u64, _timeout: Duration) -> Result<Vec<u8>, RunFailure> {
    usize::try_from(cap).map_or(Err(RunFailure::Io), |size| Ok(vec![b' '; size]))
}


fn every_port_answers_its_cap() -> TestResult {
    let all = (0..FULL_PORT_COUNT).map(|i| format!("p{i}")).collect::<Vec<_>>();
    let read = collect_host(HOST, &all, NOW, &Limits::default(), full_report, &mut frozen())?;
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


const BAD_EXIT_CODE: i32 = 3;


const BAD_EXIT_READ: u64 = 10;


const SMALL_PORT_CAP: u64 = 100;


const CLOCK_STEP_SECONDS: u64 = 30;


const RUNS_BEFORE_TIME_OUT: usize = 4;


const CUSTOM_TIMEOUT_SECONDS: u64 = 7;


const MIN_TIMEOUT: u64 = 0;


const OVER_TIMEOUT: u64 = 61;


const MAX_TIMEOUT: u64 = 60;


const BELOW_PORT_TIMEOUT: u64 = 9;


const OVER_CEILING: u64 = 3_601;


fn fail_with(failure: RunFailure) -> Result<Vec<u8>, RunFailure> {
    Err(failure)
}


fn too_large(_port: &str, _cap: u64, _timeout: Duration) -> Result<Vec<u8>, RunFailure> {
    fail_with(RunFailure::TooLarge)
}


fn timed_out(_port: &str, _cap: u64, _timeout: Duration) -> Result<Vec<u8>, RunFailure> {
    fail_with(RunFailure::TimedOut)
}


fn spawn_failed(_port: &str, _cap: u64, _timeout: Duration) -> Result<Vec<u8>, RunFailure> {
    fail_with(RunFailure::Spawn)
}


fn bad_exit(_port: &str, _cap: u64, _timeout: Duration) -> Result<Vec<u8>, RunFailure> {
    fail_with(RunFailure::Failed {
        code: Some(BAD_EXIT_CODE),
        read: BAD_EXIT_READ,
    })
}


fn refused(_port: &str, _cap: u64, _timeout: Duration) -> Result<Vec<u8>, RunFailure> {
    fail_with(RunFailure::Refused)
}


fn io_failed(_port: &str, _cap: u64, _timeout: Duration) -> Result<Vec<u8>, RunFailure> {
    fail_with(RunFailure::Io)
}


fn custom_timeout_only(port: &str, _cap: u64, timeout: Duration) -> Result<Vec<u8>, RunFailure> {
    if timeout == Duration::from_secs(CUSTOM_TIMEOUT_SECONDS) {
        Ok(good(port).into_bytes())
    } else {
        fail_with(RunFailure::Io)
    }
}


fn numbered(count: usize) -> Vec<String> {
    (0..count).map(|i| format!("p{i}")).collect()
}


fn clock_every(step: Duration) -> impl FnMut() -> Instant {
    let base = Instant::now();
    let mut calls = u32::MIN;
    move || {
        let now = base + step * calls;
        calls += 1;
        now
    }
}


fn failed_all(read: &net_topology::collect::HostRead, expected: PortFailure) -> bool {
    read.failed_ports.iter().all(|(_port, failure)| *failure == expected)
}


#[test]
fn a_too_large_port_spends_the_whole_port_cap() -> TestResult {
    let read = collect_host(HOST, &numbered(FULL_PORT_COUNT), NOW, &Limits::default(), too_large, &mut frozen())?;
    assert_eq!(read.ports_run, BUDGET_PORTS);
    assert_eq!(read.skipped_budget, FULL_PORT_COUNT - BUDGET_PORTS);
    assert!(failed_all(&read, PortFailure::TooLarge));
    Ok(())
}


#[test]
fn a_timed_out_or_io_port_spends_the_whole_port_cap() -> TestResult {
    let timed = collect_host(HOST, &numbered(FULL_PORT_COUNT), NOW, &Limits::default(), timed_out, &mut frozen())?;
    assert_eq!(timed.ports_run, BUDGET_PORTS);
    assert!(failed_all(&timed, PortFailure::TimedOut));
    let io = collect_host(HOST, &numbered(FULL_PORT_COUNT), NOW, &Limits::default(), io_failed, &mut frozen())?;
    assert_eq!(io.ports_run, BUDGET_PORTS);
    assert!(failed_all(&io, PortFailure::Io));
    Ok(())
}


#[test]
fn a_spawn_failure_or_refusal_spends_nothing() -> TestResult {
    let spawn = collect_host(HOST, &numbered(FULL_PORT_COUNT), NOW, &Limits::default(), spawn_failed, &mut frozen())?;
    assert_eq!(spawn.ports_run, FULL_PORT_COUNT);
    assert!(failed_all(&spawn, PortFailure::Spawn));
    let refusal = collect_host(HOST, &numbered(FULL_PORT_COUNT), NOW, &Limits::default(), refused, &mut frozen())?;
    assert_eq!(refusal.ports_run, FULL_PORT_COUNT);
    assert!(failed_all(&refusal, PortFailure::Rejected));
    Ok(())
}


#[test]
fn a_bad_exit_spends_what_it_read() -> TestResult {
    let limits = Limits {
        max_port_bytes: SMALL_PORT_CAP,
        max_host_read_bytes: SMALL_PORT_CAP,
        ..Limits::default()
    };
    let exit = collect_host(HOST, &numbered(FULL_PORT_COUNT), NOW, &limits, bad_exit, &mut frozen())?;
    assert_eq!(u64::try_from(exit.ports_run)?, SMALL_PORT_CAP / BAD_EXIT_READ);
    assert!(failed_all(&exit, PortFailure::Failed));
    Ok(())
}


#[test]
fn the_host_time_budget_skips_the_remaining_ports_from_the_fifth() -> TestResult {
    let mut clock = clock_every(Duration::from_secs(CLOCK_STEP_SECONDS));
    let read = collect_host(HOST, &numbered(FULL_PORT_COUNT), NOW, &Limits::default(), spawn_failed, &mut clock)?;
    assert_eq!(read.ports_run, RUNS_BEFORE_TIME_OUT);
    assert_eq!(read.skipped_time, FULL_PORT_COUNT - RUNS_BEFORE_TIME_OUT);
    assert_eq!(read.skipped_budget, 0);
    assert_eq!(read.failed_ports.len(), RUNS_BEFORE_TIME_OUT);
    Ok(())
}


#[test]
fn the_time_limits_are_validated() -> TestResult {
    let all = ports(&["eth1"]);
    let cases = [
        (MIN_TIMEOUT, Limits::default().max_host_seconds),
        (OVER_TIMEOUT, Limits::default().max_host_seconds),
        (Limits::default().port_timeout_seconds, BELOW_PORT_TIMEOUT),
        (Limits::default().port_timeout_seconds, OVER_CEILING),
    ];
    cases.iter().try_for_each(|(per_port, host)| -> TestResult {
        let limits = Limits {
            port_timeout_seconds: *per_port,
            max_host_seconds: *host,
            ..Limits::default()
        };
        let result = collect_host(HOST, &all, NOW, &limits, dispatch, &mut frozen());
        assert!(matches!(
            result,
            Err(ParseError::InvalidPortSeconds { .. } | ParseError::InvalidHostSeconds { .. })
        ));
        Ok(())
    })?;
    let edge = Limits {
        port_timeout_seconds: MAX_TIMEOUT,
        max_host_seconds: MAX_TIMEOUT,
        ..Limits::default()
    };
    assert!(collect_host(HOST, &all, NOW, &edge, dispatch, &mut frozen()).is_ok());
    Ok(())
}


#[test]
fn the_runner_receives_the_configured_port_deadline() -> TestResult {
    let limits = Limits {
        port_timeout_seconds: CUSTOM_TIMEOUT_SECONDS,
        ..Limits::default()
    };
    let read = collect_host(HOST, &ports(&["eth1"]), NOW, &limits, custom_timeout_only, &mut frozen())?;
    assert!(read.failed_ports.is_empty());
    assert_eq!(read.observations.len(), 1);
    Ok(())
}


const UNWAITABLE_CHARGE: u64 = 7;


#[test]
fn an_unwaitable_child_is_an_io_failure_charged_at_the_worst_case() -> TestResult {
    assert_eq!(run_failure_category(&RunFailure::Unwaitable), PortFailure::Io);
    assert_eq!(charge_of(&RunFailure::Unwaitable, UNWAITABLE_CHARGE), UNWAITABLE_CHARGE);
    Ok(())
}
