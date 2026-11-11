#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use std::error::Error;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use synthetic_checks::transport::icmp_echo;
use types::TestResult;


const LEFT: Duration = Duration::from_secs(5);


fn ping_allowed() -> Result<bool, Box<dyn Error>> {
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ping_group_range")?;
    let bounds: Vec<u32> = range.split_whitespace().map(str::parse).collect::<Result<_, _>>()?;
    let gid = std::fs::metadata("/proc/self")?.gid();
    Ok(bounds.first().zip(bounds.get(1)).is_some_and(|(low, high)| (*low..=*high).contains(&gid)))
}


fn echo_loopback(address: IpAddr) -> TestResult {
    let result = icmp_echo(address, LEFT);
    if ping_allowed()? {
        result?;
    } else {
        assert!(result.err().ok_or("expected a refusal")?.to_string().contains("ping_group_range"));
    }
    Ok(())
}


#[test]
fn an_echo_to_ipv4_loopback_is_answered_or_the_group_range_is_named() -> TestResult {
    echo_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST))
}


#[test]
fn an_echo_to_ipv6_loopback_is_answered_or_the_group_range_is_named() -> TestResult {
    echo_loopback(IpAddr::V6(Ipv6Addr::LOCALHOST))
}


#[test]
fn an_overflowing_time_left_is_refused() -> TestResult {
    let error = icmp_echo(IpAddr::V4(Ipv4Addr::LOCALHOST), Duration::MAX)
        .err()
        .ok_or("expected an error")?;
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    Ok(())
}
