#[path = "common/types.rs"]
mod types;


use std::cell::{Cell, RefCell};
use std::io;
use std::net::IpAddr;
use std::time::Duration;
use synthetic_checks::error::{GuardError, ProbeError};
use synthetic_checks::probe::{icmp_probe, probe_limits};
use synthetic_checks::target::guard_address;
use types::TestResult;


const TIMEOUT_SECONDS: u64 = 10;


const SLOW_STEP_SECONDS: u64 = 11;


const LATENCY_STEP_MS: u64 = 25;


const PUBLIC: &str = "93.184.216.34";


const PRIVATE: &str = "10.0.0.5";


fn limits() -> Result<synthetic_checks::probe::ProbeLimits, ProbeError> {
    probe_limits(Duration::from_secs(TIMEOUT_SECONDS), 1, 0)
}


#[test]
fn a_reply_succeeds_with_the_latency_of_the_injected_clock() -> TestResult {
    let now = Cell::new(0);
    let clock = || Duration::from_millis(now.get());
    let seen: RefCell<Vec<(IpAddr, Duration)>> = RefCell::new(Vec::new());
    let ping = |address: IpAddr, left: Duration| {
        seen.borrow_mut().push((address, left));
        now.set(LATENCY_STEP_MS);
        Ok(())
    };
    let outcome = icmp_probe(guard_address(PUBLIC.parse()?, &[])?, &limits()?, &ping, &clock)?;
    assert!(outcome.succeeded);
    assert_eq!(outcome.latency_ms, LATENCY_STEP_MS);
    assert_eq!(outcome.status, None);
    assert_eq!(*seen.borrow(), vec![(PUBLIC.parse()?, Duration::from_secs(TIMEOUT_SECONDS))]);
    Ok(())
}


#[test]
fn a_timed_out_ping_is_a_timeout() -> TestResult {
    let ping = |_: IpAddr, _: Duration| Err(io::Error::from(io::ErrorKind::TimedOut));
    let error = icmp_probe(guard_address(PUBLIC.parse()?, &[])?, &limits()?, &ping, &|| Duration::ZERO)
        .err()
        .ok_or("expected a timeout")?;
    assert!(matches!(error, ProbeError::Timeout { .. }));
    Ok(())
}


#[test]
fn another_ping_error_is_a_transport_error_with_its_cause() -> TestResult {
    let ping = |_: IpAddr, _: Duration| Err(io::Error::other("unreachable"));
    let error = icmp_probe(guard_address(PUBLIC.parse()?, &[])?, &limits()?, &ping, &|| Duration::ZERO)
        .err()
        .ok_or("expected an error")?;
    assert!(matches!(error, ProbeError::Transport(_)));
    assert!(std::error::Error::source(&error).is_some());
    Ok(())
}


#[test]
fn a_reply_after_the_deadline_is_a_timeout() -> TestResult {
    let now = Cell::new(0);
    let clock = || Duration::from_secs(now.get());
    let slow = |_: IpAddr, _: Duration| {
        now.set(SLOW_STEP_SECONDS);
        Ok(())
    };
    let error = icmp_probe(guard_address(PUBLIC.parse()?, &[])?, &limits()?, &slow, &clock)
        .err()
        .ok_or("expected a timeout")?;
    assert!(matches!(error, ProbeError::Timeout { .. }));
    Ok(())
}


#[test]
fn a_zero_timeout_never_pings() -> TestResult {
    let calls = Cell::new(0);
    let ping = |_: IpAddr, _: Duration| {
        calls.set(calls.get() + 1);
        Ok(())
    };
    let zero = probe_limits(Duration::ZERO, 1, 0)?;
    let error = icmp_probe(guard_address(PUBLIC.parse()?, &[])?, &zero, &ping, &|| Duration::ZERO)
        .err()
        .ok_or("expected a timeout")?;
    assert!(matches!(error, ProbeError::Timeout { .. }));
    assert_eq!(calls.get(), 0);
    Ok(())
}


#[test]
fn an_address_outside_the_scope_never_reaches_the_ping() -> TestResult {
    let calls = Cell::new(0);
    let ping = |_: IpAddr, _: Duration| {
        calls.set(calls.get() + 1);
        Ok(())
    };
    let refused = guard_address(PRIVATE.parse()?, &[]).err().ok_or("expected a refusal")?;
    assert!(matches!(refused, GuardError::Refused { .. }));
    let scope = ["10.0.0.0/8".parse()?];
    let outcome = icmp_probe(guard_address(PRIVATE.parse()?, &scope)?, &limits()?, &ping, &|| Duration::ZERO)?;
    assert!(outcome.succeeded);
    assert_eq!(calls.get(), 1);
    Ok(())
}
