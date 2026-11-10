#[path = "common/refuse.rs"]
mod refuse;
#[path = "common/types.rs"]
mod types;


use refuse::refusing;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;
use synthetic_checks::transport::tcp_connect;
use types::TestResult;


const LEFT: Duration = Duration::from_secs(5);


const SHORT: Duration = Duration::from_millis(1);


const UNANSWERED: &str = "10.255.255.1:80";


#[test]
fn connects_to_an_open_port() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    tcp_connect(listener.local_addr()?, LEFT)?;
    Ok(())
}


#[test]
fn a_closed_port_is_refused() -> TestResult {
    let refused = refusing()?;
    let closed = refused.address;
    let error = tcp_connect(closed, LEFT).err().ok_or("expected a refusal")?;
    assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
    Ok(())
}


#[test]
fn a_zero_time_left_is_an_error() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let error = tcp_connect(listener.local_addr()?, Duration::ZERO).err().ok_or("expected an error")?;
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    Ok(())
}


#[test]
fn an_unanswered_address_fails_within_the_short_time_left() -> TestResult {
    assert!(tcp_connect(UNANSWERED.parse::<SocketAddr>()?, SHORT).is_err());
    Ok(())
}
