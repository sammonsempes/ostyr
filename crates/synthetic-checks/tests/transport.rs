#[path = "common/refuse.rs"]
mod refuse;
#[path = "common/types.rs"]
mod types;


use refuse::refusing;
use std::cell::Cell;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::time::{Duration, Instant};
use synthetic_checks::transport::{
    await_reply, echo_request, receive, refused_socket, reply_matches, tcp_connect, timeout_kind, ECHO_REPLY_V4, ECHO_REPLY_V6, ECHO_REQUEST_V4,
    ECHO_REQUEST_V6, FOREIGN_FLOOD, MAX_FOREIGN_REPLIES,
};
use types::TestResult;


const LEFT: Duration = Duration::from_secs(5);


const SHORT: Duration = Duration::from_millis(1);


const SILENT_WAIT: Duration = Duration::from_millis(50);


const UNANSWERED: &str = "10.255.255.1:80";


const PAYLOAD: [u8; 4] = [1, 2, 3, 4];


const REVERSED_PAYLOAD: [u8; 4] = [4, 3, 2, 1];


const SHORT_PAYLOAD: [u8; 3] = [1, 2, 3];


const LONG_PAYLOAD: [u8; 5] = [1, 2, 3, 4, 5];


const FOREIGN_PAYLOAD: [u8; 1] = [9];


const OTHER_HOST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);


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


fn target_v4() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}


fn target_v6() -> IpAddr {
    IpAddr::V6(Ipv6Addr::LOCALHOST)
}


fn v4_mapped() -> IpAddr {
    IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped())
}


fn message(kind: u8, payload: &[u8]) -> Vec<u8> {
    [kind, 0, 0, 0, 0, 0, 0, 1].into_iter().chain(payload.iter().copied()).collect()
}


#[test]
fn the_request_has_the_family_type_and_our_payload() -> TestResult {
    assert_eq!(echo_request(target_v4(), &PAYLOAD), message(ECHO_REQUEST_V4, &PAYLOAD));
    assert_eq!(echo_request(target_v6(), &PAYLOAD), message(ECHO_REQUEST_V6, &PAYLOAD));
    Ok(())
}


#[test]
fn a_genuine_reply_matches() -> TestResult {
    assert!(reply_matches(&message(ECHO_REPLY_V4, &PAYLOAD), target_v4(), target_v4(), &PAYLOAD));
    assert!(reply_matches(&message(ECHO_REPLY_V6, &PAYLOAD), target_v6(), target_v6(), &PAYLOAD));
    assert!(reply_matches(&message(ECHO_REPLY_V4, &PAYLOAD), v4_mapped(), target_v4(), &PAYLOAD));
    Ok(())
}


#[test]
fn a_foreign_type_is_refused() -> TestResult {
    assert!(!reply_matches(&message(ECHO_REQUEST_V4, &PAYLOAD), target_v4(), target_v4(), &PAYLOAD));
    assert!(!reply_matches(&message(ECHO_REPLY_V6, &PAYLOAD), target_v4(), target_v4(), &PAYLOAD));
    Ok(())
}


#[test]
fn a_foreign_payload_is_refused() -> TestResult {
    assert!(!reply_matches(
        &message(ECHO_REPLY_V4, &REVERSED_PAYLOAD),
        target_v4(),
        target_v4(),
        &PAYLOAD
    ));
    assert!(!reply_matches(
        &message(ECHO_REPLY_V4, &SHORT_PAYLOAD),
        target_v4(),
        target_v4(),
        &PAYLOAD
    ));
    assert!(!reply_matches(&message(ECHO_REPLY_V4, &LONG_PAYLOAD), target_v4(), target_v4(), &PAYLOAD));
    Ok(())
}


#[test]
fn a_foreign_source_is_refused() -> TestResult {
    assert!(!reply_matches(
        &message(ECHO_REPLY_V4, &PAYLOAD),
        IpAddr::V4(OTHER_HOST),
        target_v4(),
        &PAYLOAD
    ));
    Ok(())
}


#[test]
fn a_truncated_reply_is_refused() -> TestResult {
    assert!(!reply_matches(&[ECHO_REPLY_V4, 0, 0], target_v4(), target_v4(), &[]));
    assert!(!reply_matches(&[], target_v4(), target_v4(), &[]));
    Ok(())
}


#[test]
fn foreign_packets_are_dropped_then_the_reply_is_accepted() -> TestResult {
    let reads = Cell::new(0);
    let mut next = || {
        reads.set(reads.get() + 1);
        let payload: &[u8] = if reads.get() < MAX_FOREIGN_REPLIES { &FOREIGN_PAYLOAD } else { &PAYLOAD };
        Ok((message(ECHO_REPLY_V4, payload), target_v4()))
    };
    await_reply(&mut next, target_v4(), &PAYLOAD)?;
    assert_eq!(reads.get(), MAX_FOREIGN_REPLIES);
    Ok(())
}


#[test]
fn a_flood_of_foreign_packets_ends_after_a_bounded_number_of_reads() -> TestResult {
    let reads = Cell::new(0);
    let mut next = || {
        reads.set(reads.get() + 1);
        Ok((message(ECHO_REPLY_V4, &FOREIGN_PAYLOAD), target_v4()))
    };
    let error = await_reply(&mut next, target_v4(), &PAYLOAD).err().ok_or("expected an error")?;
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert_eq!(error.to_string(), FOREIGN_FLOOD);
    assert_eq!(reads.get(), MAX_FOREIGN_REPLIES);
    Ok(())
}


#[test]
fn a_read_error_ends_the_wait() -> TestResult {
    let mut next = || Err(io::Error::from(ErrorKind::ConnectionReset));
    let error = await_reply(&mut next, target_v4(), &PAYLOAD).err().ok_or("expected an error")?;
    assert_eq!(error.kind(), ErrorKind::ConnectionReset);
    Ok(())
}


#[test]
fn read_timeouts_become_timed_out_and_other_errors_stay() -> TestResult {
    assert_eq!(timeout_kind(io::Error::from(ErrorKind::WouldBlock)).kind(), ErrorKind::TimedOut);
    assert_eq!(timeout_kind(io::Error::from(ErrorKind::NotFound)).kind(), ErrorKind::NotFound);
    Ok(())
}


#[test]
fn a_refused_socket_names_the_group_range_and_keeps_its_cause() -> TestResult {
    let error = refused_socket(io::Error::from(ErrorKind::PermissionDenied));
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("ping_group_range"));
    assert!(error.get_ref().ok_or("no inner error")?.source().is_some());
    Ok(())
}


#[test]
fn receive_ends_at_a_passed_deadline_and_at_a_silent_socket() -> TestResult {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let passed = receive(&socket, Instant::now()).err().ok_or("expected a timeout")?;
    assert_eq!(passed.kind(), ErrorKind::TimedOut);
    let silent = receive(&socket, Instant::now() + SILENT_WAIT).err().ok_or("expected a timeout")?;
    assert_eq!(silent.kind(), ErrorKind::TimedOut);
    Ok(())
}


#[test]
fn receive_returns_the_packet_and_its_source() -> TestResult {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    sender.send_to(&PAYLOAD, socket.local_addr()?)?;
    let (packet, source) = receive(&socket, Instant::now() + LEFT)?;
    assert_eq!(packet, PAYLOAD);
    assert_eq!(source, target_v4());
    Ok(())
}
