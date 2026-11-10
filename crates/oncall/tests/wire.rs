#[path = "common/types.rs"]
mod types;


use oncall::error::TransportError;
use oncall::limits::{MAX_REPLY_BYTES, MAX_REPLY_LINE_BYTES};
use oncall::wire::{connect_first, io_error, parse_line, parse_reply, read_reply, remaining};
use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, TcpListener};
use std::time::{Duration, Instant};
use types::TestResult;


const GENEROUS: Duration = Duration::from_secs(60);


const UNUSED_PORT: u16 = 1;


const LOOPBACK: [u8; 4] = [127, 0, 0, 1];


const FLOOD_FACTOR: usize = 8;


const CODE_OK: u16 = 250;


const CODE_READY: u16 = 220;


const FLOOD_CHUNK: usize = 512;


fn feed<'data>(data: &'data [u8], consumed: &'data mut usize) -> impl FnMut(&mut [u8]) -> Result<usize, TransportError> + 'data {
    move |buffer: &mut [u8]| {
        let available = data.get(*consumed..).unwrap_or(&[]);
        let count = available.len().min(buffer.len());
        buffer
            .iter_mut()
            .zip(available.iter())
            .take(count)
            .for_each(|(target, source)| *target = *source);
        *consumed += count;
        Ok(count)
    }
}


#[test]
fn a_single_and_a_multi_line_reply_are_parsed() -> TestResult {
    let single = parse_reply(b"250 ok\r\n")?.ok_or("incomplete")?;
    assert_eq!((single.code, single.lines), (CODE_OK, vec!["ok".to_string()]));
    let multi = parse_reply(b"250-first\r\n250-second\r\n250 last\r\n")?.ok_or("incomplete")?;
    assert_eq!(multi.lines, vec!["first", "second", "last"]);
    let bare = parse_reply(b"250\r\n")?.ok_or("incomplete")?;
    assert_eq!(bare.lines, vec![String::new()]);
    let unix_endings = parse_reply(b"220 hi\n")?.ok_or("incomplete")?;
    assert_eq!(unix_endings.code, CODE_READY);
    Ok(())
}


#[test]
fn an_incomplete_reply_asks_for_more() -> TestResult {
    assert!(parse_reply(b"")?.is_none());
    assert!(parse_reply(b"250-first\r\n")?.is_none());
    assert!(parse_reply(b"250 par")?.is_none());
    Ok(())
}


#[test]
fn malformed_replies_are_refused() -> TestResult {
    let refused = |bytes: &[u8]| matches!(parse_reply(bytes), Err(TransportError::ReplyFormat));
    assert!(refused(b"25\r\n"));
    assert!(refused(b"abc ok\r\n"));
    assert!(refused(b"250ok\r\n"));
    assert!(refused(b"+50 ok\r\n"));
    assert!(refused(b"\xff50 ok\r\n"));
    assert!(refused(b"2\xc3\xa9 ok\r\n"));
    assert!(refused(b"250 ok\r\n250 again\r\n"));
    assert!(refused(b"250 ok\r\nextra"));
    assert!(refused(b"250-a\r\n251 b\r\n"));
    Ok(())
}


#[test]
fn a_line_over_the_bound_is_refused_complete_or_not() -> TestResult {
    let long = "x".repeat(MAX_REPLY_LINE_BYTES);
    assert!(matches!(
        parse_reply(format!("250 {long}\r\n").as_bytes()),
        Err(TransportError::ReplyTooLong)
    ));
    assert!(matches!(parse_reply(format!("250 {long}").as_bytes()), Err(TransportError::ReplyTooLong)));
    assert!(matches!(parse_line(format!("250 {long}").as_bytes()), Err(TransportError::ReplyTooLong)));
    Ok(())
}


#[test]
fn a_reply_without_a_newline_stops_at_the_line_bound_and_consumes_a_bounded_amount() -> TestResult {
    let flood = vec![b'A'; MAX_REPLY_BYTES * FLOOD_FACTOR];
    let mut consumed = 0;
    let outcome = read_reply(&mut feed(&flood, &mut consumed));
    assert!(matches!(outcome, Err(TransportError::ReplyTooLong)));
    assert!(consumed <= MAX_REPLY_LINE_BYTES + FLOOD_CHUNK);
    Ok(())
}


#[test]
fn a_multi_line_reply_over_the_reply_bound_stops_at_the_bound() -> TestResult {
    let flood = b"250-0123456789\r\n".repeat(MAX_REPLY_BYTES);
    let mut consumed = 0;
    let outcome = read_reply(&mut feed(&flood, &mut consumed));
    assert!(matches!(outcome, Err(TransportError::ReplyTooLong)));
    assert_eq!(consumed, MAX_REPLY_BYTES + 1);
    Ok(())
}


#[test]
fn a_reply_is_read_across_several_reads_and_errors_and_eof_are_reported() -> TestResult {
    let mut consumed = 0;
    let whole = read_reply(&mut feed(b"250-a\r\n250 b\r\n", &mut consumed))?;
    assert_eq!(whole.lines, vec!["a", "b"]);
    let mut empty = 0;
    assert!(matches!(read_reply(&mut feed(b"250 par", &mut empty)), Err(TransportError::Closed)));
    assert!(matches!(
        read_reply(&mut |_buffer: &mut [u8]| Err(TransportError::Deadline)),
        Err(TransportError::Deadline)
    ));
    Ok(())
}


#[test]
fn timeouts_are_the_deadline_and_other_io_errors_keep_their_cause() -> TestResult {
    assert!(matches!(io_error(Error::from(ErrorKind::WouldBlock)), TransportError::Deadline));
    assert!(matches!(io_error(Error::from(ErrorKind::TimedOut)), TransportError::Deadline));
    assert!(matches!(io_error(Error::from(ErrorKind::ConnectionReset)), TransportError::Io(_)));
    Ok(())
}


#[test]
fn the_remaining_time_follows_the_injected_clock() -> TestResult {
    let base = Instant::now();
    let deadline = base + GENEROUS;
    assert_eq!(remaining(deadline, &|| base)?, GENEROUS);
    assert!(matches!(remaining(deadline, &|| deadline), Err(TransportError::Deadline)));
    assert!(matches!(remaining(deadline, &|| deadline + GENEROUS), Err(TransportError::Deadline)));
    Ok(())
}


#[test]
fn the_first_usable_address_is_connected_and_failures_are_reported() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let good = listener.local_addr()?;
    let refused = SocketAddr::from((LOOPBACK, UNUSED_PORT));
    let clock = Instant::now;
    let deadline = Instant::now() + GENEROUS;
    assert!(connect_first(&[refused, good], deadline, &clock).is_ok());
    assert!(matches!(connect_first(&[refused], deadline, &clock), Err(TransportError::Io(_))));
    assert!(matches!(connect_first(&[], deadline, &clock), Err(TransportError::NoAddress)));
    assert!(matches!(connect_first(&[good], Instant::now(), &clock), Err(TransportError::Deadline)));
    Ok(())
}
