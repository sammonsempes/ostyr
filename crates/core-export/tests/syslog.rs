#[path = "common/types.rs"]
mod types;


use core_export::ecs::{blank_event, to_json};
use core_export::error::ExportError;
use core_export::syslog::{
    bind_address, format_message, frame, header_token, priority, send_datagrams, write_frames, SyslogHeader, MAX_APP_NAME_LEN, NIL_VALUE,
    UDP_BIND_V4, UDP_BIND_V6,
};
use std::net::UdpSocket;
use std::time::Duration;
use time::OffsetDateTime;
use types::TestResult;


const FIXED_UNIX: i64 = 1_700_000_000;


const YEAR_BEFORE_COMMON_ERA: i64 = -62_198_755_200;


const EXPECTED_PRIORITY: u32 = 134;


const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);


const DATAGRAM_BUFFER: usize = 4096;


const LONG_NAME: usize = 100;


fn header() -> SyslogHeader {
    SyslogHeader {
        hostname: "srv1".to_string(),
        app_name: "ostyr".to_string(),
    }
}


#[test]
fn priority_is_local0_informational() -> TestResult {
    assert_eq!(priority(), EXPECTED_PRIORITY);
    Ok(())
}


#[test]
fn header_tokens_are_printable_ascii_without_space() -> TestResult {
    assert_eq!(header_token("srv 1é", LONG_NAME), "srv_1_");
    assert_eq!(header_token("", LONG_NAME), NIL_VALUE);
    assert_eq!(header_token(&"a".repeat(LONG_NAME), MAX_APP_NAME_LEN).len(), MAX_APP_NAME_LEN);
    Ok(())
}


#[test]
fn message_follows_rfc_5424() -> TestResult {
    let event = blank_event(OffsetDateTime::from_unix_timestamp(FIXED_UNIX)?);
    let expected = format!("<134>1 2023-11-14T22:13:20Z srv1 ostyr - ecs - {}", to_json(&event)?);
    assert_eq!(format_message(&header(), &event)?, expected);
    Ok(())
}


#[test]
fn an_unformattable_timestamp_is_an_error() -> TestResult {
    let event = blank_event(OffsetDateTime::from_unix_timestamp(YEAR_BEFORE_COMMON_ERA)?);
    assert!(matches!(format_message(&header(), &event), Err(ExportError::Timestamp(_))));
    Ok(())
}


#[test]
fn frames_use_octet_counting() -> TestResult {
    assert_eq!(frame("abc"), "3 abc");
    assert_eq!(frame("é"), "2 é");
    let mut out = Vec::new();
    write_frames(&mut out, &["ab".to_string(), "c".to_string()])?;
    assert_eq!(String::from_utf8(out)?, "2 ab1 c");
    Ok(())
}


#[test]
fn a_failing_writer_is_an_io_error() -> TestResult {
    let mut full: &mut [u8] = &mut [];
    assert!(matches!(write_frames(&mut full, &["x".to_string()]), Err(ExportError::Io { .. })));
    Ok(())
}


#[test]
fn datagrams_are_sent_unframed() -> TestResult {
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    receiver.set_read_timeout(Some(RECEIVE_TIMEOUT))?;
    send_datagrams(&receiver.local_addr()?.to_string(), &["one".to_string(), "two".to_string()])?;
    let mut buffer = [u8::MIN; DATAGRAM_BUFFER];
    let first = receiver.recv(&mut buffer)?;
    assert_eq!(buffer.get(..first), Some("one".as_bytes()));
    let second = receiver.recv(&mut buffer)?;
    assert_eq!(buffer.get(..second), Some("two".as_bytes()));
    Ok(())
}


#[test]
fn an_unusable_datagram_address_is_an_io_error() -> TestResult {
    assert!(matches!(
        send_datagrams("not-an-address", &["x".to_string()]),
        Err(ExportError::Io { .. })
    ));
    Ok(())
}


#[test]
fn datagrams_reach_an_ipv6_target() -> TestResult {
    let receiver = UdpSocket::bind("[::1]:0")?;
    receiver.set_read_timeout(Some(RECEIVE_TIMEOUT))?;
    send_datagrams(&receiver.local_addr()?.to_string(), &["six".to_string()])?;
    let mut buffer = [u8::MIN; DATAGRAM_BUFFER];
    let received = receiver.recv(&mut buffer)?;
    assert_eq!(buffer.get(..received), Some("six".as_bytes()));
    Ok(())
}


#[test]
fn the_bind_address_follows_the_target_family() -> TestResult {
    assert_eq!(bind_address(&"127.0.0.1:1".parse()?), UDP_BIND_V4);
    assert_eq!(bind_address(&"[::1]:1".parse()?), UDP_BIND_V6);
    Ok(())
}
