#[path = "common/types.rs"]
mod types;


use dns_rpz::trigger::{longest_zero_run, net_trigger, parse_net, reversed_fields, Run};
use std::net::{AddrParseError, Ipv6Addr};
use types::TestResult;


const SEGMENT_COUNT: usize = 8;


const LATE_START: usize = 4;


const LATE_LENGTH: usize = 3;


fn trigger_of(value: &str) -> Result<Option<String>, AddrParseError> {
    Ok(net_trigger(parse_net(value)?))
}


#[test]
fn an_ipv4_host_is_a_reversed_32_bit_prefix() -> TestResult {
    assert_eq!(trigger_of("10.0.0.1")?.as_deref(), Some("32.1.0.0.10.rpz-ip"));
    assert_eq!(trigger_of("10.0.0.1/32")?.as_deref(), Some("32.1.0.0.10.rpz-ip"));
    Ok(())
}


#[test]
fn an_ipv4_cidr_clears_host_bits_and_keeps_every_octet() -> TestResult {
    assert_eq!(trigger_of("192.0.2.77/24")?.as_deref(), Some("24.0.2.0.192.rpz-ip"));
    assert_eq!(trigger_of("10.9.8.7/8")?.as_deref(), Some("8.0.0.0.10.rpz-ip"));
    Ok(())
}


#[test]
fn ipv6_uses_reversed_fields_with_zz_for_the_longest_zero_run() -> TestResult {
    assert_eq!(trigger_of("2001:db8::1")?.as_deref(), Some("128.1.zz.db8.2001.rpz-ip"));
    assert_eq!(trigger_of("::1")?.as_deref(), Some("128.1.zz.rpz-ip"));
    assert_eq!(trigger_of("2001:db8::/32")?.as_deref(), Some("32.zz.db8.2001.rpz-ip"));
    assert_eq!(trigger_of("::/128")?.as_deref(), Some("128.zz.rpz-ip"));
    assert_eq!(trigger_of("2001:db8:abcd:ef01::/64")?.as_deref(), Some("64.zz.ef01.abcd.db8.2001.rpz-ip"));
    Ok(())
}


#[test]
fn a_single_zero_field_is_written_out_and_the_first_longest_run_wins() -> TestResult {
    assert_eq!(reversed_fields("1:0:3:4:5:6:7:8".parse::<Ipv6Addr>()?), "8.7.6.5.4.3.0.1");
    assert_eq!(reversed_fields("1:2:3:4:5:6:7:8".parse::<Ipv6Addr>()?), "8.7.6.5.4.3.2.1");
    assert_eq!(reversed_fields("1:0:0:2:0:0:3:4".parse::<Ipv6Addr>()?), "4.3.zz.2.0.0.1");
    assert_eq!(reversed_fields("1:0:0:2:0:0:0:4".parse::<Ipv6Addr>()?), "4.zz.2.0.0.1");
    Ok(())
}


#[test]
fn the_longest_zero_run_reports_start_and_length() -> TestResult {
    assert_eq!(longest_zero_run(&[]), Run { start: 0, len: 0 });
    let late = "1:0:0:2:0:0:0:3".parse::<Ipv6Addr>()?.segments();
    assert_eq!(
        longest_zero_run(&late),
        Run {
            start: LATE_START,
            len: LATE_LENGTH
        }
    );
    assert_eq!(
        longest_zero_run(&Ipv6Addr::UNSPECIFIED.segments()),
        Run {
            start: 0,
            len: SEGMENT_COUNT
        }
    );
    Ok(())
}


#[test]
fn a_zero_length_prefix_has_no_trigger_and_garbage_is_refused() -> TestResult {
    assert_eq!(trigger_of("0.0.0.0/0")?, None);
    assert_eq!(trigger_of("::/0")?, None);
    assert!(parse_net("not-an-address").is_err());
    assert!(parse_net("10.0.0.1/33").is_err());
    Ok(())
}
