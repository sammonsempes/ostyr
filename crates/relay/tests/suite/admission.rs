use crate::support::TestResult;
use relay::admission::{admit, gauges, new_admission, source_of};
use relay::model::Refusal;
use std::net::IpAddr;


const TOTAL: usize = 3;


const PER_SOURCE: usize = 2;


fn ip(text: &str) -> Result<IpAddr, std::net::AddrParseError> {
    text.parse()
}


#[test]
fn sources_fold_ipv6_to_64_and_mapped_to_ipv4() -> TestResult {
    assert_eq!(source_of(ip("2001:db8:0:1:aaaa:bbbb:cccc:dddd")?), ip("2001:db8:0:1::")?);
    assert_eq!(source_of(ip("2001:db8:0:1:1:2:3:4")?), source_of(ip("2001:db8:0:1:9:9:9:9")?));
    assert_eq!(source_of(ip("::ffff:192.0.2.7")?), ip("192.0.2.7")?);
    assert_eq!(source_of(ip("192.0.2.7")?), ip("192.0.2.7")?);
    Ok(())
}


#[test]
fn both_caps_hold_and_a_drop_frees_the_slot() -> TestResult {
    let admission = new_admission();
    let first = admit(&admission, ip("192.0.2.1")?, TOTAL, PER_SOURCE)?;
    let second = admit(&admission, ip("192.0.2.1")?, TOTAL, PER_SOURCE)?;
    assert_eq!(admit(&admission, ip("192.0.2.1")?, TOTAL, PER_SOURCE).err(), Some(Refusal::Source));
    let other = admit(&admission, ip("192.0.2.2")?, TOTAL, PER_SOURCE)?;
    assert_eq!(admit(&admission, ip("192.0.2.3")?, TOTAL, PER_SOURCE).err(), Some(Refusal::Total));
    assert_eq!(gauges(&admission), (TOTAL, PER_SOURCE));
    drop(first);
    assert_eq!(gauges(&admission), (PER_SOURCE, PER_SOURCE));
    drop(second);
    assert_eq!(gauges(&admission), (1, 1));
    drop(other);
    assert_eq!(gauges(&admission), (0, 0));
    Ok(())
}


#[test]
fn a_mapped_address_counts_with_its_ipv4_source() -> TestResult {
    let admission = new_admission();
    let direct = admit(&admission, ip("192.0.2.9")?, TOTAL, 1)?;
    assert_eq!(admit(&admission, ip("::ffff:192.0.2.9")?, TOTAL, 1).err(), Some(Refusal::Source));
    drop(direct);
    Ok(())
}


#[test]
fn a_lowered_cap_refuses_new_connections_and_keeps_live_ones() -> TestResult {
    let admission = new_admission();
    let live = admit(&admission, ip("192.0.2.1")?, TOTAL, PER_SOURCE)?;
    let also = admit(&admission, ip("192.0.2.2")?, TOTAL, PER_SOURCE)?;
    assert_eq!(admit(&admission, ip("192.0.2.3")?, 1, 1).err(), Some(Refusal::Total));
    assert_eq!(gauges(&admission), (PER_SOURCE, PER_SOURCE));
    drop((live, also));
    Ok(())
}


#[test]
fn the_live_count_is_published() -> TestResult {
    let admission = new_admission();
    let receiver = admission.live.subscribe();
    let permit = admit(&admission, ip("192.0.2.1")?, TOTAL, PER_SOURCE)?;
    assert_eq!(*receiver.borrow(), 1);
    drop(permit);
    assert_eq!(*receiver.borrow(), 0);
    Ok(())
}
