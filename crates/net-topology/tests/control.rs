#[path = "common/types.rs"]
mod types;


use net_topology::error::ParseError;
use net_topology::limits::Limits;
use net_topology::lldp::{parse_lldpd, replace_control_bytes};
use net_topology::model::Parsed;
use types::TestResult;


const NOW: i64 = 1_700_000_000;


const HOST: &str = "server";


const CONTROL_BYTES: [u8; 4] = [0x00, 0x01, 0x1B, 0x1F];


const REPLACEMENT: u8 = 0x7F;


const NEIGHBOURS: usize = 2;


const CONTROL_FIRST: u8 = 0x1F;


const CONTROL_SECOND: u8 = 0x00;


const PORT_CAP: usize = 2;


const HOST_CAP: usize = 1;


fn interface(port: &str, chassis_id: &[u8], name: &[u8]) -> Vec<u8> {
    let mut text = format!(r#"{{"name":"{port}","chassis":[{{"id":[{{"type":"local","value":""#).into_bytes();
    text.extend_from_slice(chassis_id);
    text.extend_from_slice(br#""}],"name":[{"value":""#);
    text.extend_from_slice(name);
    text.extend_from_slice(br#""}]}],"port":[{"id":[{"type":"ifname","value":"Gi0/1"}]}]}"#);
    text
}


fn report(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut text = br#"{"lldp":[{"interface":["#.to_vec();
    text.extend_from_slice(first);
    text.push(b',');
    text.extend_from_slice(second);
    text.extend_from_slice(b"]}]}");
    text
}


fn parse_bytes(bytes: &[u8]) -> Result<Parsed, ParseError> {
    parse_lldpd(bytes, HOST, NOW, &Limits::default())
}


fn with_byte(prefix: &str, byte: u8) -> Vec<u8> {
    let mut text = prefix.as_bytes().to_vec();
    text.push(byte);
    text.extend_from_slice(b"x");
    text
}


#[test]
fn a_control_byte_in_a_display_name_drops_the_name_and_keeps_both_neighbours() -> TestResult {
    CONTROL_BYTES.iter().try_for_each(|byte| -> TestResult {
        let bytes = report(
            &interface("eth0", b"sw-a", &with_byte("client", *byte)),
            &interface("eth1", b"sw-b", b"ok"),
        );
        let parsed = parse_bytes(&bytes)?;
        assert_eq!(parsed.observations.len(), NEIGHBOURS);
        assert_eq!(parsed.skipped.dropped_display, 1);
        assert_eq!(parsed.skipped.control_bytes, 1);
        assert!(parsed.observations.first().ok_or("none")?.remote_name.is_none());
        assert_eq!(parsed.observations.get(1).ok_or("none")?.remote_chassis.value, "sw-b");
        Ok(())
    })
}


#[test]
fn a_control_byte_in_a_chassis_id_skips_that_neighbour_only() -> TestResult {
    CONTROL_BYTES.iter().try_for_each(|byte| -> TestResult {
        let bytes = report(&interface("eth0", &with_byte("sw-a", *byte), b"ok"), &interface("eth1", b"sw-b", b"ok"));
        let parsed = parse_bytes(&bytes)?;
        assert_eq!(parsed.observations.len(), 1);
        assert_eq!(parsed.skipped.bad_field, 1);
        assert_eq!(parsed.skipped.control_bytes, 1);
        assert_eq!(parsed.observations.first().ok_or("none")?.remote_chassis.value, "sw-b");
        Ok(())
    })
}


#[test]
fn a_control_byte_between_tokens_is_malformed() -> TestResult {
    CONTROL_BYTES.iter().try_for_each(|byte| -> TestResult {
        let mut bytes = br#"{"lldp":[{"interface":[]}]"#.to_vec();
        bytes.push(*byte);
        bytes.push(b'}');
        assert!(matches!(parse_bytes(&bytes), Err(ParseError::Malformed { .. })));
        Ok(())
    })
}


#[test]
fn tab_line_feed_and_carriage_return_are_kept() -> TestResult {
    let mut bytes = b"{\"lldp\":\r\n\t[]}".to_vec();
    assert_eq!(replace_control_bytes(&mut bytes), 0);
    assert_eq!(bytes, b"{\"lldp\":\r\n\t[]}".to_vec());
    let mut hostile = vec![CONTROL_FIRST, b'a', CONTROL_SECOND];
    assert_eq!(replace_control_bytes(&mut hostile), NEIGHBOURS);
    assert_eq!(hostile, vec![REPLACEMENT, b'a', REPLACEMENT]);
    Ok(())
}


#[test]
fn limits_with_a_port_cap_above_the_host_cap_are_refused() -> TestResult {
    let limits = Limits {
        max_links_per_host: HOST_CAP,
        max_links_per_port: PORT_CAP,
        ..Limits::default()
    };
    let outcome = parse_lldpd(&b"{\"lldp\":[]}"[..], HOST, NOW, &limits);
    assert!(matches!(
        outcome,
        Err(ParseError::InvalidLimits {
            per_port: PORT_CAP,
            per_host: HOST_CAP
        })
    ));
    Ok(())
}
