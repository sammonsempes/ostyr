#[path = "support/ber.rs"]
mod ber;
#[path = "support/types.rs"]
mod types;


use ber::*;
use sha2::{Digest, Sha256};
use site_collector::error::ConfigError;
use site_collector::listen::count_reason;
use site_collector::listen_model::ListenerStats;
use site_collector::model::{
    DropReason, TrapDrop, TrapKind, TrapLimits, TrapRecord, TrapVersion, DEFAULT_MAX_VALUE_CHARS, DEFAULT_MAX_VARBINDS, MAX_OID_ARCS, MAX_TRAP_BYTES,
    MAX_VALUE_CHARS_CEILING, MAX_VARBINDS_CEILING,
};
use site_collector::snmp::{cut_text, drop_of, is_community_oid, parse_trap, raw_generic_trap, v1_trap_oid, validate_trap_limits};
use snmp_parser::asn1_rs::{Err as BerErr, Needed};
use snmp_parser::error::SnmpError;
use snmp_parser::TrapType;
use std::net::Ipv4Addr;
use types::TestResult;


const COMMUNITY: &[u8] = b"public";


const LONG_COMMUNITY_BYTES: usize = 255;


const DIGEST_HEX_CHARS: usize = 12;


const SECOND_COMMUNITY: &[u8] = b"Netw0rk-Site7";


const WRAPPED_GENERICS: [i128; 2] = [256, 262];


const WRAPPED_FIRST: u32 = 256;


const UNKNOWN_GENERIC: u8 = 7;


const INDEFINITE_LENGTH: u8 = 0x80;


const COMMUNITY_COUNT: usize = 3;


const LONG_ENTERPRISE_ARCS: usize = 127;


const TWO_PARSE_DROPS: u64 = 2;


const SMALL_VARBINDS: usize = 8;


const SMALL_VALUE_CHARS: usize = 10;


const NESTING_DEPTH: usize = 300;


const TOO_MANY_ARCS: usize = 1000;


const FUZZ_FLIPS: [u8; 3] = [0x00, 0xff, 0x80];


const FIXTURE_NAMES: [&str; 4] = ["v1_coldstart.bin", "v1_enterprise.bin", "v2c_trap.bin", "v2c_inform.bin"];


const UNSIGNED_MAX: u64 = 4_294_967_295;


const COUNTER64_VALUE: u64 = 10_000_000_000;


const NEGATIVE_NUMBER: i128 = -5;


const GENERIC_UNKNOWN: i128 = 7;


const GENERIC_COLD_START: i128 = 0;


const GENERIC_LINK_DOWN: i128 = 2;


const GENERIC_ENTERPRISE: i128 = 6;


const SPECIFIC_TRAP: i128 = 17;


const AGENT_OCTETS: [u8; 4] = [192, 0, 2, 7];


const AGENT: &[u8] = &AGENT_OCTETS;


const HOSTILE_OCTETS: [u8; 5] = [b'a', 0, 0xe2, 0x80, 0xae];


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const BIT_STRING_BODY: [u8; 2] = [0, 0xa0];


const OPAQUE_BODY: [u8; 2] = [1, 0xab];


const UNKNOWN_APPLICATION_BODY: [u8; 1] = [0xef];


const CUT_EXTRA: usize = 5;


const CLAIMED_4GB: [u8; 9] = [TAG_SEQUENCE, 0x84, 0xff, 0xff, 0xff, 0xff, TAG_INTEGER, 1, 1];


const OID_FIRST_BYTE: u8 = 0x2b;


const WIDE_ARC_BYTES: usize = 11;


const CONTINUED: u8 = 0xff;


const SHORT_ENTERPRISE: [u64; 2] = [1, 3];


const BAD_COMMUNITY: [u8; 1] = [0xff];


const IP_VALUE: &[u8] = &[10, 1, 2, 3];


const SECURITY_MODEL_OTHER: i128 = 99;


const FRAMING_BYTES: usize = 40;


fn limits() -> TrapLimits {
    TrapLimits::default()
}


fn fixture(name: &str) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(format!("{}/tests/fixtures/snmp/{name}", env!("CARGO_MANIFEST_DIR")))
}


fn text_varbind(value: Vec<u8>) -> Vec<u8> {
    varbind(IF_INDEX, value)
}


fn v2_with(extra: Vec<Vec<u8>>) -> Vec<u8> {
    let varbinds: Vec<Vec<u8>> = v2_header(UPTIME, LINK_DOWN).into_iter().chain(extra).collect();
    v2_message(PDU_TRAP_V2, COMMUNITY, &varbinds)
}


const UPTIME: u64 = 4242;


fn parse_default(datagram: &[u8]) -> Result<TrapRecord, Box<dyn std::error::Error>> {
    Ok(parse_trap(datagram, &limits())?)
}


fn values_of(extra: Vec<Vec<u8>>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let record = parse_default(&v2_with(extra))?;
    Ok(record.varbinds.into_iter().map(|varbind| varbind.value).collect())
}


fn v3_message() -> Vec<u8> {
    let header = sequence(&[integer(1), integer(MAX_TRAP_BYTES as i128), octets(&[0]), integer(SECURITY_MODEL_OTHER)]);
    let scoped = sequence(&[octets(&[]), octets(&[]), generic_pdu(PDU_TRAP_V2, &v2_header(UPTIME, LINK_DOWN))]);
    sequence(&[integer(VERSION_V3), header, octets(&[]), scoped])
}


#[test]
fn v1_cold_start_maps_to_snmp_traps() -> TestResult {
    let record = parse_default(&v1_trap(COMMUNITY, ENTERPRISE, AGENT, GENERIC_COLD_START, 0, &[]))?;
    assert_eq!(record.version, TrapVersion::V1);
    assert_eq!(record.kind, TrapKind::TrapV1);
    assert_eq!(record.trap_oid, "1.3.6.1.6.3.1.1.5.1");
    assert_eq!(record.agent_address, Some(Ipv4Addr::from(AGENT_OCTETS)));
    assert_eq!(record.uptime_ticks, UPTIME_TICKS_V1 as u32);
    assert!(record.varbinds.is_empty());
    assert_eq!(record.varbinds_omitted, 0);
    Ok(())
}


#[test]
fn v1_link_down_and_enterprise_specific() -> TestResult {
    let down = parse_default(&v1_trap(COMMUNITY, ENTERPRISE, AGENT, GENERIC_LINK_DOWN, 0, &[]))?;
    assert_eq!(down.trap_oid, "1.3.6.1.6.3.1.1.5.3");
    let varbinds = [text_varbind(octets(b"eth0"))];
    let specific = parse_default(&v1_trap(COMMUNITY, ENTERPRISE, AGENT, GENERIC_ENTERPRISE, SPECIFIC_TRAP, &varbinds))?;
    assert_eq!(specific.trap_oid, "1.3.6.1.4.1.8072.2.3.0.17");
    assert_eq!(specific.varbinds.len(), 1);
    assert_eq!(
        specific.varbinds.first().map(|varbind| varbind.oid.as_str()),
        Some("1.3.6.1.2.1.2.2.1.1.7")
    );
    Ok(())
}


#[test]
fn v1_unknown_generic_trap_is_malformed() -> TestResult {
    assert_eq!(
        parse_trap(&v1_trap(COMMUNITY, ENTERPRISE, AGENT, GENERIC_UNKNOWN, 0, &[]), &limits()),
        Err(TrapDrop::Malformed)
    );
    Ok(())
}


#[test]
fn v2c_trap_with_three_varbinds() -> TestResult {
    let extra = vec![
        text_varbind(octets(b"eth0")),
        text_varbind(integer(NEGATIVE_NUMBER)),
        text_varbind(tlv(TAG_COUNTER32, &integer_content(1))),
    ];
    let record = parse_default(&v2_with(extra))?;
    assert_eq!(record.version, TrapVersion::V2c);
    assert_eq!(record.kind, TrapKind::TrapV2);
    assert_eq!(record.trap_oid, "1.3.6.1.6.3.1.1.5.3");
    assert_eq!(record.agent_address, None);
    assert_eq!(record.uptime_ticks, UPTIME as u32);
    let values: Vec<&str> = record.varbinds.iter().map(|varbind| varbind.value.as_str()).collect();
    assert_eq!(values, ["eth0", "-5", "1"]);
    Ok(())
}


#[test]
fn v2c_inform_is_kind_inform() -> TestResult {
    let record = parse_default(&v2_message(PDU_INFORM, COMMUNITY, &v2_header(UPTIME, LINK_DOWN)))?;
    assert_eq!(record.kind, TrapKind::Inform);
    Ok(())
}


#[test]
fn every_value_type_is_rendered() -> TestResult {
    let extra = vec![
        text_varbind(octets(&HOSTILE_OCTETS)),
        text_varbind(octets(&INVALID_UTF8)),
        text_varbind(oid(ENTERPRISE)),
        text_varbind(tlv(TAG_BIT_STRING, &BIT_STRING_BODY)),
        text_varbind(tlv(TAG_OCTET_STRING, &[])),
        text_varbind(tlv(TAG_UTF8, b"ab")),
        text_varbind(tlv(TAG_IP_ADDRESS, IP_VALUE)),
        text_varbind(unsigned(TAG_COUNTER32, UNSIGNED_MAX)),
        text_varbind(unsigned(TAG_GAUGE32, 1)),
        text_varbind(unsigned(TAG_TIME_TICKS, 0)),
        text_varbind(tlv(TAG_OPAQUE, &OPAQUE_BODY)),
        text_varbind(unsigned(TAG_COUNTER64, COUNTER64_VALUE)),
        text_varbind(unsigned(TAG_UNSIGNED32, UNSIGNED_MAX)),
        text_varbind(tlv(TAG_UNKNOWN_APPLICATION, &UNKNOWN_APPLICATION_BODY)),
        text_varbind(tlv(TAG_NULL, &[])),
        text_varbind(tlv(TAG_NO_SUCH_OBJECT, &[])),
        text_varbind(tlv(TAG_NO_SUCH_INSTANCE, &[])),
        text_varbind(tlv(TAG_END_OF_MIB_VIEW, &[])),
    ];
    let values = values_of(extra)?;
    let expected = [
        "hex:6100e280ae",
        "hex:fffe",
        "1.3.6.1.4.1.8072.2.3",
        "hex:a0",
        "",
        "hex:6162",
        "10.1.2.3",
        "4294967295",
        "1",
        "0",
        "hex:01ab",
        "10000000000",
        "4294967295",
        "hex:ef",
        "unspecified",
        "noSuchObject",
        "noSuchInstance",
        "endOfMibView",
    ];
    assert_eq!(values, expected);
    Ok(())
}


#[test]
fn long_values_are_cut_visibly() -> TestResult {
    let long = vec![b'x'; SMALL_VALUE_CHARS + CUT_EXTRA];
    let small = TrapLimits {
        max_varbinds: SMALL_VARBINDS,
        max_value_chars: SMALL_VALUE_CHARS,
    };
    let record = parse_trap(&v2_with(vec![text_varbind(octets(&long))]), &small)?;
    assert_eq!(
        record.varbinds.first().map(|varbind| varbind.value.as_str()),
        Some("xxxxxxxxxx[cut, 5 chars]")
    );
    assert_eq!(cut_text("abc".to_string(), SMALL_VALUE_CHARS), "abc");
    Ok(())
}


#[test]
fn varbind_count_is_capped_and_omission_counted() -> TestResult {
    let filler = text_varbind(tlv(TAG_NULL, &[]));
    let header_size = v2_with(vec![]).len();
    let count = (MAX_TRAP_BYTES - header_size - FRAMING_BYTES) / filler.len();
    let datagram = v2_with(vec![filler; count]);
    assert!(datagram.len() <= MAX_TRAP_BYTES);
    let small = TrapLimits {
        max_varbinds: SMALL_VARBINDS,
        max_value_chars: DEFAULT_MAX_VALUE_CHARS,
    };
    let record = parse_trap(&datagram, &small)?;
    assert_eq!(record.varbinds.len(), SMALL_VARBINDS);
    assert_eq!(record.varbinds_omitted, count - SMALL_VARBINDS);
    assert!(count > DEFAULT_MAX_VARBINDS);
    Ok(())
}


#[test]
fn oversized_datagram_is_refused_before_parsing() -> TestResult {
    assert_eq!(parse_trap(&vec![0; MAX_TRAP_BYTES + 1], &limits()), Err(TrapDrop::TooLarge));
    assert_eq!(parse_trap(&vec![0; MAX_TRAP_BYTES], &limits()), Err(TrapDrop::Malformed));
    Ok(())
}


#[test]
fn huge_length_field_is_malformed() -> TestResult {
    assert_eq!(parse_trap(&CLAIMED_4GB, &limits()), Err(TrapDrop::Malformed));
    Ok(())
}


#[test]
fn oid_with_too_many_arcs_is_malformed() -> TestResult {
    let long: Vec<u8> = std::iter::once(OID_FIRST_BYTE).chain((1..TOO_MANY_ARCS).map(|_| 1)).collect();
    let bounded: Vec<u8> = std::iter::once(OID_FIRST_BYTE)
        .chain((FIRST_BYTE_ARCS..MAX_OID_ARCS).map(|_| 1))
        .collect();
    let in_name = v2_with(vec![sequence(&[tlv(TAG_OID, &long), tlv(TAG_NULL, &[])])]);
    let in_value = v2_with(vec![text_varbind(tlv(TAG_OID, &long))]);
    let in_enterprise = v1_trap(
        COMMUNITY,
        &SHORT_ENTERPRISE,
        AGENT,
        GENERIC_COLD_START,
        0,
        &[sequence(&[tlv(TAG_OID, &long), tlv(TAG_NULL, &[])])],
    );
    let within = v2_with(vec![text_varbind(tlv(TAG_OID, &bounded))]);
    assert_eq!(parse_trap(&in_name, &limits()), Err(TrapDrop::Malformed));
    assert_eq!(parse_trap(&in_value, &limits()), Err(TrapDrop::Malformed));
    assert_eq!(parse_trap(&in_enterprise, &limits()), Err(TrapDrop::Malformed));
    assert!(parse_trap(&within, &limits()).is_ok());
    Ok(())
}


const COMMUNITY_OID: &[u64] = &[1, 3, 6, 1, 6, 3, 18, 1, 4, 0];


const COMMUNITY_SIBLING_OID: &[u64] = &[1, 3, 6, 1, 6, 3, 18, 1, 40];


const FIRST_BYTE_ARCS: usize = 2;


const REDACTED_TEXT: &str = "[redacted]";


fn arcs_oid(arcs: usize) -> Vec<u8> {
    std::iter::once(OID_FIRST_BYTE).chain((FIRST_BYTE_ARCS..arcs).map(|_| 1)).collect()
}


#[test]
fn trap_community_varbind_is_redacted() -> TestResult {
    let long_community = vec![b'k'; LONG_COMMUNITY_BYTES];
    let communities: [&[u8]; COMMUNITY_COUNT] = [COMMUNITY, SECOND_COMMUNITY, &long_community];
    let shown: String = communities
        .iter()
        .map(|community| {
            let record = parse_default(&v2_with(vec![varbind(COMMUNITY_OID, octets(community))]))?;
            assert_eq!(record.varbinds.first().map(|varbind| varbind.value.as_str()), Some(REDACTED_TEXT));
            assert_eq!(record.varbinds.first().map(|varbind| varbind.oid.as_str()), Some("1.3.6.1.6.3.18.1.4.0"));
            Ok(format!("{record:?}"))
        })
        .collect::<Result<String, Box<dyn std::error::Error>>>()?;
    assert!(!shown.contains("public"));
    assert!(!shown.contains("Netw0rk"));
    assert!(!shown.contains(&"k".repeat(LONG_COMMUNITY_BYTES)));
    assert!(communities
        .iter()
        .all(|community| !shown.contains(&sha256_hex(community).chars().take(DIGEST_HEX_CHARS).collect::<String>())));
    Ok(())
}


#[test]
fn trap_community_sibling_oid_is_kept() -> TestResult {
    let record = parse_default(&v2_with(vec![varbind(COMMUNITY_SIBLING_OID, octets(b"visible"))]))?;
    assert_eq!(record.varbinds.first().map(|varbind| varbind.value.as_str()), Some("visible"));
    assert!(is_community_oid("1.3.6.1.6.3.18.1.4"));
    assert!(!is_community_oid("1.3.6.1.6.3.18.1.40"));
    Ok(())
}


#[test]
fn oid_arc_limit_is_exact() -> TestResult {
    let edge = MAX_OID_ARCS;
    let accepted_name = v2_with(vec![sequence(&[tlv(TAG_OID, &arcs_oid(edge)), tlv(TAG_NULL, &[])])]);
    let refused_name = v2_with(vec![sequence(&[tlv(TAG_OID, &arcs_oid(edge + 1)), tlv(TAG_NULL, &[])])]);
    let accepted_value = v2_with(vec![text_varbind(tlv(TAG_OID, &arcs_oid(edge)))]);
    let refused_value = v2_with(vec![text_varbind(tlv(TAG_OID, &arcs_oid(edge + 1)))]);
    assert!(parse_trap(&accepted_name, &limits()).is_ok());
    assert_eq!(parse_trap(&refused_name, &limits()), Err(TrapDrop::Malformed));
    assert!(parse_trap(&accepted_value, &limits()).is_ok());
    assert_eq!(parse_trap(&refused_value, &limits()), Err(TrapDrop::Malformed));
    Ok(())
}


#[test]
fn oid_arc_beyond_u64_is_malformed() -> TestResult {
    let wide: Vec<u8> = std::iter::once(OID_FIRST_BYTE)
        .chain((0..WIDE_ARC_BYTES).map(|_| CONTINUED))
        .chain(std::iter::once(1))
        .collect();
    assert_eq!(
        parse_trap(&v2_with(vec![text_varbind(tlv(TAG_OID, &wide))]), &limits()),
        Err(TrapDrop::Malformed)
    );
    Ok(())
}


#[test]
fn deeply_nested_value_is_kept_as_hex_without_recursion() -> TestResult {
    let nested = (0..NESTING_DEPTH).fold(tlv(TAG_NULL, &[1]), |inner, _| sequence(&[inner]));
    let datagram = v2_with(vec![text_varbind(nested)]);
    assert!(datagram.len() <= MAX_TRAP_BYTES);
    let record = parse_default(&datagram)?;
    assert!(record
        .varbinds
        .first()
        .is_some_and(|varbind| varbind.value.starts_with("hex:") && varbind.value.contains("[cut, ")));
    Ok(())
}


#[test]
fn unsupported_messages() -> TestResult {
    let get = v2_message(PDU_GET_REQUEST, COMMUNITY, &[text_varbind(tlv(TAG_NULL, &[]))]);
    let response = v2_message(PDU_RESPONSE, COMMUNITY, &[]);
    let bulk = message(
        VERSION_V2C,
        COMMUNITY,
        tlv(PDU_GET_BULK, &concat(&[integer(1), integer(0), integer(1), sequence(&[])])),
    );
    let unknown = v2_message(PDU_UNKNOWN, COMMUNITY, &[]);
    let v1_inform = message(VERSION_V1, COMMUNITY, generic_pdu(PDU_INFORM, &[]));
    let all = [get, response, bulk, unknown, v1_inform, v3_message()];
    assert!(all.iter().all(|datagram| parse_trap(datagram, &limits()) == Err(TrapDrop::Unsupported)));
    Ok(())
}


#[test]
fn malformed_messages() -> TestResult {
    let bad_version = message(VERSION_BAD, COMMUNITY, generic_pdu(PDU_TRAP_V2, &v2_header(UPTIME, LINK_DOWN)));
    let no_varbind = v2_message(PDU_TRAP_V2, COMMUNITY, &[]);
    let one_varbind = v2_message(
        PDU_TRAP_V2,
        COMMUNITY,
        &v2_header(UPTIME, LINK_DOWN).into_iter().take(1).collect::<Vec<_>>(),
    );
    let wrong_uptime_oid = v2_message(
        PDU_TRAP_V2,
        COMMUNITY,
        &[varbind(IF_INDEX, unsigned(TAG_TIME_TICKS, 1)), varbind(SNMP_TRAP_OID, oid(LINK_DOWN))],
    );
    let wrong_uptime_type = v2_message(
        PDU_TRAP_V2,
        COMMUNITY,
        &[varbind(SYS_UPTIME, integer(1)), varbind(SNMP_TRAP_OID, oid(LINK_DOWN))],
    );
    let wrong_trap_oid = v2_message(
        PDU_TRAP_V2,
        COMMUNITY,
        &[varbind(SYS_UPTIME, unsigned(TAG_TIME_TICKS, 1)), varbind(IF_INDEX, oid(LINK_DOWN))],
    );
    let wrong_trap_type = v2_message(
        PDU_TRAP_V2,
        COMMUNITY,
        &[varbind(SYS_UPTIME, unsigned(TAG_TIME_TICKS, 1)), varbind(SNMP_TRAP_OID, integer(1))],
    );
    let bad_community = message(VERSION_V2C, &BAD_COMMUNITY, generic_pdu(PDU_TRAP_V2, &v2_header(UPTIME, LINK_DOWN)));
    let all = [
        bad_version,
        no_varbind,
        one_varbind,
        wrong_uptime_oid,
        wrong_uptime_type,
        wrong_trap_oid,
        wrong_trap_type,
        bad_community,
        Vec::new(),
        vec![TAG_SEQUENCE],
    ];
    assert!(all.iter().all(|datagram| parse_trap(datagram, &limits()) == Err(TrapDrop::Malformed)));
    Ok(())
}


fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}


#[test]
fn no_community_derived_value_is_kept() -> TestResult {
    let long_community = vec![b'k'; LONG_COMMUNITY_BYTES];
    let communities: [&[u8]; COMMUNITY_COUNT] = [COMMUNITY, SECOND_COMMUNITY, &long_community];
    let shown: String = communities
        .iter()
        .map(|community| {
            let record = parse_default(&v2_message(PDU_TRAP_V2, community, &v2_header(UPTIME, LINK_DOWN)))?;
            let v1 = parse_default(&v1_trap(community, ENTERPRISE, AGENT, GENERIC_COLD_START, 0, &[]))?;
            Ok(format!("{record:?}{v1:?}"))
        })
        .collect::<Result<String, Box<dyn std::error::Error>>>()?;
    assert!(!shown.contains("public"));
    assert!(!shown.contains("Netw0rk"));
    assert!(!shown.contains(&"k".repeat(LONG_COMMUNITY_BYTES)));
    assert!(communities
        .iter()
        .all(|community| !shown.contains(&sha256_hex(community).chars().take(DIGEST_HEX_CHARS).collect::<String>())));
    let first = parse_default(&v2_message(PDU_TRAP_V2, COMMUNITY, &v2_header(UPTIME, LINK_DOWN)))?;
    let second = parse_default(&v2_message(PDU_TRAP_V2, SECOND_COMMUNITY, &v2_header(UPTIME, LINK_DOWN)))?;
    assert_eq!(first, second);
    Ok(())
}


#[test]
fn wrapped_generic_trap_is_malformed() -> TestResult {
    let wrapped = WRAPPED_GENERICS.map(|generic| v1_trap(COMMUNITY, ENTERPRISE, AGENT, generic, 0, &[]));
    assert!(wrapped.iter().all(|datagram| parse_trap(datagram, &limits()) == Err(TrapDrop::Malformed)));
    assert_eq!(wrapped.first().map(|datagram| raw_generic_trap(datagram)), Some(Ok(WRAPPED_FIRST)));
    assert_eq!(raw_generic_trap(&[]), Err(TrapDrop::Malformed));
    assert_eq!(v1_trap_oid("1.3", TrapType(UNKNOWN_GENERIC), 0), Err(TrapDrop::Malformed));
    Ok(())
}


#[test]
fn indefinite_length_v1_pdu_is_malformed() -> TestResult {
    let body = concat(&[
        oid(ENTERPRISE),
        tlv(TAG_IP_ADDRESS, AGENT),
        integer(0),
        integer(0),
        unsigned(TAG_TIME_TICKS, 1),
        sequence(&[]),
    ]);
    let indefinite = concat(&[vec![PDU_TRAP_V1, INDEFINITE_LENGTH], body, vec![0, 0]]);
    let datagram = message(VERSION_V1, COMMUNITY, indefinite);
    assert_eq!(parse_trap(&datagram, &limits()), Err(TrapDrop::Malformed));
    Ok(())
}


#[test]
fn v1_trap_pdu_in_a_v2c_message_is_unsupported() -> TestResult {
    let body = concat(&[
        oid(ENTERPRISE),
        tlv(TAG_IP_ADDRESS, AGENT),
        integer(0),
        integer(0),
        unsigned(TAG_TIME_TICKS, 1),
        sequence(&[]),
    ]);
    let datagram = message(VERSION_V2C, COMMUNITY, tlv(PDU_TRAP_V1, &body));
    assert_eq!(parse_trap(&datagram, &limits()), Err(TrapDrop::Unsupported));
    Ok(())
}


#[test]
fn v1_enterprise_trap_oid_is_capped_with_its_added_arcs() -> TestResult {
    let enterprise = |arcs: usize| -> Vec<u64> { std::iter::repeat_n(1, arcs).collect() };
    let over = v1_trap(
        COMMUNITY,
        &enterprise(LONG_ENTERPRISE_ARCS),
        AGENT,
        GENERIC_ENTERPRISE,
        SPECIFIC_TRAP,
        &[],
    );
    let within = v1_trap(
        COMMUNITY,
        &enterprise(LONG_ENTERPRISE_ARCS - 1),
        AGENT,
        GENERIC_ENTERPRISE,
        SPECIFIC_TRAP,
        &[],
    );
    assert_eq!(parse_trap(&over, &limits()), Err(TrapDrop::Malformed));
    assert!(parse_trap(&within, &limits()).is_ok());
    Ok(())
}


#[test]
fn limits_are_validated() -> TestResult {
    assert_eq!(validate_trap_limits(&limits()), Ok(()));
    let top = TrapLimits {
        max_varbinds: MAX_VARBINDS_CEILING,
        max_value_chars: MAX_VALUE_CHARS_CEILING,
    };
    assert_eq!(validate_trap_limits(&top), Ok(()));
    let zero_varbinds = TrapLimits { max_varbinds: 0, ..limits() };
    let high_varbinds = TrapLimits {
        max_varbinds: MAX_VARBINDS_CEILING + 1,
        ..limits()
    };
    let zero_chars = TrapLimits {
        max_value_chars: 0,
        ..limits()
    };
    let high_chars = TrapLimits {
        max_value_chars: MAX_VALUE_CHARS_CEILING + 1,
        ..limits()
    };
    assert_eq!(validate_trap_limits(&zero_varbinds), Err(ConfigError::BadMaxVarbinds));
    assert_eq!(validate_trap_limits(&high_varbinds), Err(ConfigError::BadMaxVarbinds));
    assert_eq!(validate_trap_limits(&zero_chars), Err(ConfigError::BadMaxValueChars));
    assert_eq!(validate_trap_limits(&high_chars), Err(ConfigError::BadMaxValueChars));
    Ok(())
}


#[test]
fn drops_map_to_reasons_and_counters() -> TestResult {
    assert_eq!(DropReason::from(TrapDrop::TooLarge), DropReason::TrapTooLarge);
    assert_eq!(DropReason::from(TrapDrop::Malformed), DropReason::TrapMalformed);
    assert_eq!(DropReason::from(TrapDrop::Unsupported), DropReason::TrapUnsupported);
    let mut stats = ListenerStats::default();
    count_reason(&mut stats, DropReason::TrapTooLarge);
    count_reason(&mut stats, DropReason::TrapMalformed);
    count_reason(&mut stats, DropReason::TrapUnsupported);
    assert_eq!((stats.dropped_too_long, stats.dropped_parse), (1, TWO_PARSE_DROPS));
    Ok(())
}


#[test]
fn parser_error_kinds_map_to_drops() -> TestResult {
    assert_eq!(drop_of(&BerErr::Failure(SnmpError::InvalidPduType)), TrapDrop::Unsupported);
    assert_eq!(drop_of(&BerErr::Error(SnmpError::InvalidPduType)), TrapDrop::Unsupported);
    assert_eq!(drop_of(&BerErr::Error(SnmpError::InvalidMessage)), TrapDrop::Malformed);
    assert_eq!(drop_of(&BerErr::Incomplete(Needed::Unknown)), TrapDrop::Malformed);
    Ok(())
}


fn samples() -> Result<Vec<Vec<u8>>, std::io::Error> {
    let built = vec![
        v2_with(vec![text_varbind(octets(b"eth0")), text_varbind(tlv(TAG_IP_ADDRESS, IP_VALUE))]),
        v1_trap(
            COMMUNITY,
            ENTERPRISE,
            AGENT,
            GENERIC_ENTERPRISE,
            SPECIFIC_TRAP,
            &[text_varbind(integer(1))],
        ),
    ];
    let captured = FIXTURE_NAMES.iter().map(|name| fixture(name)).collect::<Result<Vec<_>, _>>()?;
    Ok(built.into_iter().chain(captured).collect())
}


#[test]
fn every_truncation_is_handled() -> TestResult {
    let outcomes = samples()?
        .iter()
        .flat_map(|sample| (0..sample.len()).map(move |cut| sample.iter().take(cut).copied().collect::<Vec<u8>>()))
        .map(|truncated| parse_trap(&truncated, &limits()))
        .collect::<Vec<_>>();
    assert!(!outcomes.is_empty());
    assert!(outcomes.iter().all(|outcome| outcome.is_err() || outcome.is_ok()));
    assert!(outcomes
        .iter()
        .filter_map(|outcome| outcome.as_ref().err())
        .all(|reason| *reason != TrapDrop::TooLarge));
    Ok(())
}


#[test]
fn every_single_byte_flip_is_handled() -> TestResult {
    let count = samples()?
        .iter()
        .flat_map(|sample| {
            (0..sample.len()).flat_map(move |position| {
                FUZZ_FLIPS.iter().map(move |flip| {
                    let mut mutated = sample.clone();
                    mutated.iter_mut().skip(position).take(1).for_each(|byte| *byte = *flip);
                    mutated
                })
            })
        })
        .map(|mutated| parse_trap(&mutated, &limits()))
        .filter(|outcome| outcome.is_ok())
        .count();
    assert!(count > 0);
    Ok(())
}


#[test]
fn captured_fixtures_parse() -> TestResult {
    let records = FIXTURE_NAMES
        .iter()
        .map(|name| parse_default(&fixture(name)?))
        .collect::<Result<Vec<TrapRecord>, Box<dyn std::error::Error>>>()?;
    let kinds: Vec<TrapKind> = records.iter().map(|record| record.kind).collect();
    assert_eq!(kinds, [TrapKind::TrapV1, TrapKind::TrapV1, TrapKind::TrapV2, TrapKind::Inform]);
    Ok(())
}
