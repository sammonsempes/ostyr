pub const TAG_INTEGER: u8 = 0x02;


pub const TAG_BIT_STRING: u8 = 0x03;


pub const TAG_OCTET_STRING: u8 = 0x04;


pub const TAG_NULL: u8 = 0x05;


pub const TAG_OID: u8 = 0x06;


pub const TAG_UTF8: u8 = 0x0c;


pub const TAG_SEQUENCE: u8 = 0x30;


pub const TAG_IP_ADDRESS: u8 = 0x40;


pub const TAG_COUNTER32: u8 = 0x41;


pub const TAG_GAUGE32: u8 = 0x42;


pub const TAG_TIME_TICKS: u8 = 0x43;


pub const TAG_OPAQUE: u8 = 0x44;


pub const TAG_COUNTER64: u8 = 0x46;


pub const TAG_UNSIGNED32: u8 = 0x47;


pub const TAG_UNKNOWN_APPLICATION: u8 = 0x4a;


pub const TAG_NO_SUCH_OBJECT: u8 = 0x80;


pub const TAG_NO_SUCH_INSTANCE: u8 = 0x81;


pub const TAG_END_OF_MIB_VIEW: u8 = 0x82;


pub const PDU_GET_REQUEST: u8 = 0xa0;


pub const PDU_RESPONSE: u8 = 0xa2;


pub const PDU_GET_BULK: u8 = 0xa5;


pub const PDU_INFORM: u8 = 0xa6;


pub const PDU_TRAP_V2: u8 = 0xa7;


pub const PDU_UNKNOWN: u8 = 0xa9;


pub const PDU_TRAP_V1: u8 = 0xa4;


pub const VERSION_V1: i128 = 0;


pub const VERSION_V2C: i128 = 1;


pub const VERSION_V3: i128 = 3;


pub const VERSION_BAD: i128 = 2;


pub const UPTIME_TICKS_V1: u64 = 0x1234;


const LONG_ONE_BYTE: u8 = 0x81;


const LONG_TWO_BYTES: u8 = 0x82;


const ONE_BYTE_MAX: usize = 0xff;


const SHORT_MAX: usize = 0x7f;


const BYTE_BITS: usize = 8;


const SIGN_BIT: u8 = 0x80;


const ALL_ONES: u8 = 0xff;


const FIRST_ARC_WEIGHT: u64 = 40;


const FIRST_TWO_ARCS: usize = 2;


const BITS_PER_GROUP: u32 = 7;


const GROUP_MASK: u64 = 0x7f;


const ARC_GROUPS: u32 = 10;


const CONTINUATION: u8 = 0x80;


pub const SYS_UPTIME: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];


pub const SNMP_TRAP_OID: &[u64] = &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];


pub const LINK_DOWN: &[u64] = &[1, 3, 6, 1, 6, 3, 1, 1, 5, 3];


pub const ENTERPRISE: &[u64] = &[1, 3, 6, 1, 4, 1, 8072, 2, 3];


pub const IF_INDEX: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7];


pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let length = content.len();
    let header: Vec<u8> = if length <= SHORT_MAX {
        vec![tag, length as u8]
    } else if length <= ONE_BYTE_MAX {
        vec![tag, LONG_ONE_BYTE, length as u8]
    } else {
        vec![tag, LONG_TWO_BYTES, (length >> BYTE_BITS) as u8, length as u8]
    };
    header.into_iter().chain(content.iter().copied()).collect()
}


pub fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flatten().copied().collect()
}


pub fn integer_content(value: i128) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let skip = bytes
        .iter()
        .zip(bytes.iter().skip(1))
        .take_while(|(current, next)| (**current == 0 && **next < SIGN_BIT) || (**current == ALL_ONES && **next >= SIGN_BIT))
        .count();
    bytes.iter().skip(skip).copied().collect()
}


pub fn integer(value: i128) -> Vec<u8> {
    tlv(TAG_INTEGER, &integer_content(value))
}


pub fn unsigned(tag: u8, value: u64) -> Vec<u8> {
    tlv(tag, &integer_content(i128::from(value)))
}


pub fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, bytes)
}


pub fn arc_bytes(arc: u64) -> Vec<u8> {
    let groups: Vec<u8> = (0..ARC_GROUPS).map(|i| ((arc >> (BITS_PER_GROUP * i)) & GROUP_MASK) as u8).collect();
    let count = groups.iter().rev().skip_while(|group| **group == 0).count().max(1);
    groups
        .iter()
        .take(count)
        .enumerate()
        .rev()
        .map(|(index, group)| if index == 0 { *group } else { *group | CONTINUATION })
        .collect()
}


pub fn oid_content(arcs: &[u64]) -> Vec<u8> {
    let first = arcs.first().copied().unwrap_or(0) * FIRST_ARC_WEIGHT + arcs.get(1).copied().unwrap_or(0);
    arc_bytes(first)
        .into_iter()
        .chain(arcs.iter().skip(FIRST_TWO_ARCS).flat_map(|arc| arc_bytes(*arc)))
        .collect()
}


pub fn oid(arcs: &[u64]) -> Vec<u8> {
    tlv(TAG_OID, &oid_content(arcs))
}


pub fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, &concat(parts))
}


pub fn varbind(arcs: &[u64], value: Vec<u8>) -> Vec<u8> {
    sequence(&[oid(arcs), value])
}


pub fn v2_header(uptime: u64, trap_oid: &[u64]) -> Vec<Vec<u8>> {
    vec![
        varbind(SYS_UPTIME, unsigned(TAG_TIME_TICKS, uptime)),
        varbind(SNMP_TRAP_OID, oid(trap_oid)),
    ]
}


pub fn message(version: i128, community: &[u8], pdu: Vec<u8>) -> Vec<u8> {
    sequence(&[integer(version), octets(community), pdu])
}


pub fn generic_pdu(tag: u8, varbinds: &[Vec<u8>]) -> Vec<u8> {
    tlv(tag, &concat(&[integer(1), integer(0), integer(0), sequence(varbinds)]))
}


pub fn v2_message(tag: u8, community: &[u8], varbinds: &[Vec<u8>]) -> Vec<u8> {
    message(VERSION_V2C, community, generic_pdu(tag, varbinds))
}


pub fn v1_trap(community: &[u8], enterprise: &[u64], address: &[u8], generic: i128, specific: i128, varbinds: &[Vec<u8>]) -> Vec<u8> {
    let body = concat(&[
        oid(enterprise),
        tlv(TAG_IP_ADDRESS, address),
        integer(generic),
        integer(specific),
        unsigned(TAG_TIME_TICKS, UPTIME_TICKS_V1),
        sequence(varbinds),
    ]);
    message(VERSION_V1, community, tlv(PDU_TRAP_V1, &body))
}
