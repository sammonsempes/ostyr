use prost::encoding::encode_varint;


pub const RESOURCE_METRICS: u8 = 0x0a;


pub const RESOURCE: u8 = 0x0a;


pub const SCOPE_METRICS: u8 = 0x12;


pub const METRIC: u8 = 0x12;


pub const GAUGE: u8 = 0x2a;


pub const POINTS: u8 = 0x0a;


pub const VALUE: u8 = 0x12;


pub fn framed(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    encode_varint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}
