use crate::error::ListError;
use crate::model::{NtHash, DECIMAL_BASE, HASH_BYTES, HASH_HEX_LEN};
use data_encoding::HEXLOWER_PERMISSIVE;
use zeroize::Zeroizing;


/// 32 hex digits (any case) as a hash.
pub fn decode_hash(hex: &[u8]) -> Option<NtHash> {
    if hex.len() == HASH_HEX_LEN {
        let mut bytes = Zeroizing::new([0u8; HASH_BYTES]);
        let decoded = HEXLOWER_PERMISSIVE.decode_mut(hex, bytes.as_mut_slice());
        decoded.is_ok().then_some(NtHash(bytes))
    } else {
        None
    }
}


/// A non-empty run of decimal digits that fits in a `u64`.
pub fn parse_count(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        None
    } else {
        digits.iter().try_fold(0u64, |total, byte| {
            let digit = char::from(*byte).to_digit(DECIMAL_BASE)?;
            total.checked_mul(u64::from(DECIMAL_BASE))?.checked_add(u64::from(digit))
        })
    }
}


/// `<32 hex>:<decimal count>` without its newline (a trailing CR is dropped); the count is validated then dropped.
pub fn parse_line(line: &[u8]) -> Result<NtHash, ListError> {
    let text = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = text.split(|byte| *byte == b':');
    let fields = (parts.next(), parts.next(), parts.next());
    let parsed = match fields {
        (Some(hash), Some(count), None) => parse_count(count).and_then(|_| decode_hash(hash)),
        _ => None,
    };
    parsed.ok_or(ListError::Malformed)
}
