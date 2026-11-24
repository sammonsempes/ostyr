use crate::error::TriageError;
use serde::{Deserialize, Serialize};


const KIB: usize = 1024;


const MIB: usize = KIB * KIB;


pub const MAX_MESSAGE_BYTES: usize = 25 * MIB;


pub const MAX_PARTS: usize = 256;


pub const MAX_NESTING: usize = 3;


pub const MAX_HEADERS: usize = 512;


pub const MAX_HEADER_BYTES: usize = 16 * KIB;


pub const MAX_HEADER_REGION_BYTES: usize = MAX_HEADERS * MAX_HEADER_BYTES;


pub const MAX_URLS: usize = 500;


pub const MAX_ATTACHMENTS: usize = 64;


pub const MAX_NESTED_MESSAGES: usize = 8;


pub const MAX_PART_BYTES: usize = 16 * MIB;


pub const MAX_URL_BYTES: usize = 2 * KIB;


pub const MAX_SUBJECT_CHARS: usize = 200;


pub const MAX_NAME_CHARS: usize = 255;


pub const MAX_ADDRESS_BYTES: usize = 320;


pub const MAX_FROM_ADDRESSES: usize = 32;


pub const MAX_CHILD_ADDRESS_SPACE: usize = 512 * MIB;


pub const CEILING_CHILD_ADDRESS_SPACE: usize = 2048 * MIB;


pub const MAX_CHILD_DEADLINE_MILLIS: u64 = 30_000;


pub const CEILING_CHILD_DEADLINE_MILLIS: u64 = 120_000;


pub const MAX_CHILD_OUTPUT_BYTES: usize = 8 * MIB;


pub const CEILING_CHILD_OUTPUT_BYTES: usize = 32 * MIB;


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub message_bytes: usize,
    pub parts: usize,
    pub nesting: usize,
    pub headers: usize,
    pub header_bytes: usize,
    pub urls: usize,
    pub attachments: usize,
    pub nested_messages: usize,
    pub part_bytes: usize,
    pub url_bytes: usize,
    pub subject_chars: usize,
    pub name_chars: usize,
    pub address_bytes: usize,
    pub child_address_space: usize,
    pub child_deadline_millis: u64,
    pub child_output_bytes: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            message_bytes: MAX_MESSAGE_BYTES,
            parts: MAX_PARTS,
            nesting: MAX_NESTING,
            headers: MAX_HEADERS,
            header_bytes: MAX_HEADER_BYTES,
            urls: MAX_URLS,
            attachments: MAX_ATTACHMENTS,
            nested_messages: MAX_NESTED_MESSAGES,
            part_bytes: MAX_PART_BYTES,
            url_bytes: MAX_URL_BYTES,
            subject_chars: MAX_SUBJECT_CHARS,
            name_chars: MAX_NAME_CHARS,
            address_bytes: MAX_ADDRESS_BYTES,
            child_address_space: MAX_CHILD_ADDRESS_SPACE,
            child_deadline_millis: MAX_CHILD_DEADLINE_MILLIS,
            child_output_bytes: MAX_CHILD_OUTPUT_BYTES,
        }
    }
}


/// The isolation limits must be non-zero and within their ceilings.
pub fn check_child_limits(limits: &Limits) -> Result<(), TriageError> {
    let space = (1..=CEILING_CHILD_ADDRESS_SPACE).contains(&limits.child_address_space);
    let deadline = (1..=CEILING_CHILD_DEADLINE_MILLIS).contains(&limits.child_deadline_millis);
    let output = (1..=CEILING_CHILD_OUTPUT_BYTES).contains(&limits.child_output_bytes);
    (space && deadline && output).then_some(()).ok_or(TriageError::LimitsRefused)
}
