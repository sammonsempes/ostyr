//! Default caps.

use crate::model::Limits;


pub const DEFAULT_MAX_BYTES: u64 = 1_048_576;


pub const DEFAULT_MAX_ATTRIBUTES: usize = 256;


pub fn default_limits() -> Limits {
    Limits {
        max_bytes: DEFAULT_MAX_BYTES,
        max_attributes: DEFAULT_MAX_ATTRIBUTES,
    }
}
