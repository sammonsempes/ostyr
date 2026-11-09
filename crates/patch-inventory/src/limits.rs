//! Default caps; every parser takes its own `Limits`.

use crate::model::Limits;


pub const MAX_INPUT_BYTES: usize = 4_194_304;


pub const MAX_INPUT_LINES: usize = 100_000;


pub const MAX_LINE_BYTES: usize = 4096;


pub fn default_limits() -> Limits {
    Limits {
        max_bytes: MAX_INPUT_BYTES,
        max_lines: MAX_INPUT_LINES,
        max_line_bytes: MAX_LINE_BYTES,
    }
}
