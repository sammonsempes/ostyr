//! Default caps; every parser takes its own `Limits`.

use crate::model::Limits;


pub const MAX_INPUT_BYTES: usize = 4_194_304;


pub const MAX_INPUT_LINES: usize = 100_000;


pub const MAX_LINE_BYTES: usize = 4096;


pub const MAX_WINDOWS_UPDATES: usize = 1000;


pub const MAX_ITEMS_PER_UPDATE: usize = 8;


pub const MAX_TITLE_BYTES: usize = 512;


pub fn default_limits() -> Limits {
    Limits {
        max_bytes: MAX_INPUT_BYTES,
        max_lines: MAX_INPUT_LINES,
        max_line_bytes: MAX_LINE_BYTES,
    }
}


pub const MAX_WINGET_UPDATES: usize = 1000;


pub const MAX_WINGET_ID_BYTES: usize = 128;


pub const MAX_WINGET_VERSION_BYTES: usize = 128;


pub const MIN_SEPARATOR_DASHES: usize = 20;


pub const MAX_WINGET_TABLES: usize = 2;


pub const SOURCE_OPEN_FAILED_EXIT: i32 = -1_978_335_157;


pub const ROW_CELL_COUNT: usize = 3;
