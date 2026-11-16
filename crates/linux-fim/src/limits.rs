use crate::model::Limits;


pub const SUPPORTED_VERSION: u32 = 1;


pub const MAX_TABLE_BYTES: usize = 65_536;


pub const MAX_ROLES: usize = 32;


pub const MAX_WATCHED: usize = 64;


pub const MAX_HONEYTOKENS: usize = 32;


pub const MAX_PATH_BYTES: usize = 255;


pub const MAX_ROLE_NAME_BYTES: usize = 32;


pub const MAX_SELECTOR_VALUES: usize = 8;


pub const MAX_KPROBE_SELECTORS: usize = 5;


pub const MAX_KPROBE_ARGS: usize = 8;


pub const MAX_EQUAL_SELECTORS: usize = 8;


pub const MAX_PREFIX_SELECTORS: usize = 7;


pub const MAX_EVENT_LINE_BYTES: usize = 4_194_304;


pub const MAX_FIELD_BYTES: usize = 1024;


pub const POLICY_PREFIX: &str = "ostyr-fim-";


pub const NAMES_POLICY_PREFIX: &str = "ostyr-fimn-";


pub const DELETE_POLICY_PREFIX: &str = "ostyr-fimd-";


pub const ATTRIBUTE_POLICY_PREFIX: &str = "ostyr-fimx-";


pub const ANCESTOR_POLICY_PREFIX: &str = "ostyr-fima-";


pub const TOKEN_POLICY_PREFIX: &str = "ostyr-fimt-";


pub const UNKNOWN_PROCESS: &str = "unknown";


pub fn default_limits() -> Limits {
    Limits {
        max_table_bytes: MAX_TABLE_BYTES,
        max_roles: MAX_ROLES,
        max_watched: MAX_WATCHED,
        max_honeytokens: MAX_HONEYTOKENS,
        max_path_bytes: MAX_PATH_BYTES,
        max_selector_values: MAX_SELECTOR_VALUES,
        max_kprobe_selectors: MAX_KPROBE_SELECTORS,
        max_equal_selectors: MAX_EQUAL_SELECTORS,
        max_prefix_selectors: MAX_PREFIX_SELECTORS,
    }
}


pub const UNRESOLVED_NAME: &str = "[unresolved]";
