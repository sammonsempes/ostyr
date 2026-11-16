use linux_fim::model::{Honeytoken, HoneytokenKind, Role, WatchKind, WatchedPath};
use std::fs;


pub const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");


pub const DEFAULT_TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/roles/linux.yaml");


pub const SMALL_CAP: usize = 2;


pub const BIG_COUNT: usize = 9;


pub fn fixture(name: &str) -> Result<String, std::io::Error> {
    fs::read_to_string(format!("{FIXTURES}{name}"))
}


pub fn role(name: &str, watched: &[(&str, WatchKind)], tokens: &[&str]) -> Role {
    Role {
        name: name.to_string(),
        watched: watched
            .iter()
            .map(|(path, kind)| WatchedPath {
                path: (*path).to_string(),
                kind: *kind,
            })
            .collect(),
        honeytokens: tokens
            .iter()
            .map(|path| Honeytoken {
                path: (*path).to_string(),
                kind: HoneytokenKind::Canary,
            })
            .collect(),
    }
}


pub const LAST_INDEX: usize = 2;


pub const UNSUPPORTED_VERSION: u32 = 2;


pub const OVER_CAP: usize = 3;


pub const PREFIX_KPROBES: usize = 5;


pub const NAME_PREFIX_KPROBES: usize = 5;


pub const RENAME_TARGET: u32 = 3;


pub const SYMLINK_NAME: u32 = 1;


pub const LINK_CREATED: u32 = 2;


pub const MMAP_MATCHES: usize = 3;


pub const MAX_PREFIX_SELECTORS: usize = 7;


pub const WATCHED_FILES: usize = 5;


pub const WATCHED_PREFIXES: usize = 3;


pub const HONEYTOKENS: usize = 4;


pub const MAY_WRITE: u32 = 2;


pub const MMAP_FLAGS: u32 = 2;
