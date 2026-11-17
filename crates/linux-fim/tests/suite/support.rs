use linux_fim::limits::default_limits;
use linux_fim::model::{Honeytoken, HoneytokenKind, Role, WatchKind, WatchSets, WatchedPath};
use linux_fim::policy::watch_sets;
use linux_fim::roles::load_roles;
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


pub const RENAME_SOURCE: u32 = 1;


pub const RENAME_TARGET: u32 = 3;


pub const SYMLINK_NAME: u32 = 1;


pub const MAX_PREFIX_PER_POLICY: usize = 7;


pub const TOKEN_COUNT: usize = 4;


pub const ONE_SELECTOR: usize = 1;


pub const MAY_WRITE: u32 = 2;


pub const MMAP_FLAGS: u32 = 2;


pub fn sets() -> Result<WatchSets, Box<dyn std::error::Error>> {
    let table = load_roles(&fs::read_to_string(DEFAULT_TABLE)?, &default_limits())?;
    let server = table.roles.iter().find(|candidate| candidate.name == "server").ok_or("no server role")?;
    Ok(watch_sets(server))
}
