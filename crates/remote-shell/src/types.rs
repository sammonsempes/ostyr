use core_auth::types::RoleSet;
use std::collections::BTreeMap;


pub type Seconds = i64;


pub type ApproverRoles = BTreeMap<String, RoleSet>;


pub const HASH_LEN: usize = 32;


pub type ChainHash = [u8; HASH_LEN];
