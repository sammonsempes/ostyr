use core_auth::types::RoleSet;
use std::collections::BTreeMap;


pub type Seconds = i64;


pub type ApproverRoles = BTreeMap<String, RoleSet>;
