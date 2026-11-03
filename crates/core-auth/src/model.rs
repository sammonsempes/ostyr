use crate::types::RoleSet;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpEnrolment {
    pub encrypted_secret: String,
    pub last_step: u64,
    pub backup_code_hashes: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub username: String,
    pub password_hash: String,
    pub roles: RoleSet,
    pub totp: Option<TotpEnrolment>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub created_at: OffsetDateTime,
    pub last_seen: OffsetDateTime,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attempts {
    pub failures: Vec<OffsetDateTime>,
    pub locked_until: Option<OffsetDateTime>,
}
