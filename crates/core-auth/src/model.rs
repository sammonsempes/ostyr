use crate::types::RoleSet;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use webauthn_rs::prelude::{DiscoverableAuthentication, Passkey, PasskeyAuthentication, PasskeyRegistration};


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
    #[serde(default)]
    pub sessions_valid_after: Option<i64>,
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


#[derive(Debug, Clone)]
pub struct PendingLogin {
    pub nonce: String,
    pub verifier: SecretString,
    pub created_at: OffsetDateTime,
    pub source: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCredential {
    pub username: String,
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub passkey: Passkey,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialInfo {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
}


#[derive(Debug, Clone)]
pub enum ChallengeKind {
    Registration(PasskeyRegistration),
    SecondFactor(PasskeyAuthentication),
    Passwordless(DiscoverableAuthentication),
}


#[derive(Debug, Clone)]
pub struct Challenge {
    pub actor: String,
    pub user: String,
    pub created_at: OffsetDateTime,
    pub kind: ChallengeKind,
    pub reserved: bool,
}


#[derive(Debug, Clone)]
pub enum Prepared {
    SecondFactor(PasskeyAuthentication),
    Passwordless(DiscoverableAuthentication, Box<Passkey>),
}


#[derive(Debug, Clone)]
pub struct Located {
    pub user: String,
    pub prepared: Prepared,
}
