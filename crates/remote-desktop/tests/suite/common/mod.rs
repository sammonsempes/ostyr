pub mod types;


use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use data_encoding::HEXLOWER;
use ed25519_dalek::SigningKey;
use remote_desktop::keys::open_keys_engine;
use remote_desktop::model::{RelayClaims, RelayKeys, Verifier, NONCE_LENGTH, SESSION_ID_LENGTH};
use remote_desktop::sign::memory_signer;
use remote_desktop::token::{issue_token, open_verifier, seal};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;


pub const NOW: u64 = 1_700_000_000;


pub const LIFETIME: u64 = 60;


pub const PEER: &str = "123456789";


pub const TENANT: &str = "acme";


pub const KEY_ID: &str = "relay-1";


pub const RELAY_SEED: u8 = 5;


pub const OTHER_SEED: u8 = 6;


pub const AGENT_SEED: u8 = 7;


pub const SEED_LENGTH: usize = 32;


pub const SMALL_CAP: usize = 8;


pub const SECOND_NONCE: u8 = 2;


pub const HALF_LIFETIME: u64 = 30;


pub const HEAD_START: u64 = 10;


pub const KEY_GAP: u64 = 5;


pub const THIRD_NONCE: u8 = 3;


pub const SLACK: u64 = 2;


pub const EARLIER: u64 = 1;


pub const LATER: u64 = 2;


pub const GARBAGE_BYTE: u8 = 0xff;


pub const GARBAGE_LENGTH: usize = 40;


pub const SHORT_SIGNATURE_LENGTH: usize = 10;


pub const CASE_COUNT: usize = 8;


pub const LINE_COUNT: usize = 4;


pub const THIRD_LINE: usize = 2;


pub const FOURTH_LINE: usize = 3;


pub fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; SEED_LENGTH])
}


pub fn public_hex(seed: u8) -> String {
    HEXLOWER.encode(&signing_key(seed).verifying_key().to_bytes())
}


pub fn key_entry(id: &str, class: &str, seed: u8, not_before: u64, not_after: u64, revoked: bool) -> String {
    format!(
        "  - id: {id}\n    class: {class}\n    public_key: {}\n    not_before: {not_before}\n    not_after: {not_after}\n    revoked: {revoked}\n",
        public_hex(seed)
    )
}


pub fn relay_keys_text(not_before: u64, not_after: u64, revoked: bool) -> String {
    format!("keys:\n{}", key_entry(KEY_ID, "relay", RELAY_SEED, not_before, not_after, revoked))
}


pub fn valid_keys_text() -> String {
    relay_keys_text(NOW - LIFETIME, NOW + LIFETIME * LIFETIME, false)
}


pub fn agent_keys_text(id: &str, seed: u8) -> String {
    format!("keys:\n{}", key_entry(id, "routine", seed, NOW - LIFETIME, NOW + LIFETIME, false))
}


pub fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


pub fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "remote-desktop".to_owned(),
        tenant: TENANT.to_owned(),
        module: "remote-desktop".to_owned(),
        target: "keys.yaml".to_owned(),
        request_id: "keys-reload".to_owned(),
    }
}


pub fn engine_at(path: &Path, agent_keys: Option<&Path>) -> Result<Arc<ReloadEngine<RelayKeys>>, Box<dyn std::error::Error>> {
    let log = genesis_log(io::sink());
    Ok(Arc::new(open_keys_engine(
        path.to_path_buf(),
        agent_keys.map(Path::to_path_buf),
        Box::new(move |entry| append(&log, entry)),
        context(),
    )?))
}


pub fn claims(nonce: u8) -> RelayClaims {
    RelayClaims {
        key_id: KEY_ID.to_owned(),
        tenant: TENANT.to_owned(),
        session_id: [nonce; SESSION_ID_LENGTH],
        device_peer_id: PEER.to_owned(),
        viewer_subject: "alice".to_owned(),
        not_before: NOW,
        expires_at: NOW + LIFETIME,
        nonce: [nonce; NONCE_LENGTH],
    }
}


pub fn token_with(claims: &RelayClaims, seed: u8) -> Result<String, Box<dyn std::error::Error>> {
    Ok(issue_token(&memory_signer(signing_key(seed)), claims)?)
}


pub fn token_unchecked(claims: &RelayClaims) -> Result<String, Box<dyn std::error::Error>> {
    Ok(seal(
        &memory_signer(signing_key(RELAY_SEED)),
        &claims.key_id,
        postcard::to_stdvec(claims)?,
    )?)
}


pub fn token_for(claims: &RelayClaims) -> Result<String, Box<dyn std::error::Error>> {
    token_with(claims, RELAY_SEED)
}


pub struct Setup {
    pub _dir: TempDir,
    pub verifier: Verifier,
}


pub fn setup_with(keys_text: &str, cap: usize) -> Result<Setup, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let keys_path = dir.path().join("keys.yaml");
    replace_file(&keys_path, keys_text)?;
    let verifier = open_verifier(engine_at(&keys_path, None)?, cap)?;
    Ok(Setup { _dir: dir, verifier })
}


pub fn setup() -> Result<Setup, Box<dyn std::error::Error>> {
    setup_with(&valid_keys_text(), SMALL_CAP)
}
