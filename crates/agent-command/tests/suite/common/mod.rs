pub mod types;


use agent_command::keys::open_keys_engine;
use agent_command::model::{Action, Command, KeyClass, Sequences, TrustedKeys, Verifier, NONCE_LENGTH};
use agent_command::sign::{memory_signer, sign_command};
use agent_command::verify::open_verifier_with;
use core_audit::log::{append, genesis_log, owner_only};
use core_config::reload::{ReloadContext, ReloadEngine};
use data_encoding::HEXLOWER;
use ed25519_dalek::SigningKey;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;


pub const NOW: u64 = 1_700_000_000;


pub const LIFETIME: u64 = 60;


pub const AGENT: &str = "agent-1";


pub const TENANT: &str = "acme";


pub const ROUTINE_ID: &str = "routine-1";


pub const SENSITIVE_ID: &str = "sensitive-1";


pub const ROUTINE_SEED: u8 = 7;


pub const SENSITIVE_SEED: u8 = 9;


pub const SEED_LENGTH: usize = 32;


pub const SECOND: u64 = 2;


pub const THIRD: u64 = 3;


pub const KEY_COUNT: usize = 2;


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


pub fn keys_text(revoked: bool, not_after: u64) -> String {
    format!(
        "keys:\n{}{}",
        key_entry(ROUTINE_ID, "routine", ROUTINE_SEED, NOW - LIFETIME, not_after, revoked),
        key_entry(
            SENSITIVE_ID,
            "sensitive",
            SENSITIVE_SEED,
            NOW - LIFETIME,
            NOW + LIFETIME * LIFETIME,
            false
        )
    )
}


pub fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


pub fn private_file(path: &Path, text: &str) -> io::Result<()> {
    owner_only(OpenOptions::new().write(true).create(true).truncate(true))
        .open(path)?
        .write_all(text.as_bytes())
}


pub fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "agent-command".to_owned(),
        tenant: TENANT.to_owned(),
        module: "agent-command".to_owned(),
        target: "keys.yaml".to_owned(),
        request_id: "keys-reload".to_owned(),
    }
}


pub fn engine_at(path: &Path) -> Result<Arc<ReloadEngine<TrustedKeys>>, Box<dyn std::error::Error>> {
    let log = genesis_log(io::sink());
    Ok(Arc::new(open_keys_engine(
        path.to_path_buf(),
        Box::new(move |entry| append(&log, entry)),
        context(),
    )?))
}


pub fn verifier_with(engine: Arc<ReloadEngine<TrustedKeys>>, last_sequence: u64) -> Verifier {
    open_verifier_with(
        AGENT,
        TENANT,
        engine,
        Sequences {
            routine: last_sequence,
            sensitive: last_sequence,
        },
        Box::new(|_sequences| Ok(())),
    )
}


pub fn command(sequence: u64, action: Action) -> Command {
    Command {
        key_id: ROUTINE_ID.to_owned(),
        key_class: KeyClass::Routine,
        agent_id: AGENT.to_owned(),
        tenant: TENANT.to_owned(),
        issued_at: NOW,
        expires_at: NOW + LIFETIME,
        sequence,
        nonce: [sequence as u8; NONCE_LENGTH],
        action,
    }
}


pub fn sensitive_command(sequence: u64, action: Action) -> Command {
    Command {
        key_id: SENSITIVE_ID.to_owned(),
        key_class: KeyClass::Sensitive,
        ..command(sequence, action)
    }
}


pub fn sign_with(command: &Command, key_id: &str, seed: u8) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(sign_command(command, key_id, &memory_signer(signing_key(seed)))?)
}


pub fn routine_envelope(command: &Command) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    sign_with(command, ROUTINE_ID, ROUTINE_SEED)
}


pub fn sensitive_envelope(command: &Command) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    sign_with(
        &Command {
            key_id: SENSITIVE_ID.to_owned(),
            key_class: KeyClass::Sensitive,
            ..command.clone()
        },
        SENSITIVE_ID,
        SENSITIVE_SEED,
    )
}


pub struct Setup {
    pub _dir: TempDir,
    pub keys_path: PathBuf,
    pub engine: Arc<ReloadEngine<TrustedKeys>>,
    pub verifier: Verifier,
}


pub fn setup() -> Result<Setup, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let keys_path = dir.path().join("keys.yaml");
    replace_file(&keys_path, &keys_text(false, NOW + LIFETIME * LIFETIME))?;
    let engine = engine_at(&keys_path)?;
    let verifier = verifier_with(Arc::clone(&engine), 0);
    Ok(Setup {
        _dir: dir,
        keys_path,
        engine,
        verifier,
    })
}
