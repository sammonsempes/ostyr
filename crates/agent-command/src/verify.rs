use crate::codec::{decode_exact, signing_message};
use crate::error::{CommandError, StoreError};
use crate::model::{Action, Command, Envelope, KeyClass, TrustedKey, TrustedKeys, Verifier, CLOCK_SKEW_SECONDS, MAX_LIFETIME_SECONDS};
use crate::store::{file_saver, load_sequence};
use crate::types::SaveFn;
use core_config::reload::{current_config, ReloadEngine};
use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use tracing::warn;


/// The stored sequence is loaded now: a corrupt store stops the agent instead of re-opening the replay window.
pub fn open_verifier(agent_id: &str, tenant: &str, keys: Arc<ReloadEngine<TrustedKeys>>, state_file: &Path) -> Result<Verifier, StoreError> {
    Ok(open_verifier_with(
        agent_id,
        tenant,
        keys,
        load_sequence(state_file)?,
        file_saver(state_file.to_path_buf()),
    ))
}


pub fn open_verifier_with(agent_id: &str, tenant: &str, keys: Arc<ReloadEngine<TrustedKeys>>, last_sequence: u64, save: Box<SaveFn>) -> Verifier {
    Verifier {
        agent_id: agent_id.to_owned(),
        tenant: tenant.to_owned(),
        keys,
        last_sequence: Mutex::new(last_sequence),
        save,
    }
}


pub fn action_is_sensitive(action: &Action) -> bool {
    match action {
        Action::Ping | Action::CollectStatus => false,
        Action::Isolate
        | Action::Kill { .. }
        | Action::RunScript { .. }
        | Action::Update { .. }
        | Action::Uninstall
        | Action::ChangePolicy { .. } => true,
    }
}


pub fn action_name(action: &Action) -> &'static str {
    match action {
        Action::Ping => "ping",
        Action::CollectStatus => "collect_status",
        Action::Isolate => "isolate",
        Action::Kill { .. } => "kill",
        Action::RunScript { .. } => "run_script",
        Action::Update { .. } => "update",
        Action::Uninstall => "uninstall",
        Action::ChangePolicy { .. } => "change_policy",
    }
}


pub fn check_key(key: &TrustedKey, now: u64) -> Result<(), CommandError> {
    if key.revoked {
        Err(CommandError::KeyRevoked)
    } else if now < key.not_before || now > key.not_after {
        Err(CommandError::KeyOutsideValidity)
    } else {
        Ok(())
    }
}


pub fn check_signature(key: &TrustedKey, envelope: &Envelope) -> Result<(), CommandError> {
    let bytes = <[u8; SIGNATURE_LENGTH]>::try_from(envelope.signature.as_slice()).map_err(|_| CommandError::BadSignature)?;
    key.public_key
        .verify_strict(&signing_message(&envelope.command), &Signature::from_bytes(&bytes))
        .map_err(|_| CommandError::BadSignature)
}


pub fn check_target(verifier: &Verifier, command: &Command) -> Result<(), CommandError> {
    if command.agent_id != verifier.agent_id {
        Err(CommandError::WrongAgent)
    } else if command.tenant != verifier.tenant {
        Err(CommandError::WrongTenant)
    } else {
        Ok(())
    }
}


pub fn check_times(command: &Command, now: u64) -> Result<(), CommandError> {
    if command.expires_at <= command.issued_at {
        Err(CommandError::InvalidLifetime)
    } else if command.expires_at - command.issued_at > MAX_LIFETIME_SECONDS {
        Err(CommandError::LifetimeTooLong)
    } else if now >= command.expires_at {
        Err(CommandError::Expired)
    } else if command.issued_at > now.saturating_add(CLOCK_SKEW_SECONDS) {
        Err(CommandError::IssuedInFuture)
    } else {
        Ok(())
    }
}


pub fn check_class(class: KeyClass, action: &Action) -> Result<(), CommandError> {
    if action_is_sensitive(action) && class != KeyClass::Sensitive {
        Err(CommandError::SensitiveActionNeedsSensitiveKey)
    } else {
        Ok(())
    }
}


/// The lock is held from the comparison to the durable save; a failed save leaves the sequence unaccepted.
pub fn accept_sequence(verifier: &Verifier, sequence: u64) -> Result<(), CommandError> {
    let mut last = verifier.last_sequence.lock().unwrap_or_else(PoisonError::into_inner);
    if sequence <= *last {
        Err(CommandError::ReplayedSequence)
    } else {
        (verifier.save)(sequence).map_err(CommandError::Store)?;
        *last = sequence;
        Ok(())
    }
}


/// The signature is verified over the received bytes before the command is decoded.
pub fn check(verifier: &Verifier, bytes: &[u8], now: u64) -> Result<Command, CommandError> {
    let envelope: Envelope = decode_exact(bytes)?;
    let keys = current_config(&verifier.keys);
    let key = keys.keys.get(&envelope.key_id).ok_or(CommandError::UnknownKey)?;
    check_key(key, now)?;
    check_signature(key, &envelope)?;
    let command: Command = decode_exact(&envelope.command)?;
    check_target(verifier, &command)?;
    check_times(&command, now)?;
    check_class(key.class, &command.action)?;
    accept_sequence(verifier, command.sequence)?;
    Ok(command)
}


/// Fails closed; the refusal is logged with its reason only, never with the command.
pub fn verify_command(verifier: &Verifier, bytes: &[u8], now: u64) -> Result<Command, CommandError> {
    check(verifier, bytes, now).inspect_err(|refusal| warn!(reason = %refusal, "command refused"))
}
