use crate::action::validate_action;
use crate::codec::{decode_exact, signing_message};
use crate::error::{CommandError, StoreError};
use crate::model::{
    Action, Command, Envelope, KeyClass, Sequences, TrustedKey, TrustedKeys, Verifier, CLOCK_SKEW_SECONDS, EXCLUSIVE_ACTIONS, MAX_LIFETIME_SECONDS,
    MAX_SEQUENCE_ADVANCE,
};
use crate::store::{check_state_private, file_saver, load_sequences};
use crate::types::SaveFn;
use core_config::reload::{current_config, ReloadEngine};
use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use tracing::warn;


/// The state file must be private; the stored sequences are loaded now: a corrupt store stops the agent instead of re-opening the replay window.
pub fn open_verifier(agent_id: &str, tenant: &str, keys: Arc<ReloadEngine<TrustedKeys>>, state_file: &Path) -> Result<Verifier, StoreError> {
    check_state_private(state_file)?;
    Ok(open_verifier_with(
        agent_id,
        tenant,
        keys,
        load_sequences(state_file)?,
        file_saver(state_file.to_path_buf()),
    ))
}


pub fn open_verifier_with(
    agent_id: &str,
    tenant: &str,
    keys: Arc<ReloadEngine<TrustedKeys>>,
    last_sequences: Sequences,
    save: Box<SaveFn>,
) -> Verifier {
    Verifier {
        agent_id: agent_id.to_owned(),
        tenant: tenant.to_owned(),
        keys,
        last_sequences: Mutex::new(last_sequences),
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
        | Action::ChangePolicy { .. }
        | Action::InstallUpdates { .. }
        | Action::Reboot { .. }
        | Action::OpenShell { .. } => true,
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
        Action::InstallUpdates { .. } => "install_updates",
        Action::Reboot { .. } => "reboot",
        Action::OpenShell { .. } => "open_shell",
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


pub fn check_binding(key_id: &str, key: &TrustedKey, command: &Command) -> Result<(), CommandError> {
    if command.key_id != key_id {
        Err(CommandError::KeyIdMismatch)
    } else if command.key_class != key.class {
        Err(CommandError::KeyClassMismatch)
    } else {
        Ok(())
    }
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


pub fn check_scope(key: &TrustedKey, action: &Action, exclusive: &[&str]) -> Result<(), CommandError> {
    let kind = action_name(action);
    let in_scope = match &key.actions {
        Some(scope) => scope.contains(kind) && (scope.len() == 1 || !exclusive.contains(&kind)),
        None => !exclusive.contains(&kind),
    };
    if in_scope {
        Ok(())
    } else {
        Err(CommandError::ActionOutOfScope(kind))
    }
}


/// Runs again under the sequence lock against the current keys: a reload that revoked, replaced or narrowed the key refuses the command.
pub fn recheck_signer(verifier: &Verifier, first: &TrustedKey, command: &Command, now: u64, exclusive: &[&str]) -> Result<(), CommandError> {
    let keys = current_config(&verifier.keys);
    let key = keys.keys.get(&command.key_id).ok_or(CommandError::UnknownKey)?;
    check_key(key, now)?;
    if key.public_key != first.public_key {
        Err(CommandError::BadSignature)
    } else {
        check_binding(&command.key_id, key, command)?;
        check_class(key.class, &command.action)?;
        check_scope(key, &command.action, exclusive)
    }
}


/// The lock is held from the re-check and the comparison to the durable save; a failed save leaves the sequences unaccepted.
pub fn accept_sequence(verifier: &Verifier, first: &TrustedKey, command: &Command, now: u64, exclusive: &[&str]) -> Result<(), CommandError> {
    let mut last = verifier.last_sequences.lock().unwrap_or_else(PoisonError::into_inner);
    recheck_signer(verifier, first, command, now, exclusive)?;
    let class = first.class;
    let sequence = command.sequence;
    let previous = match class {
        KeyClass::Routine => last.routine,
        KeyClass::Sensitive => last.sensitive,
    };
    if sequence <= previous {
        Err(CommandError::ReplayedSequence)
    } else if sequence - previous > MAX_SEQUENCE_ADVANCE {
        Err(CommandError::SequenceJump)
    } else {
        let advanced = match class {
            KeyClass::Routine => Sequences { routine: sequence, ..*last },
            KeyClass::Sensitive => Sequences {
                sensitive: sequence,
                ..*last
            },
        };
        (verifier.save)(&advanced).map_err(CommandError::Store)?;
        *last = advanced;
        Ok(())
    }
}


/// `exclusive` and `between` are injected for tests; `between` runs after the checks and before the sequence lock.
pub fn check_with(verifier: &Verifier, bytes: &[u8], now: u64, exclusive: &[&str], between: &dyn Fn(&Verifier)) -> Result<Command, CommandError> {
    let envelope: Envelope = decode_exact(bytes)?;
    let keys = current_config(&verifier.keys);
    let key = keys.keys.get(&envelope.key_id).ok_or(CommandError::UnknownKey)?;
    check_key(key, now)?;
    check_signature(key, &envelope)?;
    let command: Command = decode_exact(&envelope.command)?;
    check_binding(&envelope.key_id, key, &command)?;
    check_target(verifier, &command)?;
    check_times(&command, now)?;
    validate_action(&command.action)?;
    check_class(key.class, &command.action)?;
    check_scope(key, &command.action, exclusive)?;
    between(verifier);
    accept_sequence(verifier, key, &command, now, exclusive)?;
    Ok(command)
}


/// The signature is verified over the received bytes before the command is decoded.
pub fn check(verifier: &Verifier, bytes: &[u8], now: u64) -> Result<Command, CommandError> {
    check_with(verifier, bytes, now, EXCLUSIVE_ACTIONS, &|_| {})
}


/// Fails closed; the refusal is logged with its reason only, never with the command.
pub fn verify_command(verifier: &Verifier, bytes: &[u8], now: u64) -> Result<Command, CommandError> {
    check(verifier, bytes, now).inspect_err(|refusal| warn!(reason = %refusal, "command refused"))
}
