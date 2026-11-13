use crate::error::ShareError;
use crate::model::{RawKey, RawKeyFile, RelayKey, RelayKeys};
use agent_command::error::KeyFileError;
use agent_command::keys::parse_public_key;
use agent_command::model::TrustedKeys;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use data_encoding::HEXLOWER;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};


pub fn relay_key(raw: &RawKey) -> Result<RelayKey, KeyFileError> {
    if raw.not_before > raw.not_after {
        Err(KeyFileError::Validity { id: raw.id.clone() })
    } else {
        Ok(RelayKey {
            public_key: parse_public_key(&raw.id, &raw.public_key)?,
            not_before: raw.not_before,
            not_after: raw.not_after,
            revoked: raw.revoked,
        })
    }
}


impl TryFrom<RawKeyFile> for RelayKeys {
    type Error = KeyFileError;

    fn try_from(file: RawKeyFile) -> Result<Self, Self::Error> {
        let keys = file.keys.iter().try_fold(BTreeMap::<String, RelayKey>::new(), |mut keys, raw| {
            let key = relay_key(raw)?;
            let same_key = keys
                .iter()
                .find_map(|(id, other)| (other.public_key == key.public_key).then(|| id.clone()));
            match (same_key, keys.insert(raw.id.clone(), key)) {
                (_, Some(_)) => Err(KeyFileError::Duplicate { id: raw.id.clone() }),
                (Some(first), None) => Err(KeyFileError::DuplicatePublicKey { id: raw.id.clone(), first }),
                (None, None) => Ok(keys),
            }
        })?;
        Ok(RelayKeys { keys })
    }
}


/// One line per key so a reload's diff and audit entry show which key changed.
pub fn keys_state(keys: &RelayKeys) -> ConfigState {
    keys.keys
        .iter()
        .map(|(id, key)| {
            let summary = format!(
                "not_before={} not_after={} revoked={} public_key={}",
                key.not_before,
                key.not_after,
                key.revoked,
                HEXLOWER.encode(&key.public_key.to_bytes())
            );
            (format!("keys.{id}"), summary)
        })
        .collect()
}


/// The first relay key whose id or public key is also an agent-command key, so one key can never sign both.
pub fn find_shared(relay: &RelayKeys, agent: &TrustedKeys) -> Option<ShareError> {
    relay.keys.iter().find_map(|(id, key)| {
        if agent.keys.contains_key(id) {
            Some(ShareError::SharedId { id: id.clone() })
        } else if agent.keys.values().any(|other| other.public_key == key.public_key) {
            Some(ShareError::SharedPublicKey { id: id.clone() })
        } else {
            None
        }
    })
}


pub fn check_against_agent_keys(relay: &RelayKeys, agent_path: &Path) -> Result<(), ConfigError> {
    let agent = load_file::<TrustedKeys>(agent_path)?;
    find_shared(relay, &agent).map_or(Ok(()), |shared| {
        Err(ConfigError::WatchedFile {
            file: agent_path.display().to_string(),
            reason: shared.to_string(),
        })
    })
}


/// With `agent_keys` given, a relay file sharing an id or a public key with it is refused, at start and at every reload.
pub fn keys_loader(path: PathBuf, agent_keys: Option<PathBuf>) -> Box<LoaderFn<RelayKeys>> {
    Box::new(move || {
        let relay = load_file::<RelayKeys>(&path)?;
        agent_keys.as_deref().map_or(Ok(()), |other| check_against_agent_keys(&relay, other))?;
        Ok(relay)
    })
}


pub fn open_keys_engine(
    path: PathBuf,
    agent_keys: Option<PathBuf>,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<ReloadEngine<RelayKeys>, ConfigError> {
    open_engine(keys_loader(path, agent_keys), keys_state, Vec::new(), audit, context)
}
