use crate::error::KeyFileError;
use crate::model::{KeyClass, RawKey, RawKeyFile, TrustedKey, TrustedKeys};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use data_encoding::HEXLOWER;
use ed25519_dalek::{VerifyingKey, PUBLIC_KEY_LENGTH};
use std::collections::BTreeMap;
use std::path::PathBuf;


pub fn class_name(class: KeyClass) -> &'static str {
    match class {
        KeyClass::Routine => "routine",
        KeyClass::Sensitive => "sensitive",
    }
}


pub fn parse_public_key(id: &str, text: &str) -> Result<VerifyingKey, KeyFileError> {
    let bytes = HEXLOWER
        .decode(text.as_bytes())
        .map_err(|source| KeyFileError::Hex { id: id.to_owned(), source })?;
    let array = <[u8; PUBLIC_KEY_LENGTH]>::try_from(bytes.as_slice()).map_err(|_| KeyFileError::Length { id: id.to_owned() })?;
    VerifyingKey::from_bytes(&array).map_err(|source| KeyFileError::PublicKey { id: id.to_owned(), source })
}


pub fn trusted_key(raw: &RawKey) -> Result<TrustedKey, KeyFileError> {
    if raw.not_before > raw.not_after {
        Err(KeyFileError::Validity { id: raw.id.clone() })
    } else {
        Ok(TrustedKey {
            class: raw.class,
            public_key: parse_public_key(&raw.id, &raw.public_key)?,
            not_before: raw.not_before,
            not_after: raw.not_after,
            revoked: raw.revoked,
        })
    }
}


impl TryFrom<RawKeyFile> for TrustedKeys {
    type Error = KeyFileError;

    fn try_from(file: RawKeyFile) -> Result<Self, Self::Error> {
        let keys = file.keys.iter().try_fold(BTreeMap::<String, TrustedKey>::new(), |mut keys, raw| {
            let key = trusted_key(raw)?;
            let same_key = keys
                .iter()
                .find_map(|(id, other)| (other.public_key == key.public_key).then(|| id.clone()));
            match (same_key, keys.insert(raw.id.clone(), key)) {
                (_, Some(_)) => Err(KeyFileError::Duplicate { id: raw.id.clone() }),
                (Some(first), None) => Err(KeyFileError::DuplicatePublicKey { id: raw.id.clone(), first }),
                (None, None) => Ok(keys),
            }
        })?;
        Ok(TrustedKeys { keys })
    }
}


/// One line per key so a reload's diff and audit entry show which key changed.
pub fn keys_state(keys: &TrustedKeys) -> ConfigState {
    keys.keys
        .iter()
        .map(|(id, key)| {
            let summary = format!(
                "class={} not_before={} not_after={} revoked={} public_key={}",
                class_name(key.class),
                key.not_before,
                key.not_after,
                key.revoked,
                HEXLOWER.encode(&key.public_key.to_bytes())
            );
            (format!("keys.{id}"), summary)
        })
        .collect()
}


pub fn keys_loader(path: PathBuf) -> Box<LoaderFn<TrustedKeys>> {
    Box::new(move || load_file::<TrustedKeys>(&path))
}


pub fn open_keys_engine(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<TrustedKeys>, ConfigError> {
    open_engine(keys_loader(path), keys_state, Vec::new(), audit, context)
}
