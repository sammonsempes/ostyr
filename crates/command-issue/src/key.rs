use crate::error::{KeyRefusal, PairError};
use crate::limits::{LIFETIME_SECONDS, ROUTINE_ACTIONS, SEED_BYTES, SEED_HEX_BYTES, SEED_READ_CAPACITY, SEED_READ_LIMIT};
use agent_command::model::{KeyClass, TrustedKeys};
use arc_swap::ArcSwap;
use core_config::secret_file::open_secret;
use data_encoding::HEXLOWER;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;


/// The routine signing pair; `SigningKey` prints only its public key in `Debug` and wipes itself on drop.
#[derive(Debug, Clone)]
pub struct Pair {
    pub key_id: String,
    pub public_key: VerifyingKey,
    pub signing_key: SigningKey,
}


/// The key must be the seed's public key, routine, scoped to exactly ping and collect_status, live, and valid for a whole envelope lifetime.
pub fn check_key(keys: &TrustedKeys, pair: &Pair, now: u64) -> Result<(), KeyRefusal> {
    let key = keys.keys.get(&pair.key_id).ok_or(KeyRefusal::UnknownKey)?;
    let scope: BTreeSet<String> = ROUTINE_ACTIONS.iter().map(|name| (*name).to_owned()).collect();
    if key.public_key != pair.public_key {
        Err(KeyRefusal::PublicKeyMismatch)
    } else if key.class != KeyClass::Routine {
        Err(KeyRefusal::WrongClass)
    } else if key.actions.as_ref() != Some(&scope) {
        Err(KeyRefusal::WrongScope)
    } else if key.revoked {
        Err(KeyRefusal::Revoked)
    } else if key.not_before > now {
        Err(KeyRefusal::NotYetValid)
    } else if now.checked_add(LIFETIME_SECONDS).is_none_or(|end| end > key.not_after) {
        Err(KeyRefusal::ExpiresTooSoon)
    } else {
        Ok(())
    }
}


/// At most `SEED_READ_LIMIT` bytes, exactly 64 lowercase hex characters and an optional newline.
pub fn decode_seed(source: &mut dyn Read) -> Result<Zeroizing<[u8; SEED_BYTES]>, PairError> {
    let mut text = Zeroizing::new(Vec::with_capacity(SEED_READ_CAPACITY));
    Read::take(&mut *source, SEED_READ_LIMIT)
        .read_to_end(&mut text)
        .map_err(PairError::Read)?;
    let hex = text.strip_suffix(b"\n").unwrap_or(text.as_slice());
    let mut seed = Zeroizing::new([0; SEED_BYTES]);
    if hex.len() == SEED_HEX_BYTES {
        HEXLOWER.decode_mut(hex, &mut *seed).map_err(|_partial| PairError::Format)?;
        Ok(seed)
    } else {
        Err(PairError::Format)
    }
}


/// The seed file is opened through `open_secret` (regular, owned by the service or root, no group or other bit) and read from that handle.
pub fn read_seed(path: &Path) -> Result<Zeroizing<[u8; SEED_BYTES]>, PairError> {
    let mut file = open_secret(path).map_err(PairError::Open)?;
    decode_seed(&mut file)
}


pub fn load_pair(seed_file: &Path, key_id: &str, keys: &TrustedKeys, now: u64) -> Result<Pair, PairError> {
    let seed = read_seed(seed_file)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let pair = Pair {
        key_id: key_id.to_owned(),
        public_key: signing_key.verifying_key(),
        signing_key,
    };
    check_key(keys, &pair, now).map_err(PairError::Key)?;
    Ok(pair)
}


/// Reads the seed again and swaps the pair only when every key check passes; on a refusal the old pair stays.
pub fn swap_pair(holder: &ArcSwap<Pair>, seed_file: &Path, key_id: &str, keys: &TrustedKeys, now: u64) -> Result<(), PairError> {
    let pair = load_pair(seed_file, key_id, keys, now)?;
    holder.store(Arc::new(pair));
    Ok(())
}


/// The reloadable state of the pair: the key id and the public key, never the seed.
pub fn pair_state(pair: &Pair) -> Vec<(String, String)> {
    vec![
        ("commands.key_id".to_owned(), pair.key_id.clone()),
        ("commands.public_key".to_owned(), HEXLOWER.encode(&pair.public_key.to_bytes())),
    ]
}
