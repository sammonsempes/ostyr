use crate::error::ConnectorError;
use crate::manifest::{check, valid_name};
use crate::model::{RawKeyFile, TrustedKey, TrustedKeys, MAX_KEYS_BYTES, MAX_KEY_FILE_BYTES};
use crate::package::read_capped;
use core_config::parse::{parse_document, read_text_capped};
use core_config::secret_file::open_secret;
use data_encoding::HEXLOWER;
use ed25519_dalek::{SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use zeroize::Zeroizing;


pub fn parse_public_key(text: &str) -> Result<VerifyingKey, ConnectorError> {
    let bytes = HEXLOWER
        .decode(text.as_bytes())
        .map_err(|_| ConnectorError::Invalid { field: "keys.public_key" })?;
    let array = <[u8; PUBLIC_KEY_LENGTH]>::try_from(bytes.as_slice()).map_err(|_| ConnectorError::Invalid { field: "keys.public_key" })?;
    VerifyingKey::from_bytes(&array).map_err(|_| ConnectorError::Invalid { field: "keys.public_key" })
}


impl TryFrom<RawKeyFile> for TrustedKeys {
    type Error = ConnectorError;

    fn try_from(file: RawKeyFile) -> Result<Self, Self::Error> {
        let keys = file.keys.iter().try_fold(BTreeMap::<String, TrustedKey>::new(), |mut keys, raw| {
            check(valid_name(&raw.id), "keys.id")?;
            check(valid_name(&raw.publisher), "keys.publisher")?;
            let key = TrustedKey {
                publisher: raw.publisher.clone(),
                public_key: parse_public_key(&raw.public_key)?,
                not_after: raw.not_after,
            };
            check(keys.insert(raw.id.clone(), key).is_none(), "keys.id")?;
            Ok::<_, ConnectorError>(keys)
        })?;
        Ok(TrustedKeys { keys })
    }
}


pub fn parse_trusted_keys(text: &str, label: &str) -> Result<TrustedKeys, ConnectorError> {
    TrustedKeys::try_from(parse_document::<RawKeyFile>(text, label)?)
}


/// The trusted-keys file is configuration, read with a cap.
pub fn load_trusted_keys(path: &Path) -> Result<TrustedKeys, ConnectorError> {
    let label = path.display().to_string();
    let mut file = File::open(path).map_err(|source| ConnectorError::Io { path: label.clone(), source })?;
    parse_trusted_keys(&read_text_capped(&mut file, &label, MAX_KEYS_BYTES)?, &label)
}


/// `<key-id> <seed-hex>` on one line; the bytes and the seed are wiped on drop and nothing derived from them reaches an error.
pub fn parse_signing_key(bytes: &[u8]) -> Result<(String, SigningKey), ConnectorError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ConnectorError::Invalid { field: "signing key file" })?;
    match text.split_whitespace().collect::<Vec<&str>>().as_slice() {
        [key_id, seed_hex] if valid_name(key_id) => {
            let seed = Zeroizing::new(
                HEXLOWER
                    .decode(seed_hex.as_bytes())
                    .map_err(|_| ConnectorError::Invalid { field: "signing key file" })?,
            );
            let array = Zeroizing::new(
                <[u8; SECRET_KEY_LENGTH]>::try_from(seed.as_slice()).map_err(|_| ConnectorError::Invalid { field: "signing key file" })?,
            );
            Ok(((*key_id).to_owned(), SigningKey::from_bytes(&array)))
        }
        _ => Err(ConnectorError::Invalid { field: "signing key file" }),
    }
}


/// The key file is opened by `open_secret` (no symlink, owner and mode checked on the handle) and read with a cap.
pub fn load_signing_key(path: &Path) -> Result<(String, SigningKey), ConnectorError> {
    let label = path.display().to_string();
    let bytes = Zeroizing::new(read_capped(&mut open_secret(path)?, MAX_KEY_FILE_BYTES, &label)?);
    parse_signing_key(&bytes)
}
