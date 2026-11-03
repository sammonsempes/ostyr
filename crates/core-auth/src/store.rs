use crate::error::AuthError;
use crate::model::Account;
use crate::oidc::EXTERNAL_PASSWORD_HASH;
use crate::random::random_array;
use crate::service::OIDC_PREFIX;
use crate::types::{AccountMap, RandomFn};
use core_audit::log::{check_private, owner_only};
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;


pub const STORE_VERSION: u32 = 1;


pub const TEMP_SUFFIX_BYTES: usize = 8;


#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreFile {
    pub version: u32,
    pub accounts: Vec<Account>,
}


pub fn check_reserved(account: &Account) -> Result<(), AuthError> {
    if account.username.starts_with(OIDC_PREFIX) && account.password_hash != EXTERNAL_PASSWORD_HASH {
        Err(AuthError::ReservedAccount(account.username.clone()))
    } else {
        Ok(())
    }
}


pub fn load_accounts<Input: Read>(input: Input) -> Result<AccountMap, AuthError> {
    let parsed: StoreFile = serde_json::from_reader(input)?;
    if parsed.version == STORE_VERSION {
        parsed.accounts.iter().try_for_each(check_reserved)?;
        Ok(parsed.accounts.into_iter().map(|account| (account.username.clone(), account)).collect())
    } else {
        Err(AuthError::UnsupportedVersion { found: parsed.version })
    }
}


pub fn save_accounts<Output: Write>(mut output: Output, accounts: &AccountMap) -> Result<(), AuthError> {
    let document = StoreFile {
        version: STORE_VERSION,
        accounts: accounts.values().cloned().collect(),
    };
    serde_json::to_writer_pretty(&mut output, &document)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}


/// A missing file is an empty store; an existing file must grant nothing to group or other.
pub fn load_accounts_file(path: &Path) -> Result<AccountMap, AuthError> {
    match File::open(path) {
        Ok(file) => {
            check_private(&file)?;
            load_accounts(file)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(AccountMap::new()),
        Err(error) => Err(AuthError::Io(error)),
    }
}


/// Writes a unique `.<name>.<random>.tmp` beside `path` (create_new, mode 0600), syncs it and renames it over `path`.
pub fn save_accounts_file(path: &Path, accounts: &AccountMap, random: RandomFn) -> Result<(), AuthError> {
    let name = path
        .file_name()
        .ok_or_else(|| AuthError::Usage("store path has no file name".to_owned()))?;
    let suffix = HEXLOWER.encode(&random_array::<TEMP_SUFFIX_BYTES>(random)?);
    let temporary = path.with_file_name(format!(".{}.{suffix}.tmp", name.to_string_lossy()));
    let file = owner_only(OpenOptions::new().write(true).create_new(true)).open(&temporary)?;
    save_accounts(&file, accounts)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}
