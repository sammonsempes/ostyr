use crate::error::AuthError;
use crate::model::Account;
use crate::types::AccountMap;
use core_audit::log::{check_private, owner_only};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;


pub const STORE_VERSION: u32 = 1;


#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreFile {
    pub version: u32,
    pub accounts: Vec<Account>,
}


pub fn load_accounts<Input: Read>(input: Input) -> Result<AccountMap, AuthError> {
    let parsed: StoreFile = serde_json::from_reader(input)?;
    if parsed.version == STORE_VERSION {
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


/// Writes `<path>.tmp` with mode 0600, syncs it and renames it over `path`.
pub fn save_accounts_file(path: &Path, accounts: &AccountMap) -> Result<(), AuthError> {
    let temporary = path.with_extension("tmp");
    let file = owner_only(OpenOptions::new().write(true).create(true).truncate(true)).open(&temporary)?;
    check_private(&file)?;
    save_accounts(&file, accounts)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}
