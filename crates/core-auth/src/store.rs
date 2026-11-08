use crate::error::AuthError;
use crate::model::{Account, StoredCredential};
use crate::oidc::EXTERNAL_PASSWORD_HASH;
use crate::random::random_array;
use crate::service::OIDC_PREFIX;
use crate::types::{AccountMap, CredentialMap, RandomFn};
use core_audit::log::{check_private, owner_only};
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};


pub const STORE_VERSION: u32 = 2;


pub const FIRST_STORE_VERSION: u32 = 1;


pub const TEMP_SUFFIX_BYTES: usize = 8;


pub const LOCK_SUFFIX: &str = ".lock";


#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreFile {
    pub version: u32,
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub credentials: Vec<StoredCredential>,
}


pub fn check_reserved(account: &Account) -> Result<(), AuthError> {
    if account.username.starts_with(OIDC_PREFIX) && account.password_hash != EXTERNAL_PASSWORD_HASH {
        Err(AuthError::ReservedAccount(account.username.clone()))
    } else {
        Ok(())
    }
}


pub fn check_credentials(accounts: &AccountMap, credentials: &[StoredCredential]) -> Result<(), AuthError> {
    credentials.iter().try_for_each(|credential| {
        accounts.get(&credential.username).map_or_else(
            || Err(AuthError::OrphanCredential(credential.username.clone())),
            |account| {
                if account.password_hash == EXTERNAL_PASSWORD_HASH {
                    Err(AuthError::ExternalCredentials(credential.username.clone()))
                } else {
                    Ok(())
                }
            },
        )
    })
}


pub fn load_store<Input: Read>(input: Input) -> Result<(AccountMap, CredentialMap), AuthError> {
    let parsed: StoreFile = serde_json::from_reader(input)?;
    let migrated = parsed.version == FIRST_STORE_VERSION && parsed.credentials.is_empty();
    if parsed.version == STORE_VERSION || migrated {
        parsed.accounts.iter().try_for_each(check_reserved)?;
        let accounts: AccountMap = parsed.accounts.into_iter().map(|account| (account.username.clone(), account)).collect();
        check_credentials(&accounts, &parsed.credentials)?;
        let credentials = parsed.credentials.into_iter().fold(CredentialMap::new(), |mut grouped, credential| {
            grouped.entry(credential.username.clone()).or_default().push(credential);
            grouped
        });
        Ok((accounts, credentials))
    } else {
        Err(AuthError::UnsupportedVersion { found: parsed.version })
    }
}


pub fn load_accounts<Input: Read>(input: Input) -> Result<AccountMap, AuthError> {
    load_store(input).map(|(accounts, _)| accounts)
}


pub fn save_store<Output: Write>(mut output: Output, accounts: &AccountMap, credentials: &CredentialMap) -> Result<(), AuthError> {
    let document = StoreFile {
        version: STORE_VERSION,
        accounts: accounts.values().cloned().collect(),
        credentials: credentials.values().flatten().cloned().collect(),
    };
    serde_json::to_writer_pretty(&mut output, &document)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}


pub fn save_accounts<Output: Write>(output: Output, accounts: &AccountMap) -> Result<(), AuthError> {
    save_store(output, accounts, &CredentialMap::new())
}


/// Opens `path` for reading without blocking on a FIFO or device, and refuses anything but a regular file, judged on the opened handle.
pub fn open_regular(path: &Path) -> io::Result<File> {
    let file = non_blocking(OpenOptions::new().read(true)).open(path)?;
    if file.metadata()?.is_file() {
        Ok(file)
    } else {
        Err(io::Error::new(ErrorKind::InvalidInput, "not a regular file"))
    }
}


#[cfg(unix)]
pub fn non_blocking(options: &mut OpenOptions) -> &mut OpenOptions {
    options.custom_flags(libc::O_NONBLOCK)
}


#[cfg(not(unix))]
pub fn non_blocking(options: &mut OpenOptions) -> &mut OpenOptions {
    options
}


/// A missing file is an empty store; an existing file must grant nothing to group or other.
pub fn load_store_file(path: &Path) -> Result<(AccountMap, CredentialMap), AuthError> {
    match open_regular(path) {
        Ok(file) => {
            check_private(&file)?;
            load_store(file)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok((AccountMap::new(), CredentialMap::new())),
        Err(error) => Err(AuthError::Io(error)),
    }
}


pub fn load_accounts_file(path: &Path) -> Result<AccountMap, AuthError> {
    load_store_file(path).map(|(accounts, _)| accounts)
}


/// Writes a unique `.<name>.<random>.tmp` beside `path` (create_new, mode 0600), syncs it and renames it over `path`.
pub fn save_store_file(path: &Path, accounts: &AccountMap, credentials: &CredentialMap, random: RandomFn) -> Result<(), AuthError> {
    save_store_file_with(path, accounts, credentials, random, sync_directory)
}


/// The directory a relative `path` lives in: `.` when it has no parent component.
pub fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}


#[cfg(unix)]
pub fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}


#[cfg(not(unix))]
pub fn sync_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}


/// Like `save_store_file`, with the parent directory sync injected so its failure can be tested.
pub fn save_store_file_with(
    path: &Path,
    accounts: &AccountMap,
    credentials: &CredentialMap,
    random: RandomFn,
    sync_parent: fn(&Path) -> io::Result<()>,
) -> Result<(), AuthError> {
    let name = path
        .file_name()
        .ok_or_else(|| AuthError::Usage("store path has no file name".to_owned()))?;
    let suffix = HEXLOWER.encode(&random_array::<TEMP_SUFFIX_BYTES>(random)?);
    let temporary = path.with_file_name(format!(".{}.{suffix}.tmp", name.to_string_lossy()));
    let file = owner_only(OpenOptions::new().write(true).create_new(true)).open(&temporary)?;
    save_store(&file, accounts, credentials)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    sync_parent(parent_directory(path))?;
    Ok(())
}


/// The value a store mutation produced and the outcome of writing the store afterwards.
#[derive(Debug)]
pub struct Updated<Value> {
    pub value: Value,
    pub saved: Result<(), AuthError>,
}


pub fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(LOCK_SUFFIX);
    PathBuf::from(name)
}


/// Holds an exclusive advisory lock on `<store>.lock` until the returned file is dropped.
pub fn lock_store(path: &Path) -> Result<File, AuthError> {
    let file = owner_only(OpenOptions::new().write(true).create(true).truncate(false)).open(lock_path(path))?;
    file.lock()?;
    Ok(file)
}


/// Reads the store while holding the store lock, so a concurrent writer is never seen half done.
pub fn read_store_locked(path: &Path) -> Result<(AccountMap, CredentialMap), AuthError> {
    let _lock = lock_store(path)?;
    load_store_file(path)
}


/// The only way to change the store: lock, re-read, apply `mutate`, write atomically, unlock; a failed write is reported in `saved`.
pub fn update_store_file<Value>(
    path: &Path,
    random: RandomFn,
    mutate: impl FnOnce(&mut AccountMap, &mut CredentialMap) -> Result<Value, AuthError>,
) -> Result<Updated<Value>, AuthError> {
    let _lock = lock_store(path)?;
    let (mut accounts, mut credentials) = load_store_file(path)?;
    let value = mutate(&mut accounts, &mut credentials)?;
    let saved = save_store_file(path, &accounts, &credentials, random);
    Ok(Updated { value, saved })
}
