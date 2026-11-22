use crate::error::AccountError;
use crate::types::{HomeFn, LookupFn};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};


/// The one result of the account lookup of a session: it feeds the spawn and the cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellAccount {
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}


/// What the account database says about a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEntry {
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}


/// What the home path is on disk, without following a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeFacts {
    pub is_directory: bool,
    pub owner: u32,
}


pub const PASSWD_PATH: &str = "/etc/passwd";


const PASSWD_NAME_FIELD: usize = 0;


const PASSWD_UID_FIELD: usize = 2;


const PASSWD_GID_FIELD: usize = 3;


const PASSWD_HOME_FIELD: usize = 5;


pub fn invalid_passwd() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "the account line is malformed")
}


/// The entry of a passwd line that names the account; a malformed line of that account is an error, other lines are not read further.
pub fn parse_passwd_line(line: &str, name: &str) -> Option<io::Result<AccountEntry>> {
    let fields: Vec<&str> = line.split(':').collect();
    (fields.get(PASSWD_NAME_FIELD) == Some(&name)).then(|| {
        let id = |index: usize| fields.get(index).and_then(|text| text.parse::<u32>().ok());
        match (id(PASSWD_UID_FIELD), id(PASSWD_GID_FIELD), fields.get(PASSWD_HOME_FIELD)) {
            (Some(uid), Some(gid), Some(home)) => Ok(AccountEntry {
                uid,
                gid,
                home: PathBuf::from(home),
            }),
            _ => Err(invalid_passwd()),
        }
    })
}


/// The lookup by name in a passwd file.
pub fn lookup_in(passwd: &Path, name: &str) -> io::Result<Option<AccountEntry>> {
    std::fs::read_to_string(passwd)?
        .lines()
        .find_map(|line| parse_passwd_line(line, name))
        .transpose()
}


/// The account database lookup by name: the local `/etc/passwd`, where the deployment creates the account.
pub fn lookup_account(name: &str) -> io::Result<Option<AccountEntry>> {
    lookup_in(Path::new(PASSWD_PATH), name)
}


pub fn stat_home(path: &Path) -> io::Result<HomeFacts> {
    let metadata = std::fs::symlink_metadata(path)?;
    Ok(HomeFacts {
        is_directory: metadata.file_type().is_dir(),
        owner: metadata.uid(),
    })
}


pub fn judge_ids(name: &str, entry: &AccountEntry) -> Result<(), AccountError> {
    if entry.uid == 0 || entry.gid == 0 {
        Err(AccountError::Privileged { name: name.to_owned() })
    } else {
        Ok(())
    }
}


pub fn judge_home(name: &str, entry: &AccountEntry, facts: HomeFacts) -> Result<(), AccountError> {
    if facts.is_directory && facts.owner == entry.uid {
        Ok(())
    } else {
        Err(AccountError::HomeInvalid { name: name.to_owned() })
    }
}


/// Resolves the shell account once: absent, uid 0, gid 0 and a home that is not a directory owned by the account are each refused by name.
pub fn resolve_account(name: &str, lookup: LookupFn, home: HomeFn) -> Result<ShellAccount, AccountError> {
    let entry = lookup(name)
        .map_err(AccountError::Lookup)?
        .ok_or_else(|| AccountError::Missing { name: name.to_owned() })?;
    judge_ids(name, &entry)?;
    let facts = home(&entry.home).map_err(|source| AccountError::HomeUnreadable {
        name: name.to_owned(),
        source,
    })?;
    judge_home(name, &entry, facts)?;
    Ok(ShellAccount {
        uid: entry.uid,
        gid: entry.gid,
        home: entry.home,
    })
}
