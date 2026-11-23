use crate::error::AccountError;
use crate::types::{DatabasesFn, HomeFn};
use std::io::{self, Read};
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


/// A group of the group file that holds a gid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub has_members: bool,
}


/// Everything the databases say about the primary gid of the account: the groups that hold it and the other users that have it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimaryGroup {
    pub entries: Vec<GroupEntry>,
    pub other_users: usize,
}


/// The text of the two local databases, each read once per resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Databases {
    pub passwd: String,
    pub group: String,
}


pub const PASSWD_PATH: &str = "/etc/passwd";


pub const GROUP_PATH: &str = "/etc/group";


pub const MAX_DATABASE_BYTES: u64 = 4_194_304;


const GROUP_NAME_FIELD: usize = 0;


const GROUP_MEMBERS_FIELD: usize = 3;


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


/// The lookup by name in the text of a passwd file.
pub fn lookup_in(passwd: &str, name: &str) -> io::Result<Option<AccountEntry>> {
    passwd.lines().find_map(|line| parse_passwd_line(line, name)).transpose()
}


/// Reads a file through a byte cap; one byte more is a named refusal.
pub fn read_database(path: &Path) -> io::Result<String> {
    let mut limited = std::fs::File::open(path)?.take(MAX_DATABASE_BYTES + 1);
    let mut text = String::new();
    limited.read_to_string(&mut text)?;
    if limited.limit() == 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the account database is larger than its limit",
        ))
    } else {
        Ok(text)
    }
}


/// Reads the two files once each.
pub fn read_databases_at(passwd: &Path, group: &Path) -> io::Result<Databases> {
    Ok(Databases {
        passwd: read_database(passwd)?,
        group: read_database(group)?,
    })
}


/// The local `/etc/passwd` and `/etc/group`, where the deployment creates the account.
pub fn read_databases() -> io::Result<Databases> {
    read_databases_at(Path::new(PASSWD_PATH), Path::new(GROUP_PATH))
}


pub fn invalid_group() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "a group line is malformed")
}


/// The group named by a group line when the account is in its member list; a malformed line is an error (fail closed), a blank one is skipped.
pub fn group_of_line(line: &str, name: &str) -> Option<io::Result<String>> {
    let fields: Vec<&str> = line.split(':').collect();
    match (line.trim().is_empty(), fields.get(GROUP_NAME_FIELD), fields.get(GROUP_MEMBERS_FIELD)) {
        (true, _, _) => None,
        (false, Some(group), Some(members)) => members.split(',').any(|member| member == name).then(|| Ok((*group).to_owned())),
        (false, _, _) => Some(Err(invalid_group())),
    }
}


/// Every group of the group file text whose member list names the account.
pub fn groups_in(group_file: &str, name: &str) -> io::Result<Vec<String>> {
    group_file.lines().filter_map(|line| group_of_line(line, name)).collect()
}


pub fn group_fields(fields: &[&str], gid: u32) -> io::Result<Option<GroupEntry>> {
    match fields {
        [name, _, found, members, ..] => found.parse::<u32>().map_err(|_| invalid_group()).map(|number| {
            (number == gid).then(|| GroupEntry {
                name: (*name).to_owned(),
                has_members: !members.trim().is_empty(),
            })
        }),
        _ => Err(invalid_group()),
    }
}


/// The group of a group line when it holds the gid; a malformed line is an error (fail closed), a blank one is skipped.
pub fn group_holding(line: &str, gid: u32) -> Option<io::Result<GroupEntry>> {
    let fields: Vec<&str> = line.split(':').collect();
    (!line.trim().is_empty()).then(|| group_fields(&fields, gid)).and_then(Result::transpose)
}


/// True when a passwd line of another account than `name` has the gid as its primary group; a malformed line is an error.
pub fn user_sharing(line: &str, name: &str, gid: u32) -> io::Result<bool> {
    let fields: Vec<&str> = line.split(':').collect();
    match (line.trim().is_empty(), fields.as_slice()) {
        (true, _) => Ok(false),
        (false, [other, _, _, primary, ..]) => primary
            .parse::<u32>()
            .map_err(|_| invalid_passwd())
            .map(|number| *other != name && number == gid),
        (false, _) => Err(invalid_passwd()),
    }
}


/// The groups that hold the gid and the count of other accounts that have it as their primary group.
pub fn primary_in(group_file: &str, passwd: &str, name: &str, gid: u32) -> io::Result<PrimaryGroup> {
    let entries = group_file
        .lines()
        .filter_map(|line| group_holding(line, gid))
        .collect::<io::Result<Vec<GroupEntry>>>()?;
    let other_users = passwd
        .lines()
        .map(|line| user_sharing(line, name, gid))
        .try_fold(usize::MIN, |count, shared| shared.map(|is_shared| count + usize::from(is_shared)))?;
    Ok(PrimaryGroup { entries, other_users })
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


pub fn judge_groups(name: &str, groups: &[String]) -> Result<(), AccountError> {
    if groups.is_empty() {
        Ok(())
    } else {
        Err(AccountError::SupplementaryGroups { name: name.to_owned() })
    }
}


/// The primary group must be the account's own: one group of its name, no member, no other account that has it.
pub fn judge_primary(name: &str, group: &PrimaryGroup) -> Result<(), AccountError> {
    match group.entries.as_slice() {
        [only] if only.name == name && !only.has_members && group.other_users == 0 => Ok(()),
        _ => Err(AccountError::SharedPrimaryGroup { name: name.to_owned() }),
    }
}


/// True when a passwd line holds the uid; a malformed line is an error (fail closed), a blank one is skipped.
pub fn holds_uid(line: &str, uid: u32) -> io::Result<bool> {
    let fields: Vec<&str> = line.split(':').collect();
    match (line.trim().is_empty(), fields.get(PASSWD_UID_FIELD)) {
        (true, _) => Ok(false),
        (false, Some(text)) => text.parse::<u32>().map(|number| number == uid).map_err(|_| invalid_passwd()),
        (false, None) => Err(invalid_passwd()),
    }
}


/// How many passwd lines hold the uid: `setpriv` resolves the first name of a uid and the sweep kills every process of it, so exactly one line may.
pub fn uid_holders(passwd: &str, uid: u32) -> io::Result<usize> {
    passwd
        .lines()
        .map(|line| holds_uid(line, uid))
        .try_fold(0, |count, held| held.map(|is_held| count + usize::from(is_held)))
}


pub fn judge_uid(name: &str, holders: usize) -> Result<(), AccountError> {
    if holders == 1 {
        Ok(())
    } else {
        Err(AccountError::SharedUid { name: name.to_owned() })
    }
}


pub fn judge_home(name: &str, entry: &AccountEntry, facts: HomeFacts) -> Result<(), AccountError> {
    if facts.is_directory && facts.owner == entry.uid {
        Ok(())
    } else {
        Err(AccountError::HomeInvalid { name: name.to_owned() })
    }
}


/// Resolves the shell account from the text of the databases: absent, uid 0, gid 0 and membership of any group, a primary group that is not its own dedicated one, and a home that is not a directory owned by the account are each refused by name.
pub fn resolve_in(name: &str, databases: &Databases, home: HomeFn) -> Result<ShellAccount, AccountError> {
    let entry = lookup_in(&databases.passwd, name)
        .map_err(AccountError::Lookup)?
        .ok_or_else(|| AccountError::Missing { name: name.to_owned() })?;
    judge_ids(name, &entry)?;
    judge_groups(name, &groups_in(&databases.group, name).map_err(AccountError::GroupsUnreadable)?)?;
    judge_primary(
        name,
        &primary_in(&databases.group, &databases.passwd, name, entry.gid).map_err(AccountError::PrimaryGroupUnreadable)?,
    )?;
    judge_uid(name, uid_holders(&databases.passwd, entry.uid).map_err(AccountError::Lookup)?)?;
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


/// Reads the databases once, then resolves the shell account from that one read.
pub fn resolve_account(name: &str, read: DatabasesFn, home: HomeFn) -> Result<ShellAccount, AccountError> {
    let databases = read().map_err(AccountError::Lookup)?;
    resolve_in(name, &databases, home)
}
