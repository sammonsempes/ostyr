use crate::error::IssueError;
use crate::limits::{
    AGENT_DIRECTORY_MODE, ENVELOPE_SUFFIX, FILE_MODE, GROUP_OTHER_WRITE, MAX_QUEUE_SCAN_ENTRIES, MAX_STAGING_SCAN_ENTRIES, NAME_DIGITS, STAGING_MODE,
    STAGING_NAME, STAGING_NAME_BYTES,
};
use crate::types::UnlinkFn;
use agent_command::model::CLOCK_SKEW_SECONDS;
use agent_command::sign::os_random;
use core_config::trusted_dir::open_trusted_dir;
use data_encoding::HEXLOWER;
use rustix::fs::{fchmod, fstat, fsync, mkdirat, openat, renameat_with, statat, unlinkat, AtFlags, Dir, FileType, Mode, OFlags, RenameFlags};
use rustix::io::Errno;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use tracing::{error, warn};


const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);


const STAGED_FLAGS: OFlags = OFlags::CREATE
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::WRONLY)
    .union(OFlags::CLOEXEC);


const DOT_ENTRIES: usize = 2;


/// The handles every issue works through: the trusted root and the private staging directory under it.
#[derive(Debug)]
pub struct CommandDirs {
    pub root: OwnedFd,
    pub staging: OwnedFd,
    pub service_uid: u32,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueEntry {
    pub name: String,
    pub sequence: u64,
    pub expires_at: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}


#[derive(Debug)]
pub struct Staged {
    pub name: String,
    pub identity: FileIdentity,
}


pub fn exists_ok(result: Result<(), Errno>) -> Result<(), Errno> {
    result.or_else(|errno| if errno == Errno::EXIST { Ok(()) } else { Err(errno) })
}


/// `mkdirat` when missing, then opened without following a link under the held parent.
pub fn open_directory(parent: &OwnedFd, name: &str, mode: u32) -> Result<OwnedFd, Errno> {
    exists_ok(mkdirat(parent, name, Mode::from_raw_mode(mode)))?;
    openat(parent, name, DIRECTORY_FLAGS, Mode::empty())
}


pub fn is_regular(mode: u32) -> bool {
    FileType::from_raw_mode(mode) == FileType::RegularFile
}


/// The staging directory is judged on its handle (service owner) and forced to 0700.
pub fn open_staging(root: &OwnedFd, service_uid: u32) -> Result<OwnedFd, IssueError> {
    let staging = open_directory(root, STAGING_NAME, STAGING_MODE)?;
    if fstat(&staging)?.st_uid == service_uid {
        fchmod(&staging, Mode::from_raw_mode(STAGING_MODE))?;
        Ok(staging)
    } else {
        Err(IssueError::DirectoryRefused("the staging directory belongs to another user"))
    }
}


/// Every entry except `.` and `..`, at most `cap` of them.
pub fn list_names(directory: &OwnedFd, cap: usize) -> Result<Vec<CString>, Errno> {
    let handle = openat(directory, ".", DIRECTORY_FLAGS, Mode::empty())?;
    let found = Dir::new(handle)?
        .take(cap + DOT_ENTRIES)
        .map(|entry| entry.map(|item| item.file_name().to_owned()));
    let mut names = found.collect::<Result<Vec<CString>, Errno>>()?;
    names.retain(|name| name.to_bytes() != b"." && name.to_bytes() != b"..");
    Ok(names)
}


/// At start every regular file left in staging by a crash is removed; anything else, or a full scan, refuses the start.
pub fn clean_staging(staging: &OwnedFd) -> Result<usize, IssueError> {
    let names = list_names(staging, MAX_STAGING_SCAN_ENTRIES)?;
    if names.len() >= MAX_STAGING_SCAN_ENTRIES {
        Err(IssueError::DirectoryRefused("the staging directory holds too many entries"))
    } else {
        names.iter().try_fold(0, |removed, name| {
            if is_regular(statat(staging, name, AtFlags::SYMLINK_NOFOLLOW)?.st_mode) {
                unlinkat(staging, name, AtFlags::empty())?;
                Ok(removed + 1)
            } else {
                Err(IssueError::DirectoryRefused("the staging directory holds an entry that is not a file"))
            }
        })
    }
}


pub fn open_command_dirs(path: &Path, service_uid: u32) -> Result<CommandDirs, IssueError> {
    let root = open_trusted_dir(path, service_uid)?;
    let staging = open_staging(&root, service_uid)?;
    clean_staging(&staging)?;
    Ok(CommandDirs { root, staging, service_uid })
}


/// The agent directory `<tenant>@<agent>`: `mkdirat` 0750 when missing, opened under the root handle, judged on its handle.
pub fn open_agent_directory(dirs: &CommandDirs, tenant: &str, agent: &str) -> Result<OwnedFd, IssueError> {
    let directory = open_directory(&dirs.root, &format!("{tenant}@{agent}"), AGENT_DIRECTORY_MODE)?;
    let stat = fstat(&directory)?;
    if stat.st_uid != dirs.service_uid {
        Err(IssueError::DirectoryRefused("the agent directory belongs to another user"))
    } else if stat.st_mode & GROUP_OTHER_WRITE != 0 {
        Err(IssueError::DirectoryRefused("the agent directory is writable by group or other"))
    } else {
        Ok(directory)
    }
}


pub fn envelope_name(sequence: u64, expires_at: u64) -> String {
    format!("{sequence:020}-{expires_at:020}{ENVELOPE_SUFFIX}")
}


/// `<sequence, 20 digits>-<expires_at, 20 digits>.env`, nothing else.
pub fn parse_name(text: &str) -> Option<(u64, u64)> {
    let (sequence, rest) = text.split_once('-')?;
    let expires_at = rest.strip_suffix(ENVELOPE_SUFFIX)?;
    let digits = |part: &str| part.len() == NAME_DIGITS && part.bytes().all(|byte| byte.is_ascii_digit());
    if digits(sequence) && digits(expires_at) {
        Some((sequence.parse().ok()?, expires_at.parse().ok()?))
    } else {
        None
    }
}


/// `Err` holds the lossy name of an entry that is not a well-formed regular envelope file.
pub fn judge_entry(directory: &OwnedFd, name: &CString) -> Result<Result<QueueEntry, String>, Errno> {
    let stat = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
    let text = name.to_string_lossy().into_owned();
    let parsed = if is_regular(stat.st_mode) { parse_name(&text) } else { None };
    Ok(parsed
        .map(|(sequence, expires_at)| QueueEntry {
            name: text.clone(),
            sequence,
            expires_at,
        })
        .ok_or(text))
}


/// Every entry counts under `MAX_QUEUE_SCAN_ENTRIES`; a foreign entry or a full scan is `QueueInvalid`, logged, and nothing is deleted.
pub fn list_queue(directory: &OwnedFd, tenant: &str, agent: &str) -> Result<Vec<QueueEntry>, IssueError> {
    let names = list_names(directory, MAX_QUEUE_SCAN_ENTRIES)?;
    let judged = names.iter().map(|name| judge_entry(directory, name)).collect::<Result<Vec<_>, Errno>>()?;
    let foreign = judged.iter().find_map(|entry| entry.as_ref().err().cloned());
    if names.len() >= MAX_QUEUE_SCAN_ENTRIES {
        warn!(tenant, agent, scanned = names.len(), "agent queue scan cap reached");
        Err(IssueError::QueueInvalid)
    } else if let Some(entry) = foreign {
        warn!(tenant, agent, entry = ?entry, "agent queue holds a foreign entry");
        Err(IssueError::QueueInvalid)
    } else {
        Ok(judged.into_iter().flatten().collect())
    }
}


/// Removes the well-formed envelope files past `expires_at` plus the clock skew and returns the rest.
pub fn prune(directory: &OwnedFd, entries: Vec<QueueEntry>, now: u64) -> Result<Vec<QueueEntry>, IssueError> {
    entries.into_iter().try_fold(Vec::new(), |mut kept, entry| {
        if entry.expires_at.saturating_add(CLOCK_SKEW_SECONDS) < now {
            unlinkat(directory, entry.name.as_str(), AtFlags::empty())?;
        } else {
            kept.push(entry);
        }
        Ok(kept)
    })
}


pub fn write_and_sync(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()
}


/// A removal in staging that fails is logged and named.
pub fn discard(dirs: &CommandDirs, name: &str) {
    if let Err(errno) = unlinkat(&dirs.staging, name, AtFlags::empty()) {
        error!(%errno, "cannot remove a staged envelope");
    }
}


/// Writes the bytes to a random name in staging (`O_EXCL`, 0640) through `fill`; a failure removes the staged file.
pub fn stage_with(dirs: &CommandDirs, bytes: &[u8], fill: fn(&mut File, &[u8]) -> io::Result<()>) -> Result<Staged, IssueError> {
    let mut random = [0; STAGING_NAME_BYTES];
    os_random(&mut random)?;
    let name = HEXLOWER.encode(&random);
    let mut file = File::from(openat(&dirs.staging, name.as_str(), STAGED_FLAGS, Mode::from_raw_mode(FILE_MODE))?);
    let filled = fchmod(&file, Mode::from_raw_mode(FILE_MODE))
        .map_err(io::Error::from)
        .and_then(|()| fill(&mut file, bytes))
        .and_then(|()| file.metadata());
    match filled {
        Ok(metadata) => Ok(Staged {
            name,
            identity: FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        }),
        Err(source) => {
            discard(dirs, &name);
            Err(IssueError::Io(source))
        }
    }
}


pub fn stage(dirs: &CommandDirs, bytes: &[u8]) -> Result<Staged, IssueError> {
    stage_with(dirs, bytes, write_and_sync)
}


/// `renameat2(RENAME_NOREPLACE)` from staging into the agent directory: an existing name is never overwritten.
pub fn rename_staged(dirs: &CommandDirs, directory: &OwnedFd, staged: &Staged, name: &str) -> Result<(), Errno> {
    renameat_with(&dirs.staging, staged.name.as_str(), directory, name, RenameFlags::NOREPLACE)
}


pub fn sync_directory(directory: &OwnedFd) -> Result<(), Errno> {
    fsync(directory)
}


pub fn unlink_name(directory: &OwnedFd, name: &str) -> io::Result<()> {
    unlinkat(directory, name, AtFlags::empty()).map_err(io::Error::from)
}


/// Removes the published file only when the name still holds the inode that was staged; a failed removal is a named error.
pub fn retract(directory: &OwnedFd, name: &str, identity: FileIdentity, unlink: UnlinkFn) {
    match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if stat.st_dev == identity.device && stat.st_ino == identity.inode => {
            if let Err(source) = unlink(directory, name) {
                error!(%source, name, "cannot retract a published envelope");
            }
        }
        Ok(_) => warn!(name, "published envelope replaced by another file, left alone"),
        Err(errno) => warn!(%errno, name, "published envelope already gone"),
    }
}
