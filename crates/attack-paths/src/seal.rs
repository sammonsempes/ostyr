//! `ostyr-attack-paths seal-tags [--reseal] <file>`: writes the trailer that binds the tag file's content, through a temporary file renamed over the name.


use crate::error::{SealError, TagsError};
use crate::input::{untouched, Stamp};
use crate::tags::{check_tags, read_stable, sealed_text, verify_sealed};
use crate::types::MidRead;
use core_config::parse::parse_document;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;


pub const SEAL_COMMAND: &str = "seal-tags";


pub const RESEAL_FLAG: &str = "--reseal";


pub const SEALED_LINE: &str = "complete:";


pub const PERMISSION_BITS: u32 = 0o7777;


pub const GROUP_OTHER_WRITE: u32 = 0o022;


pub const ROOT_UID: u32 = 0;


/// The two words after `seal-tags`: whether a sealed file may be sealed again, and the absolute path of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealArguments {
    pub reseal: bool,
    pub file: PathBuf,
}


/// What the file held before: nothing sealed, a seal that still matches, or a seal whose body changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Previous {
    Fresh,
    Unchanged,
    Stale,
}


/// The body to seal and what the file held before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub body: String,
    pub previous: Previous,
}


/// The directory that holds the file, as `symlink_metadata` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryFacts {
    pub is_directory: bool,
    pub mode: u32,
    pub owner: u32,
}


/// `[--reseal] <absolute file>`; anything else is a usage error.
pub fn parse_seal_arguments(arguments: &[String]) -> Result<SealArguments, SealError> {
    let (reseal, file) = match arguments {
        [file] => Ok((false, file)),
        [flag, file] if flag == RESEAL_FLAG => Ok((true, file)),
        _ => Err(SealError::Usage),
    }?;
    let path = PathBuf::from(file);
    path.is_absolute().then_some(SealArguments { reseal, file: path }).ok_or(SealError::Usage)
}


#[cfg(unix)]
pub fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}


#[cfg(not(unix))]
pub fn current_uid() -> u32 {
    ROOT_UID
}


/// Production entry: the caller is the effective user of the process and nothing happens between the read and the stamp check.
pub fn seal_tags(arguments: &[String], out: &mut dyn Write) -> Result<(), SealError> {
    seal_with(arguments, out, untouched, current_uid())
}


/// Reads the file through one stable handle, checks the body parses as tags, then writes the sealed file; the caller uid is given so a test can play root.
pub fn seal_with(arguments: &[String], out: &mut dyn Write, mid_read: MidRead, caller: u32) -> Result<(), SealError> {
    let SealArguments { reseal, file } = parse_seal_arguments(arguments)?;
    let (text, stamp) = read_stable(&file, mid_read)?;
    let plan = plan_seal(&text, reseal)?;
    let checked = check_tags(parse_document(&plan.body, &file.display().to_string())?)?;
    let count = checked.critical.len();
    let message = match plan.previous {
        Previous::Unchanged => "unchanged".to_string(),
        Previous::Fresh => format!("sealed: {count} tags sealed"),
        Previous::Stale => format!("body changed since the last seal: {count} tags sealed"),
    };
    if plan.previous != Previous::Unchanged {
        write_sealed(&file, &sealed_text(&plan.body), &stamp, caller)?;
    }
    writeln!(out, "{message}")?;
    Ok(())
}


/// A carriage return and a missing final newline are refused; a last line starting with `complete:` is a seal, replaced only with `reseal`.
pub fn plan_seal(text: &str, reseal: bool) -> Result<Plan, SealError> {
    if text.contains('\r') {
        Err(SealError::Tags(TagsError::CarriageReturn))
    } else if !text.is_empty() && !text.ends_with('\n') {
        Err(SealError::NoFinalNewline)
    } else {
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        match lines.split_last() {
            Some((last, rest)) if last.starts_with(SEALED_LINE) => replan_sealed(text, rest.concat(), reseal),
            _ => Ok(Plan {
                body: text.to_string(),
                previous: Previous::Fresh,
            }),
        }
    }
}


pub fn replan_sealed(text: &str, body: String, reseal: bool) -> Result<Plan, SealError> {
    if reseal {
        let previous = if verify_sealed(text).is_ok() {
            Previous::Unchanged
        } else {
            Previous::Stale
        };
        Ok(Plan { body, previous })
    } else {
        Err(SealError::AlreadySealed)
    }
}


/// A directory that is not a directory, that group or others can write, or that belongs to neither the caller nor root.
pub fn refuse_unsafe_directory(facts: &DirectoryFacts, caller: u32) -> Result<(), SealError> {
    if facts.is_directory && facts.mode & GROUP_OTHER_WRITE == 0 && (facts.owner == caller || facts.owner == ROOT_UID) {
        Ok(())
    } else {
        Err(SealError::UnsafeDirectory)
    }
}


/// An existing file that group or others can write.
pub fn refuse_unsafe_file(mode: u32) -> Result<(), SealError> {
    if mode & GROUP_OTHER_WRITE == 0 {
        Ok(())
    } else {
        Err(SealError::UnsafeFile)
    }
}


#[cfg(unix)]
pub fn directory_facts(directory: &Path) -> Result<DirectoryFacts, SealError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(directory)?;
    Ok(DirectoryFacts {
        is_directory: metadata.file_type().is_dir(),
        mode: metadata.mode(),
        owner: metadata.uid(),
    })
}


#[cfg(not(unix))]
pub fn directory_facts(directory: &Path) -> Result<DirectoryFacts, SealError> {
    let metadata = fs::symlink_metadata(directory)?;
    Ok(DirectoryFacts {
        is_directory: metadata.file_type().is_dir(),
        mode: 0,
        owner: current_uid(),
    })
}


/// The old file's permission bits without group and other write, and its owner and group when the caller is root.
#[cfg(unix)]
pub fn apply_attributes(file: &File, stamp: &Stamp, caller: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{fchown, PermissionsExt};
    file.set_permissions(fs::Permissions::from_mode(stamp.mode & PERMISSION_BITS & !GROUP_OTHER_WRITE))?;
    if caller == ROOT_UID {
        fchown(file, Some(stamp.owner), Some(stamp.group))
    } else {
        Ok(())
    }
}


#[cfg(not(unix))]
pub fn apply_attributes(_file: &File, _stamp: &Stamp, _caller: u32) -> std::io::Result<()> {
    Ok(())
}


/// Checks the directory and the old file, writes a random-named temporary file next to it, fsyncs, renames it over the name (a symlink at the name is replaced, never followed) and fsyncs the directory.
pub fn write_sealed(path: &Path, sealed: &str, stamp: &Stamp, caller: u32) -> Result<(), SealError> {
    let directory = path.parent().unwrap_or(path);
    refuse_unsafe_directory(&directory_facts(directory)?, caller)?;
    refuse_unsafe_file(stamp.mode)?;
    let mut staging = NamedTempFile::new_in(directory)?;
    staging.write_all(sealed.as_bytes())?;
    staging.as_file().sync_all()?;
    apply_attributes(staging.as_file(), stamp, caller)?;
    staging.persist(path).map_err(|failure| failure.error)?;
    sync_directory(directory)?;
    Ok(())
}


#[cfg(unix)]
pub fn sync_directory(directory: &Path) -> std::io::Result<()> {
    File::open(directory)?.sync_all()
}


#[cfg(not(unix))]
pub fn sync_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
}
