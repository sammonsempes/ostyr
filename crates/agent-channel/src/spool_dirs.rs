use crate::agent_app::AgentFile;
use crate::error::{AppError, SpoolDirReason};
use std::fs::File;
use std::io;
use std::path::Path;


const GROUP_OTHER_WRITE: u32 = 0o022;


/// The opened parent directories of every file the agent writes by path, held for the life of the process.
#[derive(Debug)]
pub struct SpoolDirs {
    pub handles: Vec<File>,
}


/// The directory that holds `path` (`.` for a bare file name); none for a path without a parent.
pub fn parent_directory(path: &Path) -> Option<&Path> {
    path.parent()
        .map(|parent| if parent.as_os_str().is_empty() { Path::new(".") } else { parent })
}


/// The reason a directory is not trusted: it must belong to the process user or root and not be writable by group or others.
pub fn spool_dir_fault(owner: u32, process_uid: u32, mode: u32) -> Option<SpoolDirReason> {
    if owner != process_uid && owner != 0 {
        Some(SpoolDirReason::WrongOwner)
    } else if mode & GROUP_OTHER_WRITE != 0 {
        Some(SpoolDirReason::Writable)
    } else {
        None
    }
}


#[cfg(unix)]
const NOT_DIRECTORY: i32 = rustix::io::Errno::NOTDIR.raw_os_error();


#[cfg(unix)]
const SYMLINK_LOOP: i32 = rustix::io::Errno::LOOP.raw_os_error();


#[cfg(not(unix))]
const NOT_DIRECTORY: i32 = 267;


#[cfg(not(unix))]
const SYMLINK_LOOP: i32 = -1;


/// Maps a failed directory open to its fixed refusal, any other error stays an I/O error.
pub fn open_fault(path: &Path, error: io::Error) -> AppError {
    let missing = error.kind() == io::ErrorKind::NotFound;
    let not_directory = matches!(error.raw_os_error(), Some(code) if code == NOT_DIRECTORY || code == SYMLINK_LOOP);
    if missing {
        AppError::SpoolDir {
            path: path.to_path_buf(),
            reason: SpoolDirReason::Missing,
        }
    } else if not_directory {
        AppError::SpoolDir {
            path: path.to_path_buf(),
            reason: SpoolDirReason::NotDirectory,
        }
    } else {
        AppError::Io(error)
    }
}


/// Opens a directory without following a link and judges the handle: returns it with its identity, or the refusal.
#[cfg(unix)]
pub fn open_and_judge(directory: &Path, shown: &Path) -> Result<(File, (u64, u64)), AppError> {
    use rustix::fs::OFlags;
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let flags = (OFlags::DIRECTORY | OFlags::NOFOLLOW).bits() as i32;
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(directory)
        .map_err(|error| open_fault(shown, error))?;
    let metadata = handle.metadata()?;
    match spool_dir_fault(metadata.uid(), crate::spool::effective_uid(), metadata.mode()) {
        None => Ok((handle, (metadata.dev(), metadata.ino()))),
        Some(reason) => Err(AppError::SpoolDir {
            path: shown.to_path_buf(),
            reason,
        }),
    }
}


/// Opens a directory on Windows (backup semantics) without judging its owner: the installer's protected ACL is the requirement there.
#[cfg(not(unix))]
pub fn open_and_judge(directory: &Path, shown: &Path) -> Result<(File, (u64, u64)), AppError> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(BACKUP_SEMANTICS)
        .open(directory)
        .map_err(|error| open_fault(shown, error))?;
    handle.metadata()?.is_dir().then_some((handle, (0, 0))).ok_or_else(|| AppError::SpoolDir {
        path: shown.to_path_buf(),
        reason: SpoolDirReason::NotDirectory,
    })
}


/// Opens and judges the parent directory of every file the agent writes by path; call it once per process before any spool producer or claim.
pub fn open_spool_dirs(file: &AgentFile) -> Result<SpoolDirs, AppError> {
    let files = [
        &file.spool_file,
        &file.sequence_file,
        &file.executed_file,
        &file.state_file,
        &file.audit_file,
    ];
    let judged = files.into_iter().try_fold(Vec::<(File, (u64, u64))>::new(), |mut kept, path| {
        let directory = parent_directory(path).ok_or_else(|| AppError::SpoolDir {
            path: path.clone(),
            reason: SpoolDirReason::NotDirectory,
        })?;
        let (handle, identity) = open_and_judge(directory, path)?;
        let known = kept.iter().any(|(_, seen)| *seen == identity);
        if !known {
            kept.push((handle, identity));
        }
        Ok::<_, AppError>(kept)
    })?;
    Ok(SpoolDirs {
        handles: judged.into_iter().map(|(handle, _)| handle).collect(),
    })
}
