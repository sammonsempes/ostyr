#![cfg(windows)]
use crate::descriptor::{parse_descriptor, sid_from_token_user};
use crate::judge::{judge_spool_dir, principals_from_token_user};
use crate::types::{DirAclError, FileIdentity, ParsedDescriptor, Principals};
use crate::walk::{judge_ancestor, split_volume_path, walk_prefixes};
use std::fs::{File, OpenOptions};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use windows::core::Owned;
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{GetSecurityDescriptorLength, GetTokenInformation, TokenUser};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY};
use windows::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};


const WORD_BYTES: usize = std::mem::size_of::<u64>();


const WALK_FLAGS: u32 = 0x0200_0000 | 0x0020_0000;


const SHARE_READ_WRITE: u32 = 0x1 | 0x2;


const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;


const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;


const SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;


const READ_CONTROL: u32 = 0x0002_0000;


fn windows_error(operation: &'static str, error: &windows::core::Error) -> DirAclError {
    DirAclError::Windows {
        operation,
        code: error.code().0.cast_unsigned(),
    }
}


/// Reads the owner and the DACL of an opened file or directory from its handle (`GetSecurityInfo`), never from its path.
pub fn read_descriptor(file: &File) -> Result<ParsedDescriptor, DirAclError> {
    let handle = HANDLE(file.as_raw_handle());
    let mut security = PSECURITY_DESCRIPTOR::default();
    let information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    // SAFETY: the handle is open for the whole call (borrowed from `file`) and `security` is a valid out pointer.
    let status = unsafe { GetSecurityInfo(handle, SE_FILE_OBJECT, information, None, None, None, None, Some(&mut security)) };
    // SAFETY: on success `security` was allocated by the call for the caller to free with `LocalFree`; on failure it is null, which the guard ignores.
    let _guard = unsafe { Owned::new(HLOCAL(security.0)) };
    (status == ERROR_SUCCESS).then_some(()).ok_or(DirAclError::Windows {
        operation: "GetSecurityInfo",
        code: status.0,
    })?;
    // SAFETY: `security` points at a valid self-relative descriptor that `guard` keeps allocated.
    let length = unsafe { GetSecurityDescriptorLength(security) };
    let size = usize::try_from(length).map_err(|_| DirAclError::Malformed("descriptor length"))?;
    // SAFETY: the descriptor is `size` bytes long as just reported and `guard` outlives the slice, which ends before this function returns.
    let bytes = unsafe { std::slice::from_raw_parts(security.0.cast::<u8>(), size) };
    parse_descriptor(bytes)
}


/// The SID string of the account the process runs as (`TokenUser`).
pub fn token_user_sid() -> Result<String, DirAclError> {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo handle of the current process needs no release.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: `token` is a valid out pointer; a successful call hands its ownership to the guard below.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.map_err(|error| windows_error("OpenProcessToken", &error))?;
    // SAFETY: the token handle was just opened for this process and nothing else owns it.
    let owned = unsafe { Owned::new(token) };
    let mut needed = 0;
    // SAFETY: a null buffer of length zero only asks for the required size, written to `needed`.
    let probe = unsafe { GetTokenInformation(*owned, TokenUser, None, 0, &mut needed) };
    let size = usize::try_from(needed).map_err(|_| DirAclError::Malformed("token length"))?;
    let words = size.div_ceil(WORD_BYTES);
    (size != 0).then_some(()).ok_or_else(|| match probe {
        Err(error) => windows_error("GetTokenInformation", &error),
        Ok(()) => DirAclError::Malformed("empty token user"),
    })?;
    let mut buffer = vec![u64::default(); words];
    let capacity = u32::try_from(words * WORD_BYTES).map_err(|_| DirAclError::Malformed("token length"))?;
    // SAFETY: the buffer holds `capacity` writable bytes, aligned for a pointer, and `needed` is a valid out pointer.
    unsafe { GetTokenInformation(*owned, TokenUser, Some(buffer.as_mut_ptr().cast()), capacity, &mut needed) }
        .map_err(|error| windows_error("GetTokenInformation", &error))?;
    let base = buffer.as_ptr().addr();
    // SAFETY: the buffer is initialised and `words * WORD_BYTES` bytes long; the slice ends before the buffer is dropped.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), words * WORD_BYTES) };
    sid_from_token_user(bytes, base)
}


/// The volume serial number and file index of an opened file (`GetFileInformationByHandle`).
pub fn file_identity(file: &File) -> Result<FileIdentity, DirAclError> {
    let handle = HANDLE(file.as_raw_handle());
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open for the whole call (borrowed from `file`) and `information` is a valid out pointer.
    unsafe { GetFileInformationByHandle(handle, &mut information) }.map_err(|error| windows_error("GetFileInformationByHandle", &error))?;
    Ok(FileIdentity {
        volume: information.dwVolumeSerialNumber,
        index: (u64::from(information.nFileIndexHigh) << u32::BITS) | u64::from(information.nFileIndexLow),
    })
}


fn open_for_walk(path: &Path) -> Result<File, DirAclError> {
    let handle = OpenOptions::new()
        .read(true)
        .share_mode(SHARE_READ_WRITE)
        .custom_flags(WALK_FLAGS)
        .open(path)
        .map_err(|error| DirAclError::Open {
            path: path.to_path_buf(),
            kind: error.kind(),
        })?;
    let attributes = handle
        .metadata()
        .map_err(|error| DirAclError::Open {
            path: path.to_path_buf(),
            kind: error.kind(),
        })?
        .file_attributes();
    (attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0)
        .then_some(handle)
        .ok_or_else(|| DirAclError::ReparsePoint { path: path.to_path_buf() })
}


/// Walks from the volume root to the directory holding `file_path` without following a reparse point; ancestors, leaf and identity are judged.
pub fn judge_spool_path(directory: &File, file_path: &Path) -> Result<(), DirAclError> {
    let parent = file_path.parent().unwrap_or(file_path);
    let text = parent.to_str().ok_or_else(|| DirAclError::BadPath {
        path: parent.display().to_string(),
        reason: "not valid Unicode",
    })?;
    let volume_path = split_volume_path(text)?;
    let opened = walk_prefixes(&volume_path)
        .into_iter()
        .map(|prefix| open_for_walk(Path::new(&prefix)).map(|handle| (PathBuf::from(prefix), handle)))
        .collect::<Result<Vec<_>, _>>()?;
    let ((leaf_path, leaf), ancestors) = opened.split_last().ok_or(DirAclError::Malformed("empty walk"))?;
    (file_identity(leaf)? == file_identity(directory)?)
        .then_some(())
        .ok_or_else(|| DirAclError::IdentityMismatch { path: leaf_path.clone() })?;
    let principals = principals_from_token_user(&token_user_sid()?)?;
    ancestors
        .iter()
        .try_for_each(|(path, handle)| judge_ancestor(path, &read_descriptor(handle)?, &principals))?;
    judge_spool_dir(file_path, &read_descriptor(leaf)?, &principals)
}


/// Judges one opened directory against the process account by the spool rule alone, with no ancestor walk; `open_spool_dirs` calls `judge_spool_path`.
pub fn judge_directory_handle(directory: &File, shown: &Path) -> Result<(), DirAclError> {
    let descriptor = read_descriptor(directory)?;
    let principals = principals_from_token_user(&token_user_sid()?)?;
    judge_spool_dir(shown, &descriptor, &principals)
}


fn open_entry(path: &Path) -> Result<Option<File>, DirAclError> {
    let opened = OpenOptions::new()
        .access_mode(READ_CONTROL)
        .share_mode(SHARE_ALL)
        .custom_flags(WALK_FLAGS)
        .open(path);
    match opened {
        Ok(handle) => Ok(Some(handle)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(DirAclError::Open {
            path: path.to_path_buf(),
            kind: error.kind(),
        }),
    }
}


fn judge_entry(path: &Path, handle: &File, principals: &Principals) -> Result<(), DirAclError> {
    let attributes = handle
        .metadata()
        .map_err(|error| DirAclError::Open {
            path: path.to_path_buf(),
            kind: error.kind(),
        })?
        .file_attributes();
    (attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0)
        .then_some(())
        .ok_or_else(|| DirAclError::ReparsePoint { path: path.to_path_buf() })?;
    (attributes & FILE_ATTRIBUTE_DIRECTORY == 0)
        .then_some(())
        .ok_or_else(|| DirAclError::NotRegularFile { path: path.to_path_buf() })?;
    judge_spool_dir(path, &read_descriptor(handle)?, principals)
}


/// Judges each fixed-name entry that exists (a missing one is fine): not a reparse point or directory, trusted owner, DACL within the spool rule.
pub fn judge_spool_entries(paths: &[PathBuf]) -> Result<(), DirAclError> {
    let principals = principals_from_token_user(&token_user_sid()?)?;
    paths
        .iter()
        .try_for_each(|path| open_entry(path)?.as_ref().map_or(Ok(()), |handle| judge_entry(path, handle, &principals)))
}
