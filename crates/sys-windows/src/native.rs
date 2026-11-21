#![cfg(windows)]
use crate::descriptor::{parse_descriptor, sid_from_token_user};
use crate::judge::{judge_spool_dir, principals_from_token_user};
use crate::types::{DirAclError, ParsedDescriptor};
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows::core::Owned;
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{GetSecurityDescriptorLength, GetTokenInformation, TokenUser};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};


const WORD_BYTES: usize = std::mem::size_of::<u64>();


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


/// Judges an opened spool directory: its descriptor against the process account; the one call `open_spool_dirs` makes on Windows.
pub fn judge_directory_handle(directory: &File, shown: &Path) -> Result<(), DirAclError> {
    let descriptor = read_descriptor(directory)?;
    let principals = principals_from_token_user(&token_user_sid()?)?;
    judge_spool_dir(shown, &descriptor, &principals)
}
