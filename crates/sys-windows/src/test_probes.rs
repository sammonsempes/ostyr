#![cfg(windows)]
//! Probes for the tests of `session`; the agent never calls them.
use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows::Win32::Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE};
use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};


/// Whether a process with this id exists and has not ended (`OpenProcess` plus a zero wait); a process that cannot be opened counts as gone.
pub fn process_is_running(process_id: u32) -> bool {
    // SAFETY: opening by id with SYNCHRONIZE only; a failure is a process that is gone or not ours.
    let opened = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, process_id) };
    opened
        .map(|handle| {
            // SAFETY: the handle was just opened and nothing else owns it.
            let owned = unsafe { OwnedHandle::from_raw_handle(handle.0) };
            // SAFETY: the handle is open for the whole call.
            let waited = unsafe { WaitForSingleObject(HANDLE(owned.as_raw_handle()), 0) };
            waited == WAIT_TIMEOUT
        })
        .unwrap_or(false)
}


/// Whether this process holds an inheritable pipe handle with this numeric value (a probe only: nothing is read, written or kept).
pub fn holds_inheritable_pipe(handle_value: usize) -> bool {
    let handle = HANDLE(std::ptr::with_exposed_provenance_mut::<c_void>(handle_value));
    let mut flags = 0;
    // SAFETY: the call only reads the flags of a handle value of this process and writes the out pointer; an invalid value is an error.
    let queried = unsafe { GetHandleInformation(handle, &mut flags) };
    // SAFETY: the call only reads the type of a handle value of this process; an invalid value gives the unknown type.
    let kind = unsafe { GetFileType(handle) };
    queried.is_ok() && flags & HANDLE_FLAG_INHERIT.0 != 0 && kind == FILE_TYPE_PIPE
}
