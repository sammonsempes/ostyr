#![cfg(windows)]
use crate::console::{
    begin_close, check_input_len, check_session_label, close_on_drop, command_line, console_size, coordinates, directory_text, session_environment,
    wide_null, DIRECTORY_UNITS, OUTPUT_CHUNK_BYTES, PIPE_BUFFER_BYTES, SHELL_PROGRAM_NAME,
};
use crate::types::{AssignHook, CloseState, ConsoleError, ConsoleSize};
use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use windows::core::BOOL;
use windows::core::{Owned, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Console::{CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject, JOBOBJECTINFOCLASS, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
    JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW};
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
};
use windows::Win32::System::IO::CancelIoEx;


/// The one deadline of a close: job terminated, console released, output drained and the shell ended.
pub const CLOSE_WAIT_MILLIS: u32 = 10_000;


/// The most processes the job lets the shell tree hold at once.
pub const ACTIVE_PROCESS_LIMIT: u32 = 64;


/// The `bInheritHandles` argument of the spawn: never, so the shell holds none of the agent's handles.
pub const INHERIT_HANDLES: bool = false;


const CLOSE_STEPS: usize = 2;


const CANCEL_ATTEMPTS: u32 = 50;


const CANCEL_POLL_MILLIS: u64 = 20;


const KILLED_EXIT_CODE: u32 = 1;


const STARTUP_INFO_BYTES: u32 = std::mem::size_of::<STARTUPINFOEXW>() as u32;


const RESUME_FAILED: u32 = u32::MAX;


const NO_DESKTOP: &str = "";


const UI_RESTRICTIONS: u32 = JOB_OBJECT_UILIMIT_HANDLES.0
    | JOB_OBJECT_UILIMIT_READCLIPBOARD.0
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD.0
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS.0
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS.0
    | JOB_OBJECT_UILIMIT_GLOBALATOMS.0
    | JOB_OBJECT_UILIMIT_DESKTOP.0
    | JOB_OBJECT_UILIMIT_EXITWINDOWS.0;


#[doc = "One cmd.exe in a pseudo-console inside a kill-on-close job; field order is the drop order. No handle, console, job or pipe end crosses the API and the wrapper is not `Clone`.\n\n```no_run\nuse sys_windows::session::{process_id, read_output, shell_in_job, spawn_session, Session};\nuse sys_windows::types::ConsoleError;\nlet opened: Result<Session, ConsoleError> = spawn_session(1, 1, \"a\");\nif let Ok(session) = opened {\n    let _id: u32 = process_id(&session);\n    let _bytes: Result<Vec<u8>, ConsoleError> = read_output(&session);\n    let _member: Result<bool, ConsoleError> = shell_in_job(&session);\n}\n```\n\n```compile_fail,E0616\nfn job(session: &sys_windows::session::Session) {\n    let _ = &session.job;\n}\n```\n\n```compile_fail,E0616\nfn process(session: &sys_windows::session::Session) {\n    let _ = &session.process;\n}\n```\n\n```compile_fail,E0616\nfn console(session: &sys_windows::session::Session) {\n    let _ = &session.console;\n}\n```\n\n```compile_fail,E0616\nfn input(session: &sys_windows::session::Session) {\n    let _ = &session.input;\n}\n```\n\n```compile_fail,E0616\nfn output(session: &sys_windows::session::Session) {\n    let _ = &session.output;\n}\n```\n\n```compile_fail,E0599\nfn copy(session: &sys_windows::session::Session) -> sys_windows::session::Session {\n    session.clone()\n}\n```\n"]
pub struct Session {
    state: Mutex<CloseState>,
    closing: AtomicBool,
    readers: Arc<AtomicUsize>,
    console: Mutex<Option<Owned<HPCON>>>,
    input: File,
    output: Arc<File>,
    process: OwnedHandle,
    job: OwnedHandle,
    process_id: u32,
}


struct ConsoleEnds {
    console: Owned<HPCON>,
    input: File,
    output: Arc<File>,
}


struct AttributeList {
    buffer: Vec<usize>,
}


struct Launch {
    program: Vec<u16>,
    command: Vec<u16>,
    directory: Vec<u16>,
    desktop: Vec<u16>,
    environment: Vec<u16>,
}


struct Started {
    process: OwnedHandle,
    thread: OwnedHandle,
    process_id: u32,
}


impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialised by `InitializeProcThreadAttributeList` before this value was built and is deleted only here.
        unsafe { DeleteProcThreadAttributeList(list_pointer(&mut self.buffer)) }
    }
}


impl Drop for Session {
    fn drop(&mut self) {
        let pending = close_on_drop(&mut lock(&self.state));
        let closed = if pending { run_close(self) } else { Ok(()) };
        if let Err(error) = closed {
            tracing::warn!(%error, "closing a dropped pseudo-console session failed");
        }
    }
}


fn coord(columns: i16, rows: i16) -> COORD {
    COORD { X: columns, Y: rows }
}


fn raw(handle: &OwnedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}


fn lock<Value>(mutex: &Mutex<Value>) -> MutexGuard<'_, Value> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


fn windows_error(operation: &'static str, error: &windows::core::Error) -> ConsoleError {
    ConsoleError::Windows {
        operation,
        code: error.code().0.cast_unsigned(),
    }
}


fn io_failure(operation: &'static str, error: &std::io::Error) -> ConsoleError {
    ConsoleError::Io {
        operation,
        kind: error.kind(),
    }
}


fn list_pointer(buffer: &mut [usize]) -> LPPROC_THREAD_ATTRIBUTE_LIST {
    LPPROC_THREAD_ATTRIBUTE_LIST(buffer.as_mut_ptr().cast())
}


fn system_directory() -> Result<String, ConsoleError> {
    let mut buffer = [0; DIRECTORY_UNITS];
    // SAFETY: the slice is a valid writable buffer and the call writes at most its length.
    let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) };
    directory_text("GetSystemDirectoryW", &buffer, length)
}


fn windows_directory() -> Result<String, ConsoleError> {
    let mut buffer = [0; DIRECTORY_UNITS];
    // SAFETY: the slice is a valid writable buffer and the call writes at most its length.
    let length = unsafe { GetSystemWindowsDirectoryW(Some(&mut buffer)) };
    directory_text("GetSystemWindowsDirectoryW", &buffer, length)
}


fn make_pipe() -> Result<(OwnedHandle, OwnedHandle), ConsoleError> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    // SAFETY: both out pointers are valid; no security attributes means neither handle is inheritable.
    unsafe { CreatePipe(&mut read, &mut write, None, PIPE_BUFFER_BYTES) }.map_err(|error| windows_error("CreatePipe", &error))?;
    // SAFETY: the read end was just created and nothing else owns it.
    let read_end = unsafe { OwnedHandle::from_raw_handle(read.0) };
    // SAFETY: the write end was just created and nothing else owns it.
    let write_end = unsafe { OwnedHandle::from_raw_handle(write.0) };
    Ok((read_end, write_end))
}


fn open_console(size: ConsoleSize) -> Result<ConsoleEnds, ConsoleError> {
    let (input_read, input_write) = make_pipe()?;
    let (output_read, output_write) = make_pipe()?;
    let (columns, rows) = coordinates(size);
    let coordinate = coord(columns, rows);
    let input_handle = HANDLE(input_read.as_raw_handle());
    let output_handle = HANDLE(output_write.as_raw_handle());
    // SAFETY: both handles are open pipe ends that outlive the call; the console duplicates what it keeps.
    let opened = unsafe { CreatePseudoConsole(coordinate, input_handle, output_handle, 0) };
    let created = opened.map_err(|error| windows_error("CreatePseudoConsole", &error))?;
    // SAFETY: the console was just created and nothing else owns it.
    let console = unsafe { Owned::new(created) };
    Ok(ConsoleEnds {
        console,
        input: File::from(input_write),
        output: Arc::new(File::from(output_read)),
    })
}


fn attribute_list(console: HPCON) -> Result<AttributeList, ConsoleError> {
    let mut bytes = 0;
    // SAFETY: no list and a size of zero only ask for the required size, written to `bytes`.
    let sizing = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut bytes) };
    sizing
        .err()
        .filter(|error| error.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0))
        .ok_or(ConsoleError::Windows {
            operation: "InitializeProcThreadAttributeList size",
            code: 0,
        })?;
    let mut buffer = vec![0; bytes.div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: the buffer holds at least the `bytes` the sizing call asked for and is aligned for a pointer.
    unsafe { InitializeProcThreadAttributeList(Some(list_pointer(&mut buffer)), 1, None, &mut bytes) }
        .map_err(|error| windows_error("InitializeProcThreadAttributeList", &error))?;
    let mut list = AttributeList { buffer };
    let value = std::ptr::with_exposed_provenance::<c_void>(console.0.cast_unsigned());
    // SAFETY: the list was initialised for one attribute; the pseudo-console attribute value is the handle itself, which outlives CreateProcessW.
    unsafe {
        UpdateProcThreadAttribute(
            list_pointer(&mut list.buffer),
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            Some(value),
            std::mem::size_of::<HPCON>(),
            None,
            None,
        )
    }
    .map_err(|error| windows_error("UpdateProcThreadAttribute", &error))?;
    Ok(list)
}


fn set_job_information<Value>(job: &OwnedHandle, class: JOBOBJECTINFOCLASS, value: &Value) -> Result<(), ConsoleError> {
    let size = u32::try_from(std::mem::size_of::<Value>()).map_err(|_| ConsoleError::Windows {
        operation: "SetInformationJobObject size",
        code: 0,
    })?;
    // SAFETY: the job handle is open and `value` is a valid plain-data structure of `size` bytes that matches `class`.
    unsafe { SetInformationJobObject(raw(job), class, std::ptr::from_ref(value).cast::<c_void>(), size) }
        .map_err(|error| windows_error("SetInformationJobObject", &error))
}


fn create_job() -> Result<OwnedHandle, ConsoleError> {
    // SAFETY: no security attributes and no name: a private, unnamed job.
    let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(|error| windows_error("CreateJobObjectW", &error))?;
    // SAFETY: the job was just created and nothing else owns it.
    let job = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    let mut extended = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    extended.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    extended.BasicLimitInformation.ActiveProcessLimit = ACTIVE_PROCESS_LIMIT;
    set_job_information(&job, JobObjectExtendedLimitInformation, &extended)?;
    let restrictions = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: windows::Win32::System::JobObjects::JOB_OBJECT_UILIMIT(UI_RESTRICTIONS),
    };
    set_job_information(&job, JobObjectBasicUIRestrictions, &restrictions)?;
    Ok(job)
}


fn create_shell(launch: &mut Launch, attributes: &mut AttributeList) -> Result<Started, ConsoleError> {
    let startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: STARTUP_INFO_BYTES,
            dwFlags: STARTF_USESTDHANDLES,
            lpDesktop: PWSTR(launch.desktop.as_mut_ptr()),
            ..Default::default()
        },
        lpAttributeList: list_pointer(&mut attributes.buffer),
    };
    let flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;
    let mut information = PROCESS_INFORMATION::default();
    // SAFETY: the buffers are NUL terminated and outlive the call, the startup structure is the extended form `cb` announces.
    let created = unsafe {
        CreateProcessW(
            PCWSTR(launch.program.as_ptr()),
            Some(PWSTR(launch.command.as_mut_ptr())),
            None,
            None,
            INHERIT_HANDLES,
            flags,
            Some(launch.environment.as_ptr().cast::<c_void>()),
            PCWSTR(launch.directory.as_ptr()),
            std::ptr::from_ref(&startup).cast::<STARTUPINFOW>(),
            &mut information,
        )
    };
    created.map_err(|error| windows_error("CreateProcessW", &error))?;
    // SAFETY: the process handle was just returned and nothing else owns it.
    let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess.0) };
    // SAFETY: the thread handle was just returned and nothing else owns it.
    let thread = unsafe { OwnedHandle::from_raw_handle(information.hThread.0) };
    Ok(Started {
        process,
        thread,
        process_id: information.dwProcessId,
    })
}


fn join_job(job: &OwnedHandle, started: &Started, hook: AssignHook) -> Result<(), ConsoleError> {
    hook(started.process_id).map_err(|code| ConsoleError::Windows {
        operation: "AssignProcessToJobObject",
        code,
    })?;
    // SAFETY: the job and the suspended child are open handles owned by the caller.
    unsafe { AssignProcessToJobObject(raw(job), raw(&started.process)) }.map_err(|error| windows_error("AssignProcessToJobObject", &error))?;
    // SAFETY: the thread handle is the suspended main thread of the child.
    let previous = unsafe { ResumeThread(raw(&started.thread)) };
    if previous == RESUME_FAILED {
        Err(windows_error("ResumeThread", &windows::core::Error::from_thread()))
    } else {
        Ok(())
    }
}


fn kill_process(process: &OwnedHandle) {
    // SAFETY: the process handle is open and owned by the caller.
    if let Err(error) = unsafe { TerminateProcess(raw(process), KILLED_EXIT_CODE) } {
        tracing::warn!(%error, "terminating a child that could not join its job failed");
    }
}


/// The no-fault assignment hook of a production spawn.
pub fn no_assignment_fault(_process_id: u32) -> Result<(), u32> {
    Ok(())
}


/// Starts `cmd.exe /D` in a pseudo-console of the given size, inside a kill-on-close job, with the fixed environment of the session label.
pub fn spawn_session(columns: u32, rows: u32, label: &str) -> Result<Session, ConsoleError> {
    spawn_session_with(columns, rows, label, no_assignment_fault)
}


/// `spawn_session` with a hook run on the child's process id right before it joins the job; a hook error refuses the session and kills the child.
pub fn spawn_session_with(columns: u32, rows: u32, label: &str, hook: AssignHook) -> Result<Session, ConsoleError> {
    let size = console_size(columns, rows)?;
    check_session_label(label)?;
    let system = system_directory()?;
    let windows = windows_directory()?;
    let mut launch = Launch {
        program: wide_null(&format!("{system}\\{SHELL_PROGRAM_NAME}")),
        command: wide_null(&command_line(&system)?),
        directory: wide_null(&system),
        desktop: wide_null(NO_DESKTOP),
        environment: session_environment(&system, &windows, label)?,
    };
    let ends = open_console(size)?;
    let mut attributes = attribute_list(*ends.console)?;
    let job = create_job()?;
    let started = create_shell(&mut launch, &mut attributes)?;
    join_job(&job, &started, hook).inspect_err(|_| kill_process(&started.process))?;
    Ok(Session {
        state: Mutex::new(CloseState::Open),
        closing: AtomicBool::new(false),
        readers: Arc::new(AtomicUsize::new(0)),
        console: Mutex::new(Some(ends.console)),
        input: ends.input,
        output: ends.output,
        process: started.process,
        job,
        process_id: started.process_id,
    })
}


/// The process id of the shell.
pub fn process_id(session: &Session) -> u32 {
    session.process_id
}


/// Reads up to `OUTPUT_CHUNK_BYTES` of console output, blocking; an empty result is the end of the output.
pub fn read_output(session: &Session) -> Result<Vec<u8>, ConsoleError> {
    let mut buffer = vec![0; OUTPUT_CHUNK_BYTES];
    session.readers.fetch_add(1, Ordering::SeqCst);
    let read = if session.closing.load(Ordering::SeqCst) {
        Ok(0)
    } else {
        (&*session.output).read(&mut buffer)
    };
    session.readers.fetch_sub(1, Ordering::SeqCst);
    let count = read.map_err(|error| io_failure("ReadFile", &error))?;
    buffer.truncate(count);
    Ok(buffer)
}


/// Writes at most `INPUT_CHUNK_BYTES` of keystrokes to the console; a larger write is refused by name.
pub fn write_input(session: &Session, bytes: &[u8]) -> Result<(), ConsoleError> {
    check_input_len(bytes.len())?;
    (&session.input).write_all(bytes).map_err(|error| io_failure("WriteFile", &error))
}


/// Resizes the console; a size outside the bounds is refused before the call.
pub fn resize_console(session: &Session, columns: u32, rows: u32) -> Result<(), ConsoleError> {
    let size = console_size(columns, rows)?;
    let guard = lock(&session.console);
    let console = guard.as_ref().ok_or(ConsoleError::AlreadyClosed)?;
    let (width, height) = coordinates(size);
    // SAFETY: the console handle stays open while the guard is held.
    let resized = unsafe { ResizePseudoConsole(**console, coord(width, height)) };
    resized.map_err(|error| windows_error("ResizePseudoConsole", &error))
}


fn terminate_job(session: &Session) -> Result<(), ConsoleError> {
    // SAFETY: the job handle is open for the life of the session.
    unsafe { TerminateJobObject(raw(&session.job), KILLED_EXIT_CODE) }.map_err(|error| windows_error("TerminateJobObject", &error))
}


fn drain_output(output: &File) -> Result<(), ConsoleError> {
    std::io::copy(&mut &*output, &mut std::io::sink())
        .map(|_| ())
        .map_err(|error| io_failure("drain", &error))
}


fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}


fn cancel_pending_read(output: &File) {
    // SAFETY: the handle belongs to the open output pipe end, which the caller's reference keeps open for the whole call.
    if let Err(error) = unsafe { CancelIoEx(HANDLE(output.as_raw_handle()), None) } {
        tracing::debug!(%error, "cancelling the console read found none pending");
    }
}


fn cancel_pending_reads(session: &Session) {
    let left = (0..CANCEL_ATTEMPTS).find_map(|_| {
        cancel_pending_read(&session.output);
        std::thread::sleep(Duration::from_millis(CANCEL_POLL_MILLIS));
        (session.readers.load(Ordering::SeqCst) == 0).then_some(())
    });
    if left.is_none() {
        tracing::warn!("a console read outlived the cancellation attempts of the close");
    }
}


fn release_console(session: &Session, console: Option<Owned<HPCON>>, deadline: Instant) -> Result<(), ConsoleError> {
    let (sender, receiver) = channel();
    let drain_sender = sender.clone();
    let output = Arc::clone(&session.output);
    let readers = Arc::clone(&session.readers);
    readers.fetch_add(1, Ordering::SeqCst);
    std::thread::Builder::new()
        .name("pty-drain".into())
        .spawn(move || {
            let drained = drain_output(&output);
            readers.fetch_sub(1, Ordering::SeqCst);
            if let Err(error) = drain_sender.send(drained) {
                tracing::debug!(%error, "the close stopped waiting for the output drain");
            }
        })
        .map_err(|error| {
            session.readers.fetch_sub(1, Ordering::SeqCst);
            io_failure("drain thread", &error)
        })?;
    std::thread::Builder::new()
        .name("pty-close".into())
        .spawn(move || {
            drop(console);
            if let Err(error) = sender.send(Ok(())) {
                tracing::debug!(%error, "the close stopped waiting for the console release");
            }
        })
        .map_err(|error| io_failure("console thread", &error))?;
    let results: Vec<_> = (0..CLOSE_STEPS).map(|_| receiver.recv_timeout(remaining(deadline))).collect();
    if results.iter().any(Result::is_err) {
        cancel_pending_reads(session);
    }
    results.into_iter().try_for_each(|result| {
        result
            .map_err(|error| match error {
                RecvTimeoutError::Timeout => ConsoleError::CloseTimeout { millis: CLOSE_WAIT_MILLIS },
                RecvTimeoutError::Disconnected => ConsoleError::DrainFailed,
            })
            .and_then(std::convert::identity)
    })
}


fn wait_process(session: &Session, deadline: Instant) -> Result<(), ConsoleError> {
    let millis = u32::try_from(remaining(deadline).as_millis()).unwrap_or(CLOSE_WAIT_MILLIS);
    // SAFETY: the process handle is open for the life of the session.
    let waited = unsafe { WaitForSingleObject(raw(&session.process), millis) };
    if waited == WAIT_OBJECT_0 {
        Ok(())
    } else if waited == WAIT_TIMEOUT {
        Err(ConsoleError::CloseTimeout { millis: CLOSE_WAIT_MILLIS })
    } else {
        Err(windows_error("WaitForSingleObject", &windows::core::Error::from_thread()))
    }
}


fn run_close(session: &Session) -> Result<(), ConsoleError> {
    let deadline = Instant::now() + Duration::from_millis(u64::from(CLOSE_WAIT_MILLIS));
    session.closing.store(true, Ordering::SeqCst);
    let terminated = terminate_job(session);
    let console = lock(&session.console).take();
    let released = release_console(session, console, deadline);
    let waited = wait_process(session, deadline);
    terminated.and(released).and(waited)
}


/// Terminates the job, closes the console while the output drains, all within one `CLOSE_WAIT_MILLIS` deadline (`CloseTimeout` past it, the pending read cancelled); every step runs, the first error returns.
pub fn close_console(session: &Session) -> Result<(), ConsoleError> {
    begin_close(&mut lock(&session.state))?;
    run_close(session)
}


/// Whether the shell is a member of the session's job (false only if the assignment was skipped).
pub fn shell_in_job(session: &Session) -> Result<bool, ConsoleError> {
    let mut member = BOOL::default();
    // SAFETY: both handles are open for the life of the session and `member` is a valid out pointer.
    unsafe { IsProcessInJob(raw(&session.process), Some(raw(&session.job)), &mut member) }
        .map_err(|error| windows_error("IsProcessInJob", &error))?;
    Ok(member.as_bool())
}


/// The limit flags and the active process limit the job enforces.
pub fn job_limits(session: &Session) -> Result<(u32, u32), ConsoleError> {
    let mut extended = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let size = u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).map_err(|_| ConsoleError::Windows {
        operation: "QueryInformationJobObject size",
        code: 0,
    })?;
    let target = std::ptr::from_mut(&mut extended).cast::<c_void>();
    // SAFETY: the job handle is open and `target` points at a writable structure of `size` bytes matching the class.
    unsafe { QueryInformationJobObject(Some(raw(&session.job)), JobObjectExtendedLimitInformation, target, size, None) }
        .map_err(|error| windows_error("QueryInformationJobObject", &error))?;
    Ok((
        extended.BasicLimitInformation.LimitFlags.0,
        extended.BasicLimitInformation.ActiveProcessLimit,
    ))
}
