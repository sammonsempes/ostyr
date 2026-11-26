#![cfg(windows)]
use crate::job_command::{job_launch, process_ids_from};
use crate::job_output::{child_output, ChildOutput};
use crate::session::{
    build_attribute_list, create_job, io_failure, join_job, kill_process, limits_of, list_pointer, make_pipe, process_in_job, raw, wait_for_process,
    windows_error, AttributeList, Started,
};
use crate::types::{AssignHook, ConsoleError, JobLaunch, SpawnHooks};
use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::core::PWSTR;
use windows::Win32::Foundation::{SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::JobObjects::{JobObjectBasicProcessIdList, QueryInformationJobObject, TerminateJobObject};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
};


/// The one deadline of `terminate`: the job is ended, then the main process is waited for this long.
pub const TERMINATE_WAIT_MILLIS: u32 = 10_000;


/// The `bInheritHandles` argument of the spawn: true, but only the two handles of the explicit handle list are inherited.
pub const INHERIT_LISTED_HANDLES: bool = true;


const KILLED_EXIT_CODE: u32 = 1;


/// The longest `wait_for_exit` blocks; a larger request (`INFINITE` included) is cut to it.
pub const MAX_WAIT_MILLIS: u32 = 10_000;


const NULL_DEVICE: &str = "NUL";


const STARTUP_INFO_BYTES: u32 = std::mem::size_of::<STARTUPINFOEXW>() as u32;


const LISTED_HANDLES: usize = 2;


const PROCESS_LIST_WORDS: usize = 130;


#[doc = "A program started in a kill-on-close job: dropping it closes the last job handle, which ends the whole process tree. No handle crosses the API and the wrapper is not `Clone`.\n\n```compile_fail,E0616\nfn job(child: &sys_windows::job_spawn::JobChild) {\n    let _ = &child.job;\n}\n```\n\n```compile_fail,E0616\nfn process(child: &sys_windows::job_spawn::JobChild) {\n    let _ = &child.process;\n}\n```\n\n```compile_fail,E0599\nfn copy(child: &sys_windows::job_spawn::JobChild) -> sys_windows::job_spawn::JobChild {\n    child.clone()\n}\n```\n"]
pub struct JobChild {
    process: OwnedHandle,
    job: OwnedHandle,
    process_id: u32,
}


/// A started program and the read end of its standard output, read only through `read_output` with a deadline.
pub struct JobOutput {
    pub child: JobChild,
    pub output: ChildOutput,
}


fn make_inheritable(handle: &OwnedHandle) -> Result<(), ConsoleError> {
    // SAFETY: the handle is open for the whole call; only its inherit flag changes.
    unsafe { SetHandleInformation(raw(handle), HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
        .map_err(|error| windows_error("SetHandleInformation", &error))
}


fn clear_inheritable(handle: &OwnedHandle) -> Result<(), ConsoleError> {
    // SAFETY: the handle is open for the whole call; only its inherit flag changes.
    unsafe { SetHandleInformation(raw(handle), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
        .map_err(|error| windows_error("SetHandleInformation", &error))
}


fn open_null_device() -> Result<OwnedHandle, ConsoleError> {
    File::options()
        .read(true)
        .write(true)
        .open(NULL_DEVICE)
        .map(OwnedHandle::from)
        .map_err(|error| io_failure("open NUL", &error))
}


fn handle_list(handles: &[HANDLE; LISTED_HANDLES]) -> Result<AttributeList, ConsoleError> {
    build_attribute_list(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
        handles.as_ptr().cast::<c_void>(),
        std::mem::size_of_val(handles),
    )
}


fn create_child(
    launch: &mut JobLaunch,
    attributes: &mut AttributeList,
    standard: (&OwnedHandle, &OwnedHandle, &OwnedHandle),
) -> Result<Started, ConsoleError> {
    let (input, output, error_output) = standard;
    let startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: STARTUP_INFO_BYTES,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: raw(input),
            hStdOutput: raw(output),
            hStdError: raw(error_output),
            ..Default::default()
        },
        lpAttributeList: list_pointer(&mut attributes.buffer),
    };
    let flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | CREATE_NO_WINDOW;
    let mut information = PROCESS_INFORMATION::default();
    // SAFETY: the buffers are NUL terminated and outlive the call, the startup structure is the extended form `cb` announces, and the handle array the attribute list points at is the caller's `handles`, alive until after this call.
    let created = unsafe {
        CreateProcessW(
            PCWSTR(launch.program.as_ptr()),
            Some(PWSTR(launch.command.as_mut_ptr())),
            None,
            None,
            INHERIT_LISTED_HANDLES,
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


/// The no-fault assignment hook of a production spawn.
pub fn no_job_fault(_process_id: u32) -> Result<(), u32> {
    Ok(())
}


/// Starts the program suspended in a kill-on-close job: null stdin and stderr, piped stdout; a `CreateProcess` racing the spawn can hold the pipe, so read with a deadline.
pub fn spawn_in_job(program: &str, arguments: &[&str], environment: &[(&str, &str)], directory: &str) -> Result<JobOutput, ConsoleError> {
    spawn_in_job_with(program, arguments, environment, directory, no_job_fault)
}


/// `spawn_in_job` with a hook run on the child's process id right before it joins the job; a hook or assignment error kills the child and refuses.
pub fn spawn_in_job_with(
    program: &str,
    arguments: &[&str],
    environment: &[(&str, &str)],
    directory: &str,
    hook: AssignHook,
) -> Result<JobOutput, ConsoleError> {
    spawn_in_job_hooked(
        program,
        arguments,
        environment,
        directory,
        SpawnHooks {
            assign: hook,
            after_create: no_window_action,
            after_clear: no_window_action,
        },
    )
}


/// The no-action default of the window hook.
pub fn no_window_action() {}


/// `spawn_in_job_with` plus two actions: one right after `CreateProcessW` (the window opened just before it: the pipe write end is still inheritable), one right after the inherit flags are cleared.
pub fn spawn_in_job_hooked(
    program: &str,
    arguments: &[&str],
    environment: &[(&str, &str)],
    directory: &str,
    hooks: SpawnHooks,
) -> Result<JobOutput, ConsoleError> {
    let mut launch = job_launch(program, arguments, environment, directory)?;
    let (stdout_read, stdout_write) = make_pipe()?;
    let null_device = open_null_device()?;
    let handles = [raw(&null_device), raw(&stdout_write)];
    let mut attributes = handle_list(&handles)?;
    let job = create_job()?;
    make_inheritable(&stdout_write)?;
    make_inheritable(&null_device)?;
    let started = create_child(&mut launch, &mut attributes, (&null_device, &stdout_write, &null_device))?;
    (hooks.after_create)();
    let cleared = clear_inheritable(&stdout_write).and(clear_inheritable(&null_device));
    (hooks.after_clear)();
    drop(stdout_write);
    drop(null_device);
    cleared
        .and_then(|()| join_job(&job, &started, hooks.assign))
        .inspect_err(|_| kill_process(&started.process))?;
    Ok(JobOutput {
        child: JobChild {
            process: started.process,
            job,
            process_id: started.process_id,
        },
        output: child_output(File::from(stdout_read)),
    })
}


/// The process id of the program.
pub fn child_process_id(child: &JobChild) -> u32 {
    child.process_id
}


/// Ends every process of the job, then waits at most `TERMINATE_WAIT_MILLIS` for the main process; `CloseTimeout` past it.
pub fn terminate(child: &JobChild) -> Result<(), ConsoleError> {
    let deadline = Instant::now() + Duration::from_millis(u64::from(TERMINATE_WAIT_MILLIS));
    // SAFETY: the job handle is open for the life of the child.
    let ended = unsafe { TerminateJobObject(raw(&child.job), KILLED_EXIT_CODE) }.map_err(|error| windows_error("TerminateJobObject", &error));
    let waited = wait_for_process(&child.process, deadline);
    ended.and(waited)
}


/// Waits at most `millis` (cut to `MAX_WAIT_MILLIS`) for the main process: its exit code once it ended, `None` while it still runs.
pub fn wait_for_exit(child: &JobChild, millis: u32) -> Result<Option<u32>, ConsoleError> {
    // SAFETY: the process handle is open for the life of the child.
    let waited = unsafe { WaitForSingleObject(raw(&child.process), millis.min(MAX_WAIT_MILLIS)) };
    if waited == WAIT_OBJECT_0 {
        let mut code = 0;
        // SAFETY: the process handle is open and `code` is a valid out pointer.
        unsafe { GetExitCodeProcess(raw(&child.process), &mut code) }.map_err(|error| windows_error("GetExitCodeProcess", &error))?;
        Ok(Some(code))
    } else if waited == WAIT_TIMEOUT {
        Ok(None)
    } else {
        Err(windows_error("WaitForSingleObject", &windows::core::Error::from_thread()))
    }
}


/// Whether the program is a member of the child's job (false only if the assignment was skipped).
pub fn child_in_job(child: &JobChild) -> Result<bool, ConsoleError> {
    process_in_job(&child.process, &child.job)
}


/// The limit flags and the active process limit the job enforces.
pub fn child_job_limits(child: &JobChild) -> Result<(u32, u32), ConsoleError> {
    limits_of(&child.job)
}


/// The process ids the job holds right now (the program and every descendant that has not ended), read from `JobObjectBasicProcessIdList`.
pub fn child_process_ids(child: &JobChild) -> Result<Vec<u32>, ConsoleError> {
    let mut words: Vec<u64> = vec![0; PROCESS_LIST_WORDS];
    let size = u32::try_from(std::mem::size_of_val(words.as_slice())).map_err(|_| ConsoleError::Windows {
        operation: "QueryInformationJobObject size",
        code: 0,
    })?;
    let target = words.as_mut_ptr().cast::<c_void>();
    // SAFETY: the job handle is open and `target` points at a writable, 8-byte aligned buffer of `size` bytes for the class.
    unsafe { QueryInformationJobObject(Some(raw(&child.job)), JobObjectBasicProcessIdList, target, size, None) }
        .map_err(|error| windows_error("QueryInformationJobObject", &error))?;
    Ok(process_ids_from(&words))
}
