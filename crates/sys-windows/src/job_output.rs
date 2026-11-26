#![cfg(windows)]
use crate::session::io_failure;
use crate::types::ConsoleError;
use std::fs::File;
use std::io::Read;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::IO::CancelIoEx;


/// The size of the buffer a drain reads into.
pub const DRAIN_CHUNK_BYTES: usize = 4096;


const CANCEL_ATTEMPTS: u32 = 500;


const CANCEL_POLL_MILLIS: u64 = 20;


const MAX_DRAIN_READS: u32 = 1_000_000;


#[doc = "The read end of the output pipe of a program started in a job. The pipe reaches its end only when every process holding its write end has ended, and a process outside the job can hold it (a `CreateProcess` elsewhere in the agent that inherits every inheritable handle, as the Rust standard library does), so the only way to read it is `read_output` with a deadline. The wrapper is not `Clone` and the pipe never leaves it.\n\n```compile_fail,E0616\nfn pipe(output: &sys_windows::job_output::ChildOutput) {\n    let _ = &output.file;\n}\n```\n\n```compile_fail,E0599\nfn copy(output: &sys_windows::job_output::ChildOutput) -> sys_windows::job_output::ChildOutput {\n    output.clone()\n}\n```\n"]
pub struct ChildOutput {
    file: Arc<File>,
    readers: AtomicUsize,
}


/// What a bounded read found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputRead {
    Bytes(usize),
    End,
    DeadlinePassed,
}


/// What a drain found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainEnd {
    Reached,
    DeadlinePassed,
}


pub(crate) fn child_output(file: File) -> ChildOutput {
    ChildOutput {
        file: Arc::new(file),
        readers: AtomicUsize::new(0),
    }
}


/// The number of reads in flight right now.
pub fn reader_count(output: &ChildOutput) -> usize {
    output.readers.load(Ordering::SeqCst)
}


fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}


fn cancel_pending_read(file: &File) {
    // SAFETY: the handle belongs to the open pipe end, which the caller's `Arc` keeps open for the whole call.
    if let Err(error) = unsafe { CancelIoEx(HANDLE(file.as_raw_handle()), None) } {
        tracing::debug!(%error, "cancelling the child output read found none pending");
    }
}


fn cancel_until_done(file: &File, finished: &Receiver<()>) {
    let done = (0..CANCEL_ATTEMPTS).find_map(|_| {
        cancel_pending_read(file);
        match finished.recv_timeout(Duration::from_millis(CANCEL_POLL_MILLIS)) {
            Err(RecvTimeoutError::Timeout) => None,
            Ok(()) | Err(RecvTimeoutError::Disconnected) => Some(()),
        }
    });
    if done.is_none() {
        tracing::warn!("a child output read outlived the cancellation attempts");
    }
}


fn watch_read(file: &File, finished: &Receiver<()>, expired: &AtomicBool, deadline: Instant) {
    if finished.recv_timeout(remaining(deadline)) == Err(RecvTimeoutError::Timeout) {
        expired.store(true, Ordering::SeqCst);
        cancel_until_done(file, finished);
    }
}


/// Reads up to `buffer.len()` bytes, one reader at a time; a read blocked at `deadline` is cancelled with `CancelIoEx` and gives `DeadlinePassed`.
pub fn read_output(output: &ChildOutput, buffer: &mut [u8], deadline: Instant) -> Result<OutputRead, ConsoleError> {
    let (sender, finished) = channel::<()>();
    let expired = Arc::new(AtomicBool::new(false));
    let watched_file = Arc::clone(&output.file);
    let watched_expired = Arc::clone(&expired);
    let watcher = std::thread::Builder::new()
        .name("job-read-watch".into())
        .spawn(move || watch_read(&watched_file, &finished, &watched_expired, deadline))
        .map_err(|error| io_failure("watcher thread", &error))?;
    output.readers.fetch_add(1, Ordering::SeqCst);
    let read = (&*output.file).read(buffer);
    drop(sender);
    output.readers.fetch_sub(1, Ordering::SeqCst);
    watcher.join().map_err(|_| ConsoleError::Windows {
        operation: "child output watcher panicked",
        code: 0,
    })?;
    let timed_out = expired.load(Ordering::SeqCst);
    match read {
        Ok(0) => Ok(OutputRead::End),
        Ok(count) => Ok(OutputRead::Bytes(count)),
        Err(error) if timed_out => {
            tracing::debug!(%error, "a child output read ended at its deadline");
            Ok(OutputRead::DeadlinePassed)
        }
        Err(error) => Err(io_failure("ReadFile", &error)),
    }
}


fn drain_step(output: &ChildOutput, buffer: &mut [u8], deadline: Instant) -> Result<Option<DrainEnd>, ConsoleError> {
    let found = read_output(output, buffer, deadline)?;
    Ok(match found {
        OutputRead::Bytes(_) => None,
        OutputRead::End => Some(DrainEnd::Reached),
        OutputRead::DeadlinePassed => Some(DrainEnd::DeadlinePassed),
    })
}


/// Reads and discards the output until its end or `deadline`: callers use it after `terminate` so a surviving writer cannot hold them.
pub fn drain_output(output: &ChildOutput, deadline: Instant) -> Result<DrainEnd, ConsoleError> {
    let mut buffer = [0; DRAIN_CHUNK_BYTES];
    let mut ended = None;
    let mut reads = 0;
    while ended.is_none() && reads < MAX_DRAIN_READS {
        reads += 1;
        ended = drain_step(output, &mut buffer, deadline)?;
    }
    Ok(ended.unwrap_or(DrainEnd::DeadlinePassed))
}
