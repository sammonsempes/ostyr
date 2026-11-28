use crate::error::RunError;
use crate::model::{Drained, RunEnd, RunRequest, CHANNEL_DEPTH, MAX_READ_ROUNDS, READ_CHUNK_BYTES, WORKING_DIRECTORY};
use std::io::{self, ErrorKind, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::thread::{spawn, JoinHandle};
use std::time::{Duration, Instant};
use tracing::warn;


pub fn read_once(reader: &mut dyn Read, sender: &SyncSender<Vec<u8>>, buffer: &mut [u8]) -> bool {
    match reader.read(buffer) {
        Ok(0) => false,
        Ok(count) => buffer.get(..count).is_some_and(|chunk| sender.send(chunk.to_vec()).is_ok()),
        Err(error) if error.kind() == ErrorKind::Interrupted => true,
        Err(error) => {
            let kind = error.kind();
            warn!(kind = ?kind, "log tool pipe read failed");
            false
        }
    }
}


pub fn pump(reader: &mut dyn Read, sender: &SyncSender<Vec<u8>>) {
    let mut buffer = vec![0u8; READ_CHUNK_BYTES];
    (0..MAX_READ_ROUNDS).try_for_each(|_| read_once(reader, sender, &mut buffer).then_some(()));
}


pub fn forward(chunk: &[u8], total: &mut usize, max_bytes: usize, sink: &mut dyn FnMut(&[u8])) -> Option<Drained> {
    let room = max_bytes.saturating_sub(*total);
    chunk.get(..room.min(chunk.len())).into_iter().for_each(&mut *sink);
    *total = total.saturating_add(chunk.len());
    (*total > max_bytes).then_some(Drained::Capped)
}


pub fn drain_step(
    receiver: &Receiver<Vec<u8>>,
    request: &RunRequest<'_>,
    sink: &mut dyn FnMut(&[u8]),
    progress: (Instant, &mut usize),
) -> Option<Drained> {
    let (start, total) = progress;
    let limit = Duration::from_secs(request.deadline_seconds);
    match receiver.recv_timeout(limit.saturating_sub(start.elapsed())) {
        Ok(chunk) => forward(&chunk, total, request.max_bytes, sink),
        Err(RecvTimeoutError::Timeout) => Some(Drained::Deadline),
        Err(RecvTimeoutError::Disconnected) => Some(Drained::Eof),
    }
}


pub fn drain(receiver: &Receiver<Vec<u8>>, request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])) -> Drained {
    let start = Instant::now();
    let mut total = 0usize;
    (0..MAX_READ_ROUNDS)
        .find_map(|_| drain_step(receiver, request, sink, (start, &mut total)))
        .unwrap_or(Drained::Capped)
}


pub fn finish(child: &mut Child, drained: Drained) -> Result<RunEnd, RunError> {
    match drained {
        Drained::Eof => child
            .wait()
            .map(|status| if status.success() { RunEnd::Done } else { RunEnd::Failed(status.code()) })
            .map_err(RunError::Wait),
        Drained::Capped => stop(child).map(|()| RunEnd::Capped),
        Drained::Deadline => stop(child).map(|()| RunEnd::Deadline),
    }
}


pub fn stop(child: &mut Child) -> Result<(), RunError> {
    child.kill().map_err(RunError::Kill)?;
    child.wait().map(|_| ()).map_err(RunError::Wait)
}


/// With an explicit environment the child sees exactly those pairs; without one it inherits the agent's.
pub fn apply_environment(command: &mut Command, environment: Option<&[(&str, &str)]>) {
    if let Some(pairs) = environment {
        command.env_clear().envs(pairs.iter().copied());
    }
}


pub fn spawn_child(request: &RunRequest<'_>, writer: io::PipeWriter) -> Result<Child, RunError> {
    let mut command = Command::new(request.program);
    apply_environment(&mut command, request.environment);
    command
        .args(request.args)
        .current_dir(WORKING_DIRECTORY)
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(Stdio::null())
        .spawn()
        .map_err(RunError::Spawn)
}


pub fn start_reader(mut reader: io::PipeReader) -> (Receiver<Vec<u8>>, JoinHandle<()>) {
    let (sender, receiver) = sync_channel(CHANNEL_DEPTH);
    let handle = spawn(move || pump(&mut reader, &sender));
    (receiver, handle)
}


/// A request with an explicit environment runs in a kill-on-close job on Windows (the tree ends with the deadline); elsewhere it is the plain run.
#[cfg(windows)]
pub fn run_isolated(request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])) -> Result<RunEnd, RunError> {
    crate::job_run::run_in_job(request, sink)
}


#[cfg(not(windows))]
pub fn run_isolated(request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])) -> Result<RunEnd, RunError> {
    run_plain(request, sink)
}


/// The production runner: a request with an explicit environment is the isolated run, any other the plain one.
pub fn run_process(request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])) -> Result<RunEnd, RunError> {
    if request.environment.is_some() {
        run_isolated(request, sink)
    } else {
        run_plain(request, sink)
    }
}


/// Runs the tool without a shell, stderr null; stdout goes to `sink` within the cap and deadline, else the child is killed and reaped.
pub fn run_plain(request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])) -> Result<RunEnd, RunError> {
    let (reader, writer) = io::pipe().map_err(RunError::Pipe)?;
    let mut child = spawn_child(request, writer)?;
    let (receiver, handle) = start_reader(reader);
    let drained = drain(&receiver, request, sink);
    let finished = finish(&mut child, drained);
    drop(receiver);
    let joined = handle.join().map_err(|_| RunError::Reader);
    finished.and_then(|end| joined.map(|()| end))
}
