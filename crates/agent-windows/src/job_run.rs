#![cfg(windows)]
//! The Windows runner of a request with an explicit environment: the child lives in a kill-on-close job, so a deadline or a cap ends its whole tree.

use crate::error::RunError;
use crate::model::{Drained, RunEnd, RunRequest, MAX_READ_ROUNDS, READ_CHUNK_BYTES, WORKING_DIRECTORY};
use crate::run::forward;
use std::time::{Duration, Instant};
use sys_windows::job_output::{drain_output, read_output, ChildOutput, OutputRead};
use sys_windows::job_spawn::{spawn_in_job, terminate, wait_for_exit, JobChild, JobOutput, MAX_WAIT_MILLIS};


/// How long the output is drained after the job was ended.
pub const DRAIN_SECONDS: u64 = 10;


pub fn exit_code(code: u32) -> i32 {
    i32::from_ne_bytes(code.to_ne_bytes())
}


pub fn read_step(
    output: &ChildOutput,
    buffer: &mut [u8],
    request: &RunRequest<'_>,
    sink: &mut dyn FnMut(&[u8]),
    progress: (Instant, &mut usize),
) -> Result<Option<Drained>, RunError> {
    let (deadline, total) = progress;
    let read = read_output(output, buffer, deadline).map_err(RunError::Job)?;
    Ok(match read {
        OutputRead::Bytes(count) => buffer.get(..count).and_then(|chunk| forward(chunk, total, request.max_bytes, sink)),
        OutputRead::End => Some(Drained::Eof),
        OutputRead::DeadlinePassed => Some(Drained::Deadline),
    })
}


pub fn read_all(output: &ChildOutput, request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8]), deadline: Instant) -> Result<Drained, RunError> {
    let mut buffer = vec![0u8; READ_CHUNK_BYTES];
    let mut total = 0usize;
    (0..MAX_READ_ROUNDS)
        .find_map(|_| read_step(output, &mut buffer, request, sink, (deadline, &mut total)).transpose())
        .unwrap_or(Ok(Drained::Capped))
}


pub fn stop_job(child: &JobChild, output: &ChildOutput) -> Result<(), RunError> {
    let ended = terminate(child).map_err(RunError::Job);
    let drained = drain_output(output, Instant::now() + Duration::from_secs(DRAIN_SECONDS))
        .map(|_| ())
        .map_err(RunError::Job);
    ended.and(drained)
}


pub fn finish_job(child: &JobChild, output: &ChildOutput, drained: Drained) -> Result<RunEnd, RunError> {
    match drained {
        Drained::Eof => match wait_for_exit(child, MAX_WAIT_MILLIS).map_err(RunError::Job)? {
            Some(0) => Ok(RunEnd::Done),
            Some(code) => Ok(RunEnd::Failed(Some(exit_code(code)))),
            None => stop_job(child, output).map(|()| RunEnd::Deadline),
        },
        Drained::Capped => stop_job(child, output).map(|()| RunEnd::Capped),
        Drained::Deadline => stop_job(child, output).map(|()| RunEnd::Deadline),
    }
}


/// Starts the program in a job with exactly the request environment, reads its output within the cap and the deadline, ends the tree otherwise.
pub fn run_in_job(request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])) -> Result<RunEnd, RunError> {
    let arguments: Vec<&str> = request.args.iter().map(String::as_str).collect();
    let environment = request.environment.unwrap_or(&[]);
    let JobOutput { child, output } = spawn_in_job(request.program, &arguments, environment, WORKING_DIRECTORY).map_err(RunError::Job)?;
    let deadline = Instant::now() + Duration::from_secs(request.deadline_seconds);
    let drained = read_all(&output, request, sink, deadline)?;
    finish_job(&child, &output, drained)
}
