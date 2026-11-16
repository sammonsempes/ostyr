use crate::error::IsolationError;
use crate::sensor::{kill_group, GroupKill};
use crate::types::{KillFn, NftFuture};
use rustix::process::Pid;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{copy, sink, AsyncRead, AsyncReadExt};
use tokio::process::Command;


pub const MAX_NFT_OUTPUT_BYTES: u64 = 32_768;


pub const MAX_NFT_STDERR_BYTES: u64 = 512;


/// `LC_ALL=C` keeps the English error text that `is_absent` matches under any locale.
pub const LOCALE_NAME: &str = "LC_ALL";


pub const LOCALE_VALUE: &str = "C";


pub const NFT_DEADLINE_SECONDS: u64 = 10;


/// Reads at most `cap` bytes; a stream that goes on is an error and is not drained, so the caller's group kill ends the writer.
pub async fn read_stdout<Pipe: AsyncRead + Unpin>(pipe: Option<Pipe>, cap: u64) -> Result<Vec<u8>, IsolationError> {
    let mut output = Vec::new();
    for mut stream in pipe.into_iter() {
        (&mut stream).take(cap + 1).read_to_end(&mut output).await?;
    }
    if output.len() as u64 > cap {
        Err(IsolationError::TooLarge(cap))
    } else {
        Ok(output)
    }
}


/// Keeps the first `cap` bytes and drains the rest, so a chatty child never blocks on a full pipe.
pub async fn read_stderr<Pipe: AsyncRead + Unpin>(pipe: Option<Pipe>, cap: u64) -> Result<Vec<u8>, IsolationError> {
    let mut output = Vec::new();
    for mut stream in pipe.into_iter() {
        (&mut stream).take(cap).read_to_end(&mut output).await?;
        copy(&mut stream, &mut sink()).await?;
    }
    Ok(output)
}


/// Runs the program in its own process group with bounded output and a group kill on every early end.
pub async fn run_nft_with(program: PathBuf, arguments: Vec<String>, kill: KillFn) -> Result<String, IsolationError> {
    let mut child = Command::new(program)
        .args(arguments)
        .env(LOCALE_NAME, LOCALE_VALUE)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0)
        .spawn()?;
    let mut guard = GroupKill {
        group: child.id().and_then(|id| Pid::from_raw(id as i32)),
        kill,
    };
    let (stdout, stderr) = tokio::try_join!(
        read_stdout(child.stdout.take(), MAX_NFT_OUTPUT_BYTES),
        read_stderr(child.stderr.take(), MAX_NFT_STDERR_BYTES)
    )?;
    let status = child.wait().await?;
    guard.group = None;
    if status.success() {
        Ok(std::str::from_utf8(&stdout).map_err(IsolationError::Utf8)?.to_owned())
    } else {
        Err(IsolationError::Exit {
            code: status.code(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}


pub async fn run_nft_deadline(program: PathBuf, arguments: Vec<String>, deadline: Duration) -> Result<String, IsolationError> {
    tokio::time::timeout(deadline, run_nft_with(program, arguments, kill_group))
        .await
        .map_err(|_| IsolationError::Timeout)?
}


/// The production runner.
pub fn run_nft(program: PathBuf, arguments: Vec<String>) -> NftFuture {
    Box::pin(run_nft_deadline(program, arguments, Duration::from_secs(NFT_DEADLINE_SECONDS)))
}
