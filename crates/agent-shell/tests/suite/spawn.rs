use crate::support::{default_order, private_tempdir};
use crate::types::TestResult;
use agent_shell::account::ShellAccount;
use agent_shell::model::PtyHandle;
use agent_shell::spawn::{
    missing_program, pump_output, read_chunk, shell_args, shell_environment, spawn_fn, spawn_pty, spawn_shell, write_input, ShellPrograms,
    OUTPUT_CHUNK_BYTES, SHELL_PROGRAMS,
};
use futures_util::StreamExt;
use std::io::{self, Read, Write};
use std::path::Path;
use tokio::sync::mpsc;


const ACCOUNT_UID: u32 = 1001;


const ACCOUNT_GID: u32 = 1002;


const NOBODY: u32 = 65534;


const SHELL: &str = "/bin/sh";


const ECHO_ARGS: [&str; 2] = ["-c", "echo \"$FOO:${HOME-unset}:$(pwd)\""];


const READ_ARGS: [&str; 2] = ["-c", "read line; echo got-$line"];


const SPILL_FACTOR: usize = 2;


fn account_in(home: &Path) -> ShellAccount {
    ShellAccount {
        uid: ACCOUNT_UID,
        gid: ACCOUNT_GID,
        home: home.to_path_buf(),
    }
}


fn texts(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}


struct Failing {
    errno: Option<i32>,
}


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(self.errno.map_or_else(|| io::Error::other("broken"), io::Error::from_raw_os_error))
    }
}


impl Write for Failing {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("broken"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


async fn transcript(handle: PtyHandle) -> Vec<u8> {
    let PtyHandle { output, input, exit } = handle;
    drop(input);
    exit.await;
    output
        .filter_map(|chunk| std::future::ready(chunk.ok()))
        .collect::<Vec<_>>()
        .await
        .concat()
}


#[test]
fn the_arguments_are_the_fixed_privilege_drop_and_limits() -> TestResult {
    let account = account_in(Path::new("/home/ostyr-shell"));
    assert_eq!(
        shell_args(&account, &SHELL_PROGRAMS),
        texts(&[
            "--reuid=1001",
            "--regid=1002",
            "--init-groups",
            "--no-new-privs",
            "--inh-caps=-all",
            "--bounding-set=-all",
            "--",
            "/usr/bin/prlimit",
            "--nproc=256",
            "--core=0",
            "--",
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-i",
        ])
    );
    assert_eq!(SHELL_PROGRAMS.setpriv, "/usr/bin/setpriv");
    Ok(())
}


#[test]
fn the_environment_is_exactly_the_six_variables() -> TestResult {
    let account = account_in(Path::new("/home/ostyr-shell"));
    let environment = shell_environment(&account, "session-1");
    let expected: Vec<(String, String)> = [
        ("TERM", "xterm-256color"),
        ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        ("HOME", "/home/ostyr-shell"),
        ("LANG", "C.UTF-8"),
        ("HISTFILE", "/dev/null"),
        ("OSTYR_SESSION", "session-1"),
    ]
    .iter()
    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
    .collect();
    assert_eq!(environment, expected);
    Ok(())
}


#[test]
fn a_missing_program_is_named() -> TestResult {
    assert_eq!(missing_program(&SHELL_PROGRAMS), None);
    let broken = ShellPrograms {
        setpriv: SHELL,
        prlimit: "/nonexistent/prlimit",
        bash: SHELL,
    };
    assert_eq!(missing_program(&broken), Some("/nonexistent/prlimit"));
    let directory = private_tempdir()?;
    let account = account_in(directory.path());
    let refused = spawn_shell(&account, "session-1", &broken).err();
    assert_eq!(refused.as_ref().map(io::Error::kind), Some(io::ErrorKind::NotFound));
    assert_eq!(
        refused.map(|error| error.to_string()),
        Some("shell program missing: /nonexistent/prlimit".to_owned())
    );
    Ok(())
}


#[test]
fn a_chunk_is_read_until_the_end_or_the_closed_pty() -> TestResult {
    let mut buffer = vec![u8::MIN; OUTPUT_CHUNK_BYTES];
    let mut data: &[u8] = b"abc";
    assert_eq!(read_chunk(&mut data, &mut buffer).transpose()?, Some(b"abc".to_vec()));
    assert!(read_chunk(&mut data, &mut buffer).is_none());
    let mut closed = Failing { errno: Some(libc::EIO) };
    assert!(read_chunk(&mut closed, &mut buffer).is_none());
    let mut other = Failing { errno: None };
    assert!(matches!(read_chunk(&mut other, &mut buffer), Some(Err(_))));
    Ok(())
}


#[test]
fn the_output_is_cut_in_chunks_and_stops_when_the_receiver_is_gone() -> TestResult {
    let big = vec![b'x'; OUTPUT_CHUNK_BYTES * SPILL_FACTOR];
    let (sender, mut receiver) = mpsc::channel(SPILL_FACTOR);
    pump_output(&mut big.as_slice(), &sender);
    drop(sender);
    let lengths: Vec<usize> = std::iter::from_fn(|| receiver.blocking_recv())
        .map(|chunk| chunk.map(|bytes| bytes.len()))
        .collect::<io::Result<_>>()?;
    assert_eq!(lengths, vec![OUTPUT_CHUNK_BYTES, OUTPUT_CHUNK_BYTES]);
    let (gone, closed) = mpsc::channel(1);
    drop(closed);
    pump_output(&mut big.as_slice(), &gone);
    Ok(())
}


#[test]
fn the_input_is_written_until_the_queue_closes_or_a_write_fails() -> TestResult {
    let (sender, mut receiver) = mpsc::channel(SPILL_FACTOR);
    sender.try_send(b"ab".to_vec())?;
    sender.try_send(b"cd".to_vec())?;
    drop(sender);
    let mut written = Vec::new();
    write_input(&mut written, &mut receiver)?;
    assert_eq!(written, b"abcd");
    let (again, mut queued) = mpsc::channel(1);
    again.try_send(b"x".to_vec())?;
    assert!(write_input(&mut Failing { errno: None }, &mut queued).is_err());
    Ok(())
}


#[tokio::test]
async fn a_program_runs_on_a_pty_with_a_cleared_environment_and_the_given_directory() -> TestResult {
    let directory = private_tempdir()?;
    let real = std::fs::canonicalize(directory.path())?;
    let handle = spawn_pty(SHELL, &texts(&ECHO_ARGS), &[("FOO".to_owned(), "bar".to_owned())], &real)?;
    let output = String::from_utf8(transcript(handle).await)?;
    assert!(output.contains(&format!("bar:unset:{}", real.display())), "{output}");
    Ok(())
}


#[tokio::test]
async fn the_input_reaches_the_program() -> TestResult {
    let directory = private_tempdir()?;
    let handle = spawn_pty(SHELL, &texts(&READ_ARGS), &[], directory.path())?;
    handle.input.send(b"abc\n".to_vec()).await?;
    let output = String::from_utf8(transcript(handle).await)?;
    assert!(output.contains("got-abc"), "{output}");
    Ok(())
}


#[test]
fn a_program_that_cannot_start_is_an_error() -> TestResult {
    let directory = private_tempdir()?;
    assert!(spawn_pty("/nonexistent/program", &[], &[], directory.path()).is_err());
    Ok(())
}


#[tokio::test]
async fn the_shell_of_an_order_starts_through_the_blocking_pool_and_ends_on_exit() -> TestResult {
    let directory = private_tempdir()?;
    let account = ShellAccount {
        uid: NOBODY,
        gid: NOBODY,
        home: directory.path().to_path_buf(),
    };
    let direct = spawn_shell(&account, "session-1", &SHELL_PROGRAMS)?;
    direct.input.send(b"exit\n".to_vec()).await?;
    transcript(direct).await;
    let spawn = spawn_fn(account);
    let pooled = spawn(&default_order()?).await?;
    pooled.input.send(b"exit\n".to_vec()).await?;
    transcript(pooled).await;
    Ok(())
}
