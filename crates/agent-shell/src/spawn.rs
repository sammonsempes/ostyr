use crate::account::ShellAccount;
use crate::model::{session_id_of, PtyHandle, VerifiedOpenShell, SHELL_COLUMNS, SHELL_ROWS};
use crate::types::SpawnFn;
use futures_util::FutureExt;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;


pub const SHELL_ACCOUNT: &str = "ostyr-shell";


pub const SETPRIV_PATH: &str = "/usr/bin/setpriv";


pub const PRLIMIT_PATH: &str = "/usr/bin/prlimit";


pub const BASH_PATH: &str = "/bin/bash";


/// Processes the account may hold at once, the shell included.
pub const SHELL_MAX_PROCESSES: u32 = 256;


pub const SHELL_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";


pub const SHELL_LANG: &str = "C.UTF-8";


pub const SHELL_TERM: &str = "xterm-256color";


pub const SHELL_HISTFILE: &str = "/dev/null";


/// Bytes read from the PTY at once.
pub const OUTPUT_CHUNK_BYTES: usize = 4096;


/// Output chunks waiting for the attach.
pub const OUTPUT_CHUNKS: usize = 16;


/// Terminal input chunks waiting for the writer thread.
pub const INPUT_CHUNKS: usize = 16;


/// The three programs of the spawn, each a fixed path: there is no fallback shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellPrograms {
    pub setpriv: &'static str,
    pub prlimit: &'static str,
    pub bash: &'static str,
}


pub const SHELL_PROGRAMS: ShellPrograms = ShellPrograms {
    setpriv: SETPRIV_PATH,
    prlimit: PRLIMIT_PATH,
    bash: BASH_PATH,
};


/// The first program that does not exist, so a missing one refuses the session by name.
pub fn missing_program(programs: &ShellPrograms) -> Option<&'static str> {
    [programs.setpriv, programs.prlimit, programs.bash]
        .into_iter()
        .find(|path| !Path::new(path).exists())
}


/// The arguments after `setpriv`: drop to the account, no new privileges, no capabilities, then the process limit, then an interactive bash without profile.
pub fn shell_args(account: &ShellAccount, programs: &ShellPrograms) -> Vec<String> {
    vec![
        format!("--reuid={}", account.uid),
        format!("--regid={}", account.gid),
        "--init-groups".to_owned(),
        "--no-new-privs".to_owned(),
        "--inh-caps=-all".to_owned(),
        "--bounding-set=-all".to_owned(),
        "--".to_owned(),
        programs.prlimit.to_owned(),
        format!("--nproc={SHELL_MAX_PROCESSES}"),
        "--core=0".to_owned(),
        "--".to_owned(),
        programs.bash.to_owned(),
        "--noprofile".to_owned(),
        "--norc".to_owned(),
        "-i".to_owned(),
    ]
}


/// The whole environment of the shell, after the agent's own is cleared.
pub fn shell_environment(account: &ShellAccount, session_id: &str) -> Vec<(String, String)> {
    vec![
        ("TERM".to_owned(), SHELL_TERM.to_owned()),
        ("PATH".to_owned(), SHELL_PATH.to_owned()),
        ("HOME".to_owned(), account.home.to_string_lossy().into_owned()),
        ("LANG".to_owned(), SHELL_LANG.to_owned()),
        ("HISTFILE".to_owned(), SHELL_HISTFILE.to_owned()),
        ("OSTYR_SESSION".to_owned(), session_id.to_owned()),
    ]
}


/// Reads one chunk: end of file and the EIO a closed PTY reports end the output, any other error is delivered once.
pub fn read_chunk(reader: &mut dyn Read, buffer: &mut [u8]) -> Option<std::io::Result<Vec<u8>>> {
    match reader.read(buffer) {
        Ok(0) => None,
        Ok(count) => buffer.get(..count).map(|filled| Ok(filled.to_vec())),
        Err(error) if error.raw_os_error() == Some(libc::EIO) => None,
        Err(error) => Some(Err(error)),
    }
}


/// Copies the shell output into the bounded channel until the end of the output or until the receiver is gone.
pub fn pump_output(reader: &mut dyn Read, output: &mpsc::Sender<std::io::Result<Vec<u8>>>) {
    let mut buffer = vec![u8::MIN; OUTPUT_CHUNK_BYTES];
    std::iter::from_fn(|| read_chunk(reader, &mut buffer))
        .try_for_each(|chunk| output.blocking_send(chunk))
        .inspect_err(|_gone| tracing::debug!("shell output receiver gone"))
        .unwrap_or(());
}


/// Writes the queued terminal input to the shell until the queue closes or a write fails.
pub fn write_input(writer: &mut dyn Write, input: &mut mpsc::Receiver<Vec<u8>>) -> std::io::Result<()> {
    std::iter::from_fn(|| input.blocking_recv()).try_for_each(|chunk| writer.write_all(&chunk).and_then(|()| writer.flush()))
}


/// Starts the program on a new PTY with the given arguments, a cleared environment and working directory; one reader thread, one writer thread, one waiter thread.
pub fn spawn_pty(program: &str, args: &[String], environment: &[(String, String)], directory: &Path) -> std::io::Result<PtyHandle> {
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: SHELL_ROWS,
            cols: SHELL_COLUMNS,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(std::io::Error::other)?;
    let mut command = CommandBuilder::new(program);
    command.args(args);
    command.env_clear();
    environment.iter().for_each(|(key, value)| command.env(key, value));
    command.cwd(directory);
    let mut child = pair.slave.spawn_command(command).map_err(std::io::Error::other)?;
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().map_err(std::io::Error::other)?;
    let mut writer = pair.master.take_writer().map_err(std::io::Error::other)?;
    let (output_sender, output) = mpsc::channel(OUTPUT_CHUNKS);
    let (input, mut input_receiver) = mpsc::channel(INPUT_CHUNKS);
    let (exit_sender, exit_receiver) = oneshot::channel::<()>();
    std::thread::spawn(move || {
        pump_output(&mut reader, &output_sender);
        drop(pair.master);
    });
    std::thread::spawn(move || {
        let ended = write_input(&mut writer, &mut input_receiver);
        tracing::debug!(?ended, "shell input writer ended");
    });
    std::thread::spawn(move || {
        let status = child.wait();
        tracing::info!(?status, "shell exited");
        drop(exit_sender);
    });
    Ok(PtyHandle {
        output: Box::pin(ReceiverStream::new(output)),
        input,
        exit: Box::pin(exit_receiver.map(|_closed| ())),
    })
}


/// Spawns the shell of an order as the account; a missing program refuses it by name.
pub fn spawn_shell(account: &ShellAccount, session_id: &str, programs: &ShellPrograms) -> std::io::Result<PtyHandle> {
    match missing_program(programs) {
        Some(path) => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("shell program missing: {path}"),
        )),
        None => spawn_pty(
            programs.setpriv,
            &shell_args(account, programs),
            &shell_environment(account, session_id),
            &account.home,
        ),
    }
}


/// The production `SpawnFn`: the blocking spawn runs on the blocking pool.
pub fn spawn_fn(shell_account: ShellAccount) -> Box<SpawnFn> {
    let shared = Arc::new(shell_account);
    Box::new(move |order: &VerifiedOpenShell| {
        let account = Arc::clone(&shared);
        let session = session_id_of(order).to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || spawn_shell(&account, &session, &SHELL_PROGRAMS))
                .await
                .map_err(std::io::Error::other)
                .and_then(std::convert::identity)
        })
    })
}
