#![cfg(windows)]
use std::error::Error;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Duration;
use sys_windows::session::{close_console, read_output, resize_console, spawn_session, write_input, Session};
use sys_windows::types::ConsoleError;


const WAIT_SECONDS: u64 = 60;


const HELPER_SECONDS: u64 = 600;


const MAX_CHUNKS: u32 = 4_000;


const MAX_READS: usize = 1_000_000;


const COLUMNS: u32 = 120;


const ROWS: u32 = 30;


const LABEL: &str = "t875b";


const MAX_RESIZES: u32 = 5_000;


const SIZE_VARIANTS: u32 = 2;


const BLOCKED_SECONDS: u64 = 5;


const RESIZE_SECONDS: u64 = 30;


const FLOOD_MARKER: &str = "flood=";


const RESIZE_AFTER_MARKER: &str = "resize-after=";


const SUSPEND_SCRIPT: &str = "$sig = 'using System; using System.Runtime.InteropServices; public static class Sp { \
[DllImport(\"ntdll.dll\")] public static extern int NtSuspendProcess(IntPtr h); \
[DllImport(\"ntdll.dll\")] public static extern int NtResumeProcess(IntPtr h); \
[DllImport(\"kernel32.dll\")] public static extern IntPtr OpenProcess(uint a, bool i, uint p); }'\r\n\
Add-Type -TypeDefinition $sig\r\n\
$owner = [uint32]$args[0]\r\n\
$mode = $args[1]\r\n\
$count = 0\r\n\
foreach ($c in (Get-CimInstance Win32_Process -Filter \"Name='conhost.exe'\" | Where-Object { $_.ParentProcessId -eq $owner })) {\r\n\
  $h = [Sp]::OpenProcess(0x800, $false, [uint32]$c.ProcessId)\r\n\
  if ($mode -eq 'suspend') { [void][Sp]::NtSuspendProcess($h) } else { [void][Sp]::NtResumeProcess($h) }\r\n\
  $count++\r\n\
}\r\n\
Write-Output \"conhost-$mode=$count\"\r\n";


const HOLDER_MARKER: &str = "holder-dup=";


const CLOSE_MARKER: &str = "close-result=";


const CLOSE_SECONDS: u64 = 120;


const HOLDER_SCRIPT: &str = "$sig = 'using System; using System.Runtime.InteropServices; public static class Dup { \
[DllImport(\"kernel32.dll\")] public static extern IntPtr OpenProcess(uint a, bool i, uint p); \
[DllImport(\"kernel32.dll\")] public static extern bool DuplicateHandle(IntPtr sp, IntPtr sh, IntPtr tp, out IntPtr th, uint a, bool i, uint o); }'\r\n\
Add-Type -TypeDefinition $sig\r\n\
$owner = [uint32]$args[0]\r\n\
$target = [Dup]::OpenProcess(0x40, $false, $owner)\r\n\
$count = 0\r\n\
foreach ($c in (Get-CimInstance Win32_Process -Filter \"Name='conhost.exe'\" | Where-Object { $_.ParentProcessId -eq $owner })) {\r\n\
  $src = [Dup]::OpenProcess(0x40, $false, [uint32]$c.ProcessId)\r\n\
  for ($h = 4; $h -lt 4096; $h += 4) { $out = [IntPtr]::Zero; if ([Dup]::DuplicateHandle($src, [IntPtr]$h, $target, [ref]$out, 0, $false, 2)) { $count++ } }\r\n\
}\r\n\
Write-Output \"holder-dup=$count\"\r\n";


struct ChildGuard(Child);


impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Err(error) = self.0.kill() {
            tracing::debug!(%error, "the helper had already ended");
        }
        if let Err(error) = self.0.wait() {
            tracing::warn!(%error, "reaping the helper failed");
        }
    }
}


fn run_guarded(arguments: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let mut guard = ChildGuard(
        Command::new(std::env::current_exe()?)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let mut stdout = guard.0.stdout.take().ok_or("no helper stdout")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = stdout.read_to_end(&mut bytes).map(|_| bytes);
        if let Err(error) = sender.send(read) {
            tracing::debug!(%error, "the test stopped waiting for the helper");
        }
    });
    let bytes = receiver.recv_timeout(Duration::from_secs(HELPER_SECONDS))??;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}


fn start_reader<'scope>(session: &'scope Session, scope: &'scope std::thread::Scope<'scope, '_>) -> Receiver<Vec<u8>> {
    let (sender, receiver) = channel();
    scope.spawn(move || {
        std::iter::repeat_with(|| {
            read_output(session)
                .ok()
                .filter(|chunk| !chunk.is_empty())
                .and_then(|chunk| sender.send(chunk).ok())
        })
        .take(MAX_READS)
        .map_while(|delivered| delivered)
        .for_each(drop);
    });
    receiver
}


fn read_until(receiver: &Receiver<Vec<u8>>, seen: &mut String, needle: &str) -> Result<(), Box<dyn Error>> {
    let mut chunks = 0;
    while !seen.contains(needle) && chunks < MAX_CHUNKS {
        chunks += 1;
        let chunk = receiver.recv_timeout(Duration::from_secs(WAIT_SECONDS))?;
        seen.push_str(&String::from_utf8_lossy(&chunk));
    }
    assert!(seen.contains(needle), "{needle} not in {seen:?}");
    Ok(())
}


fn marker_value(transcript: &str, marker: &str) -> Option<String> {
    transcript
        .lines()
        .filter_map(|line| line.split_once(marker).map(|pair| pair.1.trim().to_string()))
        .next()
}


#[test]
#[ignore = "helper started by a_duplicated_pipe_end_cannot_hang_the_close"]
fn pipe_holder_attack() -> Result<(), Box<dyn Error>> {
    let script = std::env::temp_dir().join(format!("holder-{}.ps1", std::process::id()));
    std::fs::write(&script, HOLDER_SCRIPT)?;
    let session = Arc::new(spawn_session(COLUMNS, ROWS, LABEL)?);
    let command = format!(
        "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"{}\" {}\r\n",
        script.display(),
        std::process::id()
    );
    let mut seen = String::new();
    std::thread::scope(|scope| -> Result<(), Box<dyn Error>> {
        let receiver = start_reader(&session, scope);
        write_input(&session, command.as_bytes())?;
        let waited = read_until(&receiver, &mut seen, HOLDER_MARKER).and_then(|()| read_until(&receiver, &mut seen, "\n"));
        let (sender, closed) = channel();
        let closing = Arc::clone(&session);
        std::thread::spawn(move || sender.send(close_console(&closing).err()));
        let verdict = match closed.recv_timeout(Duration::from_secs(CLOSE_SECONDS)) {
            Ok(Some(ConsoleError::CloseTimeout { .. })) => "timeout".to_string(),
            Ok(Some(other)) => format!("other-{other}"),
            Ok(None) => "ok".to_string(),
            Err(_) => "hung".to_string(),
        };
        writeln!(std::io::stdout(), "{CLOSE_MARKER}{verdict}")?;
        waited
    })?;
    let dups = marker_value(&seen, HOLDER_MARKER).ok_or("no duplicate count")?;
    writeln!(std::io::stdout(), "{HOLDER_MARKER}{dups}")?;
    Ok(())
}


#[test]
fn a_duplicated_pipe_end_cannot_hang_the_close() -> Result<(), Box<dyn Error>> {
    let text = run_guarded(&["--ignored", "--exact", "pipe_holder_attack", "--nocapture"])?;
    let dups = marker_value(&text, HOLDER_MARKER).ok_or_else(|| format!("no holder verdict in {text:?}"))?;
    assert!(dups.parse::<u32>()? > 0, "{text}");
    let verdict = marker_value(&text, CLOSE_MARKER).ok_or_else(|| format!("no close verdict in {text:?}"))?;
    assert_eq!(verdict, "timeout", "{text}");
    Ok(())
}


fn signal_conhost(script: &std::path::Path, mode: &str) -> Result<(), Box<dyn Error>> {
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(script)
        .arg(std::process::id().to_string())
        .arg(mode)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()?;
    assert!(status.success());
    Ok(())
}


fn verdict_of<Value: Send + 'static>(work: impl FnOnce() -> Value + Send + 'static, seconds: u64) -> Option<Value> {
    let (sender, receiver) = channel();
    std::thread::spawn(move || sender.send(work()));
    receiver.recv_timeout(Duration::from_secs(seconds)).ok()
}


#[test]
#[ignore = "helper started by a_resize_flood_against_a_stalled_console_cannot_hang_the_close"]
fn resize_flood_attack() -> Result<(), Box<dyn Error>> {
    let script = std::env::temp_dir().join(format!("suspend-{}.ps1", std::process::id()));
    std::fs::write(&script, SUSPEND_SCRIPT)?;
    let session = Arc::new(spawn_session(COLUMNS, ROWS, LABEL)?);
    let (progress_sender, progress) = channel();
    let flooder = Arc::clone(&session);
    std::thread::scope(|scope| -> Result<(), Box<dyn Error>> {
        signal_conhost(&script, "suspend")?;
        scope.spawn(move || {
            (0..MAX_RESIZES)
                .map(|step| resize_console(&flooder, COLUMNS, ROWS + step % SIZE_VARIANTS))
                .map_while(Result::ok)
                .for_each(|()| {
                    if let Err(error) = progress_sender.send(()) {
                        tracing::debug!(%error, "the test stopped counting resizes");
                    }
                });
        });
        let flood = (0..MAX_RESIZES)
            .try_for_each(|_| progress.recv_timeout(Duration::from_secs(BLOCKED_SECONDS)))
            .map_or_else(|error| format!("{error:?}"), |()| "finished".to_string());
        writeln!(std::io::stdout(), "{FLOOD_MARKER}{flood}")?;
        let closing = Arc::clone(&session);
        let closed = verdict_of(move || close_console(&closing).err(), CLOSE_SECONDS);
        let verdict = match closed {
            Some(Some(ConsoleError::CloseTimeout { .. })) => "timeout".to_string(),
            Some(Some(other)) => format!("other-{other}"),
            Some(None) => "ok".to_string(),
            None => "hung".to_string(),
        };
        writeln!(std::io::stdout(), "{CLOSE_MARKER}{verdict}")?;
        let resizing = Arc::clone(&session);
        let after = match verdict_of(move || resize_console(&resizing, COLUMNS, ROWS), RESIZE_SECONDS) {
            Some(Err(ConsoleError::AlreadyClosed)) => "refused".to_string(),
            Some(other) => format!("other-{other:?}"),
            None => "hung".to_string(),
        };
        writeln!(std::io::stdout(), "{RESIZE_AFTER_MARKER}{after}")?;
        signal_conhost(&script, "resume")
    })?;
    Ok(())
}


#[test]
fn a_resize_flood_against_a_stalled_console_cannot_hang_the_close() -> Result<(), Box<dyn Error>> {
    let text = run_guarded(&["--ignored", "--exact", "resize_flood_attack", "--nocapture"])?;
    let flood = marker_value(&text, FLOOD_MARKER).ok_or_else(|| format!("no flood verdict in {text:?}"))?;
    assert_eq!(flood, "Timeout", "{text}");
    let closed = marker_value(&text, CLOSE_MARKER).ok_or_else(|| format!("no close verdict in {text:?}"))?;
    assert_eq!(closed, "timeout", "{text}");
    let after = marker_value(&text, RESIZE_AFTER_MARKER).ok_or_else(|| format!("no resize verdict in {text:?}"))?;
    assert_eq!(after, "refused", "{text}");
    Ok(())
}
