#![cfg(windows)]
use std::error::Error;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Duration;
use sys_windows::session::{close_console, read_output, spawn_session, write_input, Session};
use sys_windows::types::ConsoleError;


const WAIT_SECONDS: u64 = 60;


const MAX_CHUNKS: u32 = 4_000;


const MAX_READS: usize = 1_000_000;


const COLUMNS: u32 = 120;


const ROWS: u32 = 30;


const LABEL: &str = "t875b";


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
    let output = Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", "pipe_holder_attack", "--nocapture"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let dups = marker_value(&text, HOLDER_MARKER).ok_or_else(|| format!("no holder verdict in {text:?}"))?;
    assert!(dups.parse::<u32>()? > 0, "{text}");
    let verdict = marker_value(&text, CLOSE_MARKER).ok_or_else(|| format!("no close verdict in {text:?}"))?;
    assert_eq!(verdict, "timeout", "{text}");
    Ok(())
}
