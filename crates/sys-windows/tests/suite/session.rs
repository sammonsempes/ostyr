use crate::types::TestResult;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;
use sys_windows::console::{session_environment, INPUT_CHUNK_BYTES};
use sys_windows::session::{
    close_console, job_limits, process_id, read_output, resize_console, shell_in_job, spawn_session, spawn_session_with, write_input, Session,
    ACTIVE_PROCESS_LIMIT, INHERIT_HANDLES,
};
use sys_windows::test_probes::{holds_inheritable_pipe, process_is_running};
use sys_windows::types::ConsoleError;


const WAIT_SECONDS: u64 = 60;


const HELPER_SECONDS: u64 = 600;


const POLL_MILLIS: u64 = 100;


const POLL_ATTEMPTS: u32 = 300;


const MAX_CHUNKS: u32 = 4_000;


const MAX_READS: usize = 1_000_000;


const ESCAPE: char = '\u{1b}';


const BELL: char = '\u{7}';


const COLUMNS: u32 = 120;


const ROWS: u32 = 30;


const LABEL: &str = "t875b";


const PING_COMMAND: &[u8] = b"ping -t 127.0.0.1\r\n";


const DETACHED_PING: &[u8] =
    b"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -Command \"Start-Process ping -ArgumentList '-t','127.0.0.1'\"\r\n";


const SUM_COMMAND: &[u8] = b"set /a 12345*3\r\n";


const SUM_RESULT: &str = "37035";


const CMD_OWN_VARIABLE: &str = "PROMPT";


const KILL_ON_JOB_CLOSE: u32 = 0x2000;


const DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x400;


const ACTIVE_PROCESS: u32 = 0x8;


const BREAKAWAY_OK: u32 = 0x800;


const SILENT_BREAKAWAY_OK: u32 = 0x1000;


const FAULT_CODE_BASE: u32 = 0;


const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;


const BREAKAWAY_MARKER: &str = "breakaway-result=";


const INHERIT_MARKER: &str = "inherit-probe=";


const SPAWNER_MARKER: &str = "spawner-saw=";


fn fault_with_the_process_id(process_id_value: u32) -> Result<(), u32> {
    Err(FAULT_CODE_BASE + process_id_value)
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


fn read_until(receiver: &Receiver<Vec<u8>>, seen: &mut String, needle: &str) -> TestResult {
    let mut chunks = 0;
    while !seen.contains(needle) && chunks < MAX_CHUNKS {
        chunks += 1;
        let chunk = receiver.recv_timeout(Duration::from_secs(WAIT_SECONDS))?;
        seen.push_str(&String::from_utf8_lossy(&chunk));
    }
    assert!(seen.contains(needle), "{needle} not in {seen:?}");
    Ok(())
}


#[derive(Clone, Copy)]
enum Escape {
    Text,
    Started,
    Csi,
    Osc,
}


fn strip_escapes(text: &str) -> String {
    let (clean, _) = text.chars().fold((String::new(), Escape::Text), |(mut kept, state), character| {
        let next = match (state, character) {
            (Escape::Text, ESCAPE) => Escape::Started,
            (Escape::Text, _) => {
                kept.push(character);
                Escape::Text
            }
            (Escape::Started, '[') => Escape::Csi,
            (Escape::Started, ']') => Escape::Osc,
            (Escape::Started, _) => Escape::Text,
            (Escape::Csi, value) if value.is_ascii_alphabetic() || value == '~' => Escape::Text,
            (Escape::Csi, _) => Escape::Csi,
            (Escape::Osc, BELL) => Escape::Text,
            (Escape::Osc, _) => Escape::Osc,
        };
        (kept, next)
    });
    clean
}


fn ping_pids() -> Result<BTreeSet<u32>, Box<dyn std::error::Error>> {
    let output = Command::new("tasklist")
        .args(["/fi", "imagename eq ping.exe", "/fo", "csv", "/nh"])
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(text
        .lines()
        .filter_map(|line| line.split(',').nth(1))
        .filter_map(|field| field.trim_matches('"').parse::<u32>().ok())
        .collect())
}


fn wait_for_pids(before: &BTreeSet<u32>) -> Result<BTreeSet<u32>, Box<dyn std::error::Error>> {
    let found = (0..POLL_ATTEMPTS).find_map(|_| {
        std::thread::sleep(Duration::from_millis(POLL_MILLIS));
        ping_pids()
            .ok()
            .map(|now| now.difference(before).copied().collect::<BTreeSet<u32>>())
            .filter(|new| !new.is_empty())
    });
    Ok(found.ok_or("no ping process appeared")?)
}


fn wait_until_gone(process_ids: &BTreeSet<u32>) -> bool {
    (0..POLL_ATTEMPTS)
        .find_map(|_| {
            std::thread::sleep(Duration::from_millis(POLL_MILLIS));
            process_ids.iter().all(|value| !process_is_running(*value)).then_some(())
        })
        .is_some()
}


#[test]
fn a_shell_computes_a_sum_and_the_result_is_read_back() -> TestResult {
    let session = spawn_session(COLUMNS, ROWS, LABEL)?;
    std::thread::scope(|scope| -> TestResult {
        let receiver = start_reader(&session, scope);
        write_input(&session, SUM_COMMAND)?;
        let mut seen = String::new();
        read_until(&receiver, &mut seen, SUM_RESULT)?;
        close_console(&session)?;
        Ok(())
    })?;
    assert!(!process_is_running(process_id(&session)));
    Ok(())
}


#[test]
fn the_shell_environment_is_exactly_the_fixed_list() -> TestResult {
    let session = spawn_session(COLUMNS, ROWS, LABEL)?;
    let transcript = std::thread::scope(|scope| -> Result<String, Box<dyn std::error::Error>> {
        let receiver = start_reader(&session, scope);
        write_input(&session, b"set\r\n")?;
        let mut seen = String::new();
        read_until(&receiver, &mut seen, "windir=")?;
        write_input(&session, SUM_COMMAND)?;
        read_until(&receiver, &mut seen, SUM_RESULT)?;
        close_console(&session)?;
        Ok(seen)
    })?;
    let clean = strip_escapes(&transcript);
    let listed = clean
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.split_once('=')
                .is_some_and(|(name, _)| !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
        })
        .filter(|line| !line.starts_with("set"))
        .map(str::to_string)
        .collect::<BTreeSet<String>>();
    let system = "C:\\Windows\\System32";
    let windows = "C:\\Windows";
    let block = session_environment(system, windows, LABEL)?;
    let expected = block
        .split(|unit| *unit == 0)
        .map(String::from_utf16_lossy)
        .filter(|line| !line.is_empty())
        .collect::<BTreeSet<String>>();
    let names = |lines: &BTreeSet<String>| {
        lines
            .iter()
            .filter_map(|line| line.split_once('=').map(|pair| pair.0.to_ascii_uppercase()))
            .collect::<BTreeSet<String>>()
    };
    let mut expected_names = names(&expected);
    expected_names.insert(CMD_OWN_VARIABLE.to_string());
    assert_eq!(names(&listed), expected_names, "{listed:?}");
    assert!(listed.contains(&format!("OSTYR_SESSION={LABEL}")), "{listed:?}");
    Ok(())
}


#[test]
fn closing_ends_the_shell_and_a_second_close_is_refused() -> TestResult {
    let session = spawn_session(COLUMNS, ROWS, LABEL)?;
    assert!(process_is_running(process_id(&session)));
    close_console(&session)?;
    assert!(!process_is_running(process_id(&session)));
    assert!(matches!(close_console(&session), Err(ConsoleError::AlreadyClosed)));
    assert!(matches!(resize_console(&session, COLUMNS, ROWS), Err(ConsoleError::AlreadyClosed)));
    Ok(())
}


#[test]
fn a_reader_blocked_in_a_read_ends_with_the_close() -> TestResult {
    let session = spawn_session(COLUMNS, ROWS, LABEL)?;
    std::thread::scope(|scope| -> TestResult {
        let receiver = start_reader(&session, scope);
        write_input(&session, SUM_COMMAND)?;
        let mut seen = String::new();
        read_until(&receiver, &mut seen, SUM_RESULT)?;
        close_console(&session)?;
        let drained = (0..MAX_CHUNKS).try_fold(0, |total, _| {
            receiver.recv_timeout(Duration::from_secs(WAIT_SECONDS)).map(|chunk| total + chunk.len())
        });
        assert!(matches!(drained, Err(std::sync::mpsc::RecvTimeoutError::Disconnected)));
        Ok(())
    })
}


#[test]
fn grandchildren_are_gone_after_the_close() -> TestResult {
    for command in [PING_COMMAND, DETACHED_PING] {
        let before = ping_pids()?;
        let session = spawn_session(COLUMNS, ROWS, LABEL)?;
        write_input(&session, command)?;
        let started = wait_for_pids(&before)?;
        assert!(started.iter().all(|value| process_is_running(*value)));
        close_console(&session)?;
        assert!(wait_until_gone(&started), "{started:?} still running");
    }
    Ok(())
}


#[test]
fn a_failing_assignment_refuses_the_session_and_kills_the_child() -> TestResult {
    let refused = spawn_session_with(COLUMNS, ROWS, LABEL, fault_with_the_process_id)
        .err()
        .ok_or("accepted")?;
    let child = Some(refused)
        .and_then(|error| match error {
            ConsoleError::Windows {
                operation: "AssignProcessToJobObject",
                code,
            } => Some(code),
            _ => None,
        })
        .ok_or("the refusal is not an assignment error")?;
    assert!(child > 0);
    assert!(wait_until_gone(&BTreeSet::from([child])));
    Ok(())
}


#[test]
fn the_shell_runs_inside_a_job_with_the_fixed_limits() -> TestResult {
    let session = spawn_session(COLUMNS, ROWS, LABEL)?;
    assert!(shell_in_job(&session)?);
    let (flags, active) = job_limits(&session)?;
    assert_eq!(
        flags & (KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION | ACTIVE_PROCESS),
        KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION | ACTIVE_PROCESS
    );
    assert_eq!(flags & (BREAKAWAY_OK | SILENT_BREAKAWAY_OK), 0);
    assert_eq!(active, ACTIVE_PROCESS_LIMIT);
    Ok(())
}


#[test]
fn the_spawn_never_inherits_handles() -> TestResult {
    assert!(!std::hint::black_box(INHERIT_HANDLES));
    Ok(())
}


#[test]
fn a_flooding_shell_dropped_unread_returns() -> TestResult {
    let session = spawn_session(COLUMNS, ROWS, LABEL)?;
    write_input(&session, b"for /l %i in (1,1,100000000) do @echo flood-%i\r\n")?;
    let pid = process_id(&session);
    drop(session);
    assert!(!process_is_running(pid));
    Ok(())
}


#[test]
fn sizes_and_inputs_outside_the_bounds_are_refused_by_name() -> TestResult {
    assert!(matches!(spawn_session(0, ROWS, LABEL).err(), Some(ConsoleError::BadSize { .. })));
    assert!(matches!(
        spawn_session(COLUMNS, ROWS, "-bad").err(),
        Some(ConsoleError::BadSessionLabel { .. })
    ));
    let session = spawn_session(COLUMNS, ROWS, LABEL)?;
    assert!(matches!(resize_console(&session, 0, ROWS), Err(ConsoleError::BadSize { .. })));
    resize_console(&session, COLUMNS + 1, ROWS + 1)?;
    let big = vec![b'a'; INPUT_CHUNK_BYTES + 1];
    assert!(matches!(write_input(&session, &big), Err(ConsoleError::InputTooLarge { .. })));
    Ok(())
}


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


fn helper_command(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    Ok(format!("\"{}\" --ignored --exact session::{name} --nocapture", executable.display()))
}


fn marker_value(transcript: &str, marker: &str) -> Option<String> {
    strip_escapes(transcript)
        .lines()
        .filter_map(|line| line.split_once(marker).map(|pair| pair.1.trim().to_string()))
        .next()
}


#[test]
#[ignore = "helper started by a_breakaway_from_inside_the_session_is_refused"]
fn breakaway_probe() -> TestResult {
    let started = Command::new("whoami.exe").creation_flags(CREATE_BREAKAWAY_FROM_JOB).spawn();
    let verdict = match started {
        Ok(mut child) => {
            child.wait()?;
            "started".to_string()
        }
        Err(error) => format!("refused-{}", error.raw_os_error().unwrap_or(0)),
    };
    writeln!(std::io::stdout(), "{BREAKAWAY_MARKER}{verdict}")?;
    Ok(())
}


#[test]
fn a_breakaway_from_inside_the_session_is_refused() -> TestResult {
    let session = spawn_session(COLUMNS, ROWS, LABEL)?;
    let verdict = std::thread::scope(|scope| -> Result<String, Box<dyn std::error::Error>> {
        let receiver = start_reader(&session, scope);
        write_input(&session, format!("{}\r\n", helper_command("breakaway_probe")?).as_bytes())?;
        let mut seen = String::new();
        read_until(&receiver, &mut seen, BREAKAWAY_MARKER)?;
        read_until(&receiver, &mut seen, "\n")?;
        close_console(&session)?;
        Ok(seen)
    })?;
    let value = marker_value(&verdict, BREAKAWAY_MARKER).ok_or("no breakaway verdict")?;
    assert_eq!(value, "refused-5");
    Ok(())
}


#[test]
#[ignore = "helper started by the_shell_does_not_inherit_a_handle_of_its_parent"]
fn inheritance_spawner() -> TestResult {
    let value = std::io::stdout().as_raw_handle().addr();
    let session = spawn_session(COLUMNS, ROWS, LABEL)?;
    let seen = std::thread::scope(|scope| -> Result<String, Box<dyn std::error::Error>> {
        let receiver = start_reader(&session, scope);
        write_input(&session, format!("{} {value}\r\n", helper_command("inheritance_probe")?).as_bytes())?;
        let mut collected = String::new();
        read_until(&receiver, &mut collected, INHERIT_MARKER)?;
        read_until(&receiver, &mut collected, "\n")?;
        close_console(&session)?;
        Ok(collected)
    })?;
    let verdict = marker_value(&seen, INHERIT_MARKER).ok_or("no probe verdict")?;
    writeln!(std::io::stdout(), "{SPAWNER_MARKER}{verdict}")?;
    Ok(())
}


#[test]
#[ignore = "helper started by inheritance_spawner inside the session"]
fn inheritance_probe() -> TestResult {
    let value = std::env::args()
        .filter_map(|argument| argument.parse::<usize>().ok())
        .next()
        .ok_or("no handle value")?;
    let verdict = if holds_inheritable_pipe(value) { "open" } else { "closed" };
    writeln!(std::io::stdout(), "{INHERIT_MARKER}{verdict}")?;
    Ok(())
}


#[test]
fn the_shell_does_not_inherit_a_handle_of_its_parent() -> TestResult {
    let text = run_guarded(&["--ignored", "--exact", "session::inheritance_spawner", "--nocapture"])?;
    let verdict = marker_value(&text, SPAWNER_MARKER).ok_or_else(|| format!("no spawner verdict in {text:?}"))?;
    assert_eq!(verdict, "closed", "{text}");
    Ok(())
}
