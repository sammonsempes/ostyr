#![cfg(unix)]

use data_encoding::BASE64_MIME;
use phishing_report::error::TriageError;
use phishing_report::isolate::{
    child_command, decide, default_isolation, default_isolation_from, exit_code, parse_child_main, payload, read_capped, reap, run_child_process,
    send_output, spawn_job, triage_isolated, write_payload, ChildRequest, Isolation, CHILD_ARGUMENT, EXIT_FAILED, EXIT_TOO_LARGE, EXIT_UNPARSABLE,
    PRLIMIT_PROGRAM, REQUEST_LINE_BYTES,
};
use phishing_report::limits::Limits;
use phishing_report::model::{ReporterPolicy, Triage};
use phishing_report::triage::triage_with;
use phishing_report::types::Job;
use std::ffi::OsStr;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{mpsc, LazyLock};
use tempfile::TempDir;
use tracing::Dispatch;


const SMALL_MAIL: &str = "From: a@example.test\r\nSubject: hello\r\n\r\nsee http://example.test/x\r\n";


const PRIVATE_MODE: u32 = 0o700;


const LOOSE_MODE: u32 = 0o777;


const EXIT_SHIFT: u32 = 8;


const CAP_BYTES: usize = 4;


const LIMIT_BYTES: usize = 1_234_567;


const FEW_POLLS: u64 = 2;


const MANY_POLLS: u64 = 500;


const FAST_GRACE_MILLIS: u64 = 30;


const SHORT_DEADLINE_MILLIS: u64 = 150;


const LONG_DEADLINE_MILLIS: u64 = 20_000;


const SMALL_OUTPUT_BYTES: usize = 1000;


const BIG_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;


const BOMB_ADDRESS_SPACE: usize = 256 * 1024 * 1024;


const BOMB_CHILDREN: usize = 240;


const BOMB_PAD_BYTES: usize = 17 * 1024 * 1024;


const PAD_LINE: usize = 78;


const CRLF_BYTES: usize = 2;


const SIGNAL_KILL: i32 = 9;


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


struct FailingRead;


impl Read for FailingRead {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read refused"))
    }
}


struct FailingWrite {
    fail_write: bool,
}


impl Write for FailingWrite {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            Err(io::Error::other("write refused"))
        } else {
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush refused"))
    }
}


fn failing_reader(_reader: &mut dyn Read, _max_bytes: usize) -> io::Result<(Vec<u8>, bool)> {
    Err(io::Error::other("pipe refused"))
}


fn trusted() -> Vec<String> {
    vec!["mx.example.test".to_owned()]
}


fn request_bytes(raw: &[u8], limits: &Limits) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let request = ChildRequest {
        trusted: trusted(),
        reporters: ReporterPolicy::default(),
        limits: limits.clone(),
    };
    let mut bytes = serde_json::to_vec(&request)?;
    bytes.push(b'\n');
    bytes.extend_from_slice(raw);
    Ok(bytes)
}


fn run_main(input: &[u8]) -> (u8, Vec<u8>) {
    let mut output = Vec::new();
    let code = parse_child_main(&mut Cursor::new(input.to_vec()), &mut output);
    (code, output)
}


fn work_dir() -> Result<TempDir, Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let parent = exe.parent().ok_or("no parent")?;
    Ok(tempfile::Builder::new()
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(PRIVATE_MODE))
        .tempdir_in(parent)?)
}


fn install_script(dir: &Path, name: &str, body: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let staged = dir.join(format!("{name}.staged"));
    let target = dir.join(name);
    std::fs::write(&staged, format!("#!/bin/sh\nulimit -c 0\n{body}\n"))?;
    let status = Command::new("install").arg("-m").arg("755").arg(&staged).arg(&target).status()?;
    assert!(status.success());
    Ok(target)
}


fn limits_for_fakes() -> Limits {
    Limits {
        child_deadline_millis: LONG_DEADLINE_MILLIS,
        ..Limits::default()
    }
}


fn run_fake(body: &str, limits: &Limits, payload: Vec<u8>) -> Result<Result<Triage, TriageError>, Box<dyn std::error::Error>> {
    let dir = work_dir()?;
    let script = install_script(dir.path(), "child.sh", body)?;
    Ok(run_child_process(
        Command::new(script),
        payload,
        limits,
        FAST_GRACE_MILLIS,
        (read_capped, spawn_job),
    ))
}


fn example_program() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(PathBuf::from(env!("CARGO_BIN_EXE_phish_triage")))
}


#[test]
fn the_binary_triages_a_file_through_its_own_child() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let dir = work_dir()?;
    let mail = dir.path().join("mail.eml");
    std::fs::write(&mail, SMALL_MAIL)?;
    let output = Command::new(example_program()?)
        .arg(&mail)
        .arg("mx.example.test")
        .arg("internal:corp.test")
        .output()?;
    let text = String::from_utf8(output.stdout)?;
    assert!(output.status.success());
    assert!(text.contains("http://example.test/x"));
    assert!(text.contains("\"reporter\""));
    let bad = Command::new(example_program()?).arg(&mail).arg("internal:-x").output()?;
    assert!(!bad.status.success());
    Ok(())
}


#[test]
fn the_binary_refuses_a_missing_argument_and_a_missing_file() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let none = Command::new(example_program()?).output()?;
    let missing = Command::new(example_program()?).arg("/nonexistent/mail.eml").output()?;
    assert!(!none.status.success());
    assert!(!missing.status.success());
    Ok(())
}


#[test]
fn a_symlinked_program_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let dir = work_dir()?;
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(example_program()?, &link)?;
    let isolation = Isolation {
        prlimit: PathBuf::from(PRLIMIT_PROGRAM),
        program: link,
    };
    assert_eq!(
        triage_isolated(SMALL_MAIL.as_bytes(), &[], &ReporterPolicy::default(), &Limits::default(), &isolation),
        Err(TriageError::ChildProgram)
    );
    Ok(())
}


fn real_isolation() -> Result<Isolation, Box<dyn std::error::Error>> {
    Ok(Isolation {
        prlimit: PathBuf::from(PRLIMIT_PROGRAM),
        program: example_program()?,
    })
}


fn exit_status(code: i32) -> ExitStatus {
    ExitStatus::from_raw(code << EXIT_SHIFT)
}


#[test]
fn the_child_entry_point_returns_the_record_of_a_message() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let limits = Limits::default();
    let (code, output) = run_main(&request_bytes(SMALL_MAIL.as_bytes(), &limits)?);
    let record: Triage = serde_json::from_slice(&output)?;
    assert_eq!(code, 0);
    assert_eq!(
        record,
        triage_with(SMALL_MAIL.as_bytes(), &trusted(), &ReporterPolicy::default(), &limits)?
    );
    Ok(())
}


#[test]
fn the_child_entry_point_names_each_failure_by_its_exit_code() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let limits = Limits::default();
    let small = Limits {
        message_bytes: SMALL_MAIL.len() - 1,
        ..limits.clone()
    };
    assert_eq!(run_main(&request_bytes(SMALL_MAIL.as_bytes(), &small)?).0, EXIT_TOO_LARGE);
    assert_eq!(run_main(&request_bytes(b"\x01\x02 not a message", &limits)?).0, EXIT_UNPARSABLE);
    assert_eq!(run_main(b"").0, EXIT_FAILED);
    assert_eq!(run_main(b"{\"trusted\":[]}").0, EXIT_FAILED);
    assert_eq!(run_main(b"{not json}\nbody").0, EXIT_FAILED);
    let long_line = vec![b'x'; REQUEST_LINE_BYTES + 1];
    assert_eq!(run_main(&long_line).0, EXIT_FAILED);
    Ok(())
}


#[test]
fn the_child_entry_point_survives_a_failing_input_and_output() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let mut output = Vec::new();
    assert_eq!(parse_child_main(&mut BufReader::new(FailingRead), &mut output), EXIT_FAILED);
    let bytes = request_bytes(SMALL_MAIL.as_bytes(), &Limits::default())?;
    let mut failing_write = FailingWrite { fail_write: true };
    assert_eq!(parse_child_main(&mut Cursor::new(bytes.clone()), &mut failing_write), EXIT_FAILED);
    let mut failing_flush = FailingWrite { fail_write: false };
    assert_eq!(parse_child_main(&mut Cursor::new(bytes), &mut failing_flush), EXIT_FAILED);
    let first_line_only = b"{\"trusted\":[],\"limits\":".to_vec();
    assert_eq!(run_main(&first_line_only).0, EXIT_FAILED);
    Ok(())
}


#[test]
fn a_failing_body_read_is_a_child_failure() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let line = request_bytes(b"", &Limits::default())?;
    let input = BufReader::new(Cursor::new(line).chain(FailingRead));
    let mut output = Vec::new();
    assert_eq!(parse_child_main(&mut { input }, &mut output), EXIT_FAILED);
    Ok(())
}


#[test]
fn exit_codes_cover_every_variant() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    assert_eq!(exit_code(TriageError::TooLarge), EXIT_TOO_LARGE);
    assert_eq!(exit_code(TriageError::Unparsable), EXIT_UNPARSABLE);
    [
        TriageError::ChildMemory,
        TriageError::ChildDeadline,
        TriageError::ChildFailed,
        TriageError::ChildOutput,
        TriageError::ChildProgram,
        TriageError::LimitsRefused,
        TriageError::PolicyRefused,
    ]
    .into_iter()
    .for_each(|error| assert_eq!(exit_code(error), EXIT_FAILED));
    Ok(())
}


#[test]
fn the_output_reader_caps_and_reports_a_cut() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let (kept, cut) = read_capped(&mut Cursor::new(b"abcdef".to_vec()), CAP_BYTES)?;
    assert_eq!((kept.as_slice(), cut), (b"abcd".as_slice(), true));
    let (whole, cut_whole) = read_capped(&mut Cursor::new(b"abcd".to_vec()), CAP_BYTES)?;
    assert_eq!((whole.as_slice(), cut_whole), (b"abcd".as_slice(), false));
    assert!(read_capped(&mut FailingRead, CAP_BYTES).is_err());
    Ok(())
}


#[test]
fn the_command_carries_the_limit_and_the_fixed_argument() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let isolation = Isolation {
        prlimit: PathBuf::from("/usr/bin/prlimit"),
        program: PathBuf::from("/opt/ostyr/phish"),
    };
    let limits = Limits {
        child_address_space: LIMIT_BYTES,
        ..Limits::default()
    };
    let command = child_command(&isolation, &limits);
    let arguments: Vec<&OsStr> = command.get_args().collect();
    assert_eq!(command.get_program(), "/usr/bin/prlimit");
    assert_eq!(arguments, ["--as=1234567", "--core=0", "--", "/opt/ostyr/phish", CHILD_ARGUMENT]);
    Ok(())
}


#[test]
fn the_default_isolation_names_prlimit_and_this_executable() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let isolation = default_isolation()?;
    assert_eq!(isolation.prlimit, PathBuf::from(PRLIMIT_PROGRAM));
    assert_eq!(isolation.program, std::env::current_exe()?);
    Ok(())
}


#[test]
fn limits_outside_their_ceilings_are_refused_before_any_process() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let isolation = Isolation {
        prlimit: PathBuf::from("/nonexistent"),
        program: PathBuf::from("/nonexistent"),
    };
    let base = Limits::default();
    let bad = [
        Limits {
            child_address_space: 0,
            ..base.clone()
        },
        Limits {
            child_address_space: usize::MAX,
            ..base.clone()
        },
        Limits {
            child_deadline_millis: 0,
            ..base.clone()
        },
        Limits {
            child_deadline_millis: u64::MAX,
            ..base.clone()
        },
        Limits {
            child_output_bytes: 0,
            ..base.clone()
        },
        Limits {
            child_output_bytes: usize::MAX,
            ..base.clone()
        },
    ];
    bad.iter().for_each(|limits| {
        assert_eq!(
            triage_isolated(SMALL_MAIL.as_bytes(), &[], &ReporterPolicy::default(), limits, &isolation),
            Err(TriageError::LimitsRefused)
        )
    });
    Ok(())
}


#[test]
fn an_oversized_message_or_request_is_refused_before_any_process() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let isolation = real_isolation().unwrap_or(Isolation {
        prlimit: PathBuf::from(PRLIMIT_PROGRAM),
        program: PathBuf::from(PRLIMIT_PROGRAM),
    });
    let small = Limits {
        message_bytes: CAP_BYTES,
        ..Limits::default()
    };
    assert_eq!(
        triage_isolated(SMALL_MAIL.as_bytes(), &[], &ReporterPolicy::default(), &small, &isolation),
        Err(TriageError::TooLarge)
    );
    let many: Vec<String> = vec!["x".repeat(REQUEST_LINE_BYTES)];
    assert_eq!(
        triage_isolated(SMALL_MAIL.as_bytes(), &many, &ReporterPolicy::default(), &Limits::default(), &isolation),
        Err(TriageError::LimitsRefused)
    );
    let bad = ReporterPolicy {
        internal_domains: vec!["-x".to_owned()],
    };
    assert_eq!(
        triage_isolated(SMALL_MAIL.as_bytes(), &[], &bad, &Limits::default(), &isolation),
        Err(TriageError::PolicyRefused)
    );
    Ok(())
}


#[test]
fn an_untrusted_program_is_refused_before_any_process() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let dir = work_dir()?;
    let loose = install_script(dir.path(), "loose.sh", "exit 0")?;
    std::fs::set_permissions(&loose, std::os::unix::fs::PermissionsExt::from_mode(LOOSE_MODE))?;
    let missing = Isolation {
        prlimit: dir.path().join("missing"),
        program: example_program()?,
    };
    let writable = Isolation {
        prlimit: PathBuf::from(PRLIMIT_PROGRAM),
        program: loose,
    };
    let relative = Isolation {
        prlimit: PathBuf::from("prlimit"),
        program: example_program()?,
    };
    [missing, writable, relative].iter().for_each(|isolation| {
        assert_eq!(
            triage_isolated(SMALL_MAIL.as_bytes(), &[], &ReporterPolicy::default(), &Limits::default(), isolation),
            Err(TriageError::ChildProgram)
        )
    });
    Ok(())
}


#[test]
fn the_real_child_triages_an_ordinary_mail_like_the_library() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let limits = Limits::default();
    let isolated = triage_isolated(SMALL_MAIL.as_bytes(), &trusted(), &ReporterPolicy::default(), &limits, &real_isolation()?)?;
    assert_eq!(
        isolated,
        triage_with(SMALL_MAIL.as_bytes(), &trusted(), &ReporterPolicy::default(), &limits)?
    );
    assert_eq!(isolated.urls.len(), 1);
    Ok(())
}


#[test]
fn the_real_child_reports_an_unparsable_and_an_oversized_message() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let isolation = real_isolation()?;
    assert_eq!(
        triage_isolated(b"\x01\x02 no", &[], &ReporterPolicy::default(), &Limits::default(), &isolation),
        Err(TriageError::Unparsable)
    );
    Ok(())
}


fn bomb_message() -> String {
    let crlf = "\r\n";
    let small = format!("From: a@b.test{crlf}Subject: s{crlf}{crlf}x");
    let children = format!("--S{crlf}Content-Type: message/rfc822{crlf}{crlf}{small}{crlf}").repeat(BOMB_CHILDREN);
    let pad = format!("{}{crlf}", "A".repeat(PAD_LINE - CRLF_BYTES)).repeat(BOMB_PAD_BYTES / PAD_LINE);
    let body = format!("{children}--S{crlf}Content-Type: application/octet-stream{crlf}{crlf}{pad}--S--{crlf}");
    let head = [
        "From: x@evil.test",
        "Subject: s",
        "MIME-Version: 1.0",
        "Content-Type: multipart/mixed; boundary=\"S\"",
    ]
    .join(crlf);
    let inner = format!("{head}{crlf}{crlf}{body}");
    let encoded = BASE64_MIME.encode(inner.as_bytes());
    let outer_head = [
        "From: employee@corp.test",
        "Subject: Fwd",
        "MIME-Version: 1.0",
        "Content-Type: multipart/mixed; boundary=\"OUT\"",
    ]
    .join(crlf);
    format!(
        "{outer_head}{crlf}{crlf}--OUT{crlf}Content-Type: text/plain{crlf}{crlf}please check{crlf}--OUT{crlf}Content-Type: application/octet-stream (x){crlf}{crlf}X-Note: y\
         --OUTContent-Type: message/rfc822{crlf}Content-Transfer-Encoding: base64{crlf}{crlf}{encoded}{crlf}--OUT--{crlf}"
    )
}


#[test]
fn a_memory_bomb_the_scan_misses_ends_as_a_child_memory_error() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let raw = bomb_message();
    let limits = Limits {
        child_address_space: BOMB_ADDRESS_SPACE,
        ..Limits::default()
    };
    assert_eq!(
        triage_isolated(raw.as_bytes(), &[], &ReporterPolicy::default(), &limits, &real_isolation()?),
        Err(TriageError::ChildMemory)
    );
    Ok(())
}


#[test]
fn a_fake_child_with_a_valid_record_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let dir = work_dir()?;
    let record = dir.path().join("record.json");
    std::fs::write(&record, serde_json::to_string(&Triage::default())?)?;
    let script = install_script(dir.path(), "ok.sh", &format!("exec /bin/cat {}", record.display()))?;
    let result = run_child_process(
        Command::new(script),
        b"x".to_vec(),
        &limits_for_fakes(),
        FAST_GRACE_MILLIS,
        (read_capped, spawn_job),
    );
    assert_eq!(result, Ok(Triage::default()));
    Ok(())
}


#[test]
fn a_child_exit_code_is_mapped_to_a_fixed_variant() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let limits = limits_for_fakes();
    assert_eq!(run_fake("exit 2", &limits, Vec::new())?, Err(TriageError::TooLarge));
    assert_eq!(run_fake("exit 3", &limits, Vec::new())?, Err(TriageError::Unparsable));
    assert_eq!(run_fake("exit 9", &limits, Vec::new())?, Err(TriageError::ChildFailed));
    assert_eq!(run_fake("kill -ABRT $$", &limits, Vec::new())?, Err(TriageError::ChildMemory));
    assert_eq!(run_fake("kill -SEGV $$", &limits, Vec::new())?, Err(TriageError::ChildFailed));
    Ok(())
}


#[test]
fn decide_reads_the_status_alone() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    assert_eq!(decide(exit_status(0), b"not json"), Err(TriageError::ChildOutput));
    assert_eq!(decide(ExitStatus::from_raw(SIGNAL_KILL), b""), Err(TriageError::ChildFailed));
    Ok(())
}


#[test]
fn malformed_output_is_a_fixed_error_without_the_marker() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let limits = limits_for_fakes();
    let marker = "SECRET-MARKER-7731";
    let wrong_type = format!("printf '{{\"sender\":\"{marker}\",\"counts\":\"{marker}\"}}'");
    let unknown_field = format!("printf '{{\"{marker}\":1}}'");
    [format!("printf '{marker} not json'"), wrong_type, unknown_field]
        .iter()
        .try_for_each(|body| {
            let result = run_fake(body, &limits, Vec::new())?;
            let error = result.err().ok_or("expected an error")?;
            assert_eq!(error, TriageError::ChildOutput);
            assert!(!format!("{error} {error:?}").contains(marker));
            Ok::<(), Box<dyn std::error::Error>>(())
        })
}


#[test]
fn a_child_writing_without_end_is_cut_at_the_output_cap() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let limits = Limits {
        child_output_bytes: SMALL_OUTPUT_BYTES,
        ..limits_for_fakes()
    };
    assert_eq!(run_fake("exec /usr/bin/yes", &limits, Vec::new())?, Err(TriageError::ChildOutput));
    Ok(())
}


#[test]
fn a_child_that_never_exits_hits_the_deadline() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let limits = Limits {
        child_deadline_millis: SHORT_DEADLINE_MILLIS,
        ..Limits::default()
    };
    assert_eq!(run_fake("exec /bin/sleep 30", &limits, Vec::new())?, Err(TriageError::ChildDeadline));
    Ok(())
}


#[test]
fn a_grandchild_holding_the_pipe_is_killed_at_the_deadline() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let limits = Limits {
        child_deadline_millis: SHORT_DEADLINE_MILLIS,
        ..Limits::default()
    };
    assert_eq!(run_fake("/bin/sleep 30 &\nexit 0", &limits, Vec::new())?, Err(TriageError::ChildDeadline));
    Ok(())
}


#[test]
fn a_child_that_closes_its_output_but_never_exits_is_killed_after_the_grace() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    assert_eq!(
        run_fake("exec >&-\nexec /bin/sleep 30", &limits_for_fakes(), Vec::new())?,
        Err(TriageError::ChildFailed)
    );
    Ok(())
}


#[test]
fn a_child_that_ignores_a_large_input_does_not_stall_the_parent() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let result = run_fake("exit 3", &limits_for_fakes(), vec![b'a'; BIG_PAYLOAD_BYTES])?;
    assert_eq!(result, Err(TriageError::Unparsable));
    Ok(())
}


#[test]
fn a_failing_pipe_read_and_a_missing_program_are_child_failures() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let dir = work_dir()?;
    let script = install_script(dir.path(), "any.sh", "exec /bin/sleep 30")?;
    let failed = run_child_process(
        Command::new(script),
        Vec::new(),
        &limits_for_fakes(),
        FAST_GRACE_MILLIS,
        (failing_reader, spawn_job),
    );
    assert_eq!(failed, Err(TriageError::ChildFailed));
    let missing = run_child_process(
        Command::new("/nonexistent/program"),
        Vec::new(),
        &limits_for_fakes(),
        FAST_GRACE_MILLIS,
        (read_capped, spawn_job),
    );
    assert_eq!(missing, Err(TriageError::ChildFailed));
    Ok(())
}


#[test]
fn reap_returns_none_while_the_child_runs() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let mut child = Command::new("/bin/sleep").arg("30").stdin(Stdio::null()).spawn()?;
    assert!(reap(&mut child, FEW_POLLS)?.is_none());
    child.kill()?;
    assert!(reap(&mut child, MANY_POLLS)?.is_some());
    assert!(reap(&mut child, 0)?.is_none());
    Ok(())
}


fn failing_spawner(_job: Job) -> io::Result<()> {
    Err(io::Error::other("no thread"))
}


#[test]
fn a_refused_helper_thread_is_a_child_failure() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let dir = work_dir()?;
    let script = install_script(dir.path(), "any.sh", "exec /bin/sleep 30")?;
    let result = run_child_process(
        Command::new(script),
        Vec::new(),
        &limits_for_fakes(),
        FAST_GRACE_MILLIS,
        (read_capped, failing_spawner),
    );
    assert_eq!(result, Err(TriageError::ChildFailed));
    Ok(())
}


fn failing_serializer(_request: &ChildRequest) -> serde_json::Result<Vec<u8>> {
    serde_json::from_str::<Vec<u8>>("not json")
}


fn failing_executable() -> io::Result<PathBuf> {
    Err(io::Error::other("no executable"))
}


#[test]
fn a_failing_serializer_or_executable_lookup_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    assert_eq!(
        payload(
            SMALL_MAIL.as_bytes(),
            &[],
            &ReporterPolicy::default(),
            &Limits::default(),
            failing_serializer
        ),
        Err(TriageError::ChildFailed)
    );
    assert_eq!(default_isolation_from(failing_executable()), Err(TriageError::ChildProgram));
    Ok(())
}


fn logged_flows() -> Result<(), Box<dyn std::error::Error>> {
    let missing = Isolation {
        prlimit: PathBuf::from("/nonexistent/prlimit"),
        program: PathBuf::from("/nonexistent/program"),
    };
    assert_eq!(
        triage_isolated(SMALL_MAIL.as_bytes(), &[], &ReporterPolicy::default(), &Limits::default(), &missing),
        Err(TriageError::ChildProgram)
    );
    let absent = run_child_process(
        Command::new("/nonexistent/program"),
        Vec::new(),
        &limits_for_fakes(),
        FAST_GRACE_MILLIS,
        (read_capped, spawn_job),
    );
    assert_eq!(absent, Err(TriageError::ChildFailed));
    assert_eq!(
        run_fake("printf garbage", &limits_for_fakes(), Vec::new())?,
        Err(TriageError::ChildOutput)
    );
    let short = Limits {
        child_deadline_millis: SHORT_DEADLINE_MILLIS,
        ..Limits::default()
    };
    assert_eq!(run_fake("exec /bin/sleep 30", &short, Vec::new())?, Err(TriageError::ChildDeadline));
    let mut sink = Vec::new();
    write_payload(&mut sink, b"payload");
    assert_eq!(sink, b"payload");
    let (sender, receiver) = mpsc::channel();
    send_output(&sender, &mut Cursor::new(b"abc".to_vec()), CAP_BYTES, read_capped);
    assert_eq!(receiver.recv()?.map_err(|error| error.to_string())?, (b"abc".to_vec(), false));
    Ok(())
}


#[test]
fn every_log_site_runs_with_a_subscriber_listening() -> Result<(), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let listening = Dispatch::new(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(std::io::sink)
            .finish(),
    );
    tracing::dispatcher::with_default(&listening, logged_flows)
}
