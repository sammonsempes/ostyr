use crate::common::types::TestResult;
use crate::common::{setup, NOW, SEED_LENGTH};
use agent_command::cli::{
    log_dispatch, parse_action, parse_class, parse_sequence, seconds_since_epoch, signing_key_from, verify_session, write_keypair, write_signed,
};
use agent_command::error::CliError;
use agent_command::model::{Action, KeyClass};
use agent_command::sign::os_random;
use data_encoding::HEXLOWER;
use std::io::{self, BufReader, Read, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing_subscriber::fmt::writer::BoxMakeWriter;


const STORED: u64 = 3;


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("closed"))
    }
}


struct FlushFails;


impl Write for FlushFails {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush"))
    }
}


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("broken pipe"))
    }
}


fn failing_fill(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


fn fixed_now() -> u64 {
    NOW
}


fn seed_hex(seed: u8) -> String {
    HEXLOWER.encode(&[seed; SEED_LENGTH])
}


fn keypair_lines() -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    write_keypair(os_random, &mut out)?;
    let text = String::from_utf8(out)?;
    let seed = text.lines().next().ok_or("no seed")?.trim_start_matches("seed ").to_owned();
    let public = text.lines().nth(1).ok_or("no public key")?.trim_start_matches("public ").to_owned();
    Ok((seed, public))
}


fn signed_line(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    write_signed(args, NOW, os_random, &mut out)?;
    Ok(String::from_utf8(out)?)
}


#[test]
fn keygen_writes_a_consistent_pair() -> TestResult {
    let (seed, public) = keypair_lines()?;
    let derived = signing_key_from(&seed)?.verifying_key().to_bytes();
    assert_eq!(HEXLOWER.encode(&derived), public);
    assert!(matches!(write_keypair(failing_fill, &mut Vec::new()), Err(CliError::Random(_))));
    assert!(matches!(write_keypair(os_random, &mut FailingWriter), Err(CliError::Io(_))));
    Ok(())
}


#[test]
fn actions_parse_by_name() -> TestResult {
    assert_eq!(parse_action("ping", None).ok(), Some(Action::Ping));
    assert_eq!(parse_action("collect_status", None).ok(), Some(Action::CollectStatus));
    assert_eq!(parse_action("isolate", None).ok(), Some(Action::Isolate));
    assert_eq!(parse_action("uninstall", None).ok(), Some(Action::Uninstall));
    assert_eq!(
        parse_action("run_script", Some("id")).ok(),
        Some(Action::RunScript { script: "id".to_owned() })
    );
    assert_eq!(parse_action("update", Some("2")).ok(), Some(Action::Update { version: "2".to_owned() }));
    assert_eq!(
        parse_action("change_policy", Some("p")).ok(),
        Some(Action::ChangePolicy { policy: "p".to_owned() })
    );
    assert_eq!(parse_action("kill", Some("1")).ok(), Some(Action::Kill { process_id: 1 }));
    assert!(matches!(parse_action("kill", Some("x")), Err(CliError::Number(_))));
    assert!(matches!(parse_action("kill", None), Err(CliError::Number(_))));
    assert!(matches!(parse_action("format", None), Err(CliError::UnknownAction(_))));
    assert!(matches!(parse_sequence("x"), Err(CliError::Number(_))));
    assert_eq!(parse_sequence(&STORED.to_string()).ok(), Some(STORED));
    Ok(())
}


#[test]
fn seeds_are_checked() -> TestResult {
    assert!(matches!(signing_key_from("zz"), Err(CliError::Hex(_))));
    assert!(matches!(signing_key_from("abcd"), Err(CliError::Seed)));
    Ok(())
}


#[test]
fn signing_reports_usage_and_failures() -> TestResult {
    let seed = seed_hex(1);
    assert!(matches!(write_signed(&["x"], NOW, os_random, &mut Vec::new()), Err(CliError::Usage(_))));
    assert!(matches!(
        write_signed(&[&seed, "k", "routine", "a", "t", "x", "ping"], NOW, os_random, &mut Vec::new()),
        Err(CliError::Number(_))
    ));
    assert!(matches!(
        write_signed(&[&seed, "k", "routine", "a", "t", "1", "ping"], NOW, failing_fill, &mut Vec::new()),
        Err(CliError::Random(_))
    ));
    assert!(matches!(
        write_signed(&[&seed, "k", "routine", "a", "t", "1", "format"], NOW, os_random, &mut Vec::new()),
        Err(CliError::UnknownAction(_))
    ));
    assert!(matches!(
        write_signed(&["zz", "k", "routine", "a", "t", "1", "ping"], NOW, os_random, &mut Vec::new()),
        Err(CliError::Hex(_))
    ));
    assert!(matches!(
        write_signed(&[&seed, "k", "routine", "a", "t", "1", "ping"], NOW, os_random, &mut FailingWriter),
        Err(CliError::Io(_))
    ));
    Ok(())
}


#[test]
fn a_session_accepts_refuses_and_reports() -> TestResult {
    let setup = setup()?;
    let seed = seed_hex(crate::common::SENSITIVE_SEED);
    let good = signed_line(&[&seed, "sensitive-1", "sensitive", "agent-1", "acme", "1", "kill", "4"])?;
    let other = signed_line(&[&seed, "sensitive-1", "sensitive", "agent-2", "acme", "2", "ping"])?;
    let input = format!("{good}{good}{other}not hex\n");
    let mut out = Vec::new();
    verify_session(&setup.verifier, input.as_bytes(), &mut out, fixed_now)?;
    let lines: Vec<String> = String::from_utf8(out)?.lines().map(str::to_owned).collect();
    match lines.as_slice() {
        [accepted, replayed, wrong_agent, not_hex] => {
            assert_eq!(accepted, "accepted kill");
            assert!(replayed.starts_with("refused sequence number"));
            assert!(wrong_agent.starts_with("refused command addressed to another agent"));
            assert!(not_hex.starts_with("refused not hexadecimal"));
            Ok(())
        }
        _ => Err("unexpected session output".into()),
    }
}


#[test]
fn a_session_reports_io_failures() -> TestResult {
    let setup = setup()?;
    let broken = BufReader::new(FailingReader);
    assert!(matches!(
        verify_session(&setup.verifier, broken, &mut Vec::new(), fixed_now),
        Err(CliError::Io(_))
    ));
    assert!(matches!(
        verify_session(&setup.verifier, "x\n".as_bytes(), &mut FailingWriter, fixed_now),
        Err(CliError::Io(_))
    ));
    assert!(matches!(
        verify_session(&setup.verifier, "x\n".as_bytes(), &mut FlushFails, fixed_now),
        Err(CliError::Io(_))
    ));
    Ok(())
}


#[test]
fn a_clock_before_the_epoch_reads_as_zero() -> TestResult {
    let before = UNIX_EPOCH.duration_since(SystemTime::now());
    assert!(before.is_err());
    assert_eq!(seconds_since_epoch(before), 0);
    assert_eq!(seconds_since_epoch(Ok(Duration::from_secs(NOW))), NOW);
    Ok(())
}


#[derive(Clone)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);


impl Write for SharedBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn classes_parse_by_name() -> TestResult {
    assert_eq!(parse_class("routine").ok(), Some(KeyClass::Routine));
    assert_eq!(parse_class("sensitive").ok(), Some(KeyClass::Sensitive));
    assert!(matches!(parse_class("admin"), Err(CliError::Class(_))));
    let seed = seed_hex(1);
    assert!(matches!(
        write_signed(&[&seed, "k", "admin", "a", "t", "1", "ping"], NOW, os_random, &mut Vec::new()),
        Err(CliError::Class(_))
    ));
    Ok(())
}


#[test]
fn refusals_and_clock_warnings_reach_the_injected_writer() -> TestResult {
    let setup = setup()?;
    let captured = SharedBuffer(Arc::new(Mutex::new(Vec::new())));
    let sink = captured.clone();
    let dispatch = log_dispatch(BoxMakeWriter::new(move || sink.clone()));
    let before_epoch = UNIX_EPOCH.duration_since(SystemTime::now());
    tracing::dispatcher::with_default(&dispatch, || -> TestResult {
        seconds_since_epoch(before_epoch);
        verify_session(&setup.verifier, "00\n".as_bytes(), &mut Vec::new(), fixed_now)?;
        Ok(())
    })?;
    let text = String::from_utf8(captured.0.lock().unwrap_or_else(PoisonError::into_inner).clone())?;
    assert!(text.contains("system clock is before the Unix epoch"), "{text}");
    assert!(text.contains("command refused"), "{text}");
    Ok(())
}
