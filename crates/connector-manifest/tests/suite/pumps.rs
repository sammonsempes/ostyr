use crate::common::types::TestResult;
use connector_manifest::error::ConnectorError;
use connector_manifest::reply::Reply;
use connector_manifest::run::{
    apply, complete, gather, log_reaping, pump_stderr, pump_stdin, pump_stdout, send_event, verdict, Cause, Event, Gathered, Reaper, StderrReport,
    GATE_RELEASE, MAX_STDERR_BYTES,
};
use std::io::{self, Cursor, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};


const CAP: usize = 4;


const SECRET_BYTES: u64 = 6;


const THIRD: usize = 2;


const FAR_SECONDS: u64 = 60;


const SETTLE_MILLISECONDS: u64 = 50;


const EXIT_THREE_CODE: i32 = 3;


const EXIT_CODE_THREE: i32 = 3 << 8;


const KILLED_BY_NINE: i32 = 9;


pub struct Failing {
    pub served: usize,
}


impl Read for Failing {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.served > 0 {
            let count = self.served.min(buffer.len());
            buffer.iter_mut().take(count).for_each(|byte| *byte = b'x');
            self.served -= count;
            Ok(count)
        } else {
            Err(io::Error::other("injected read failure"))
        }
    }
}


pub struct Sink {
    pub kind: Option<io::ErrorKind>,
    pub flush_fails: bool,
    pub bytes: Vec<u8>,
}


impl Write for Sink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self.kind {
            Some(kind) => Err(io::Error::from(kind)),
            None => {
                self.bytes.extend_from_slice(data);
                Ok(data.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.flush_fails {
            Err(io::Error::other("injected flush failure"))
        } else {
            Ok(())
        }
    }
}


fn events_of(run: impl FnOnce(&mut dyn FnMut(Event))) -> Vec<Event> {
    let mut seen = Vec::new();
    run(&mut |event| seen.push(event));
    seen
}


#[test]
fn stdout_within_the_cap_is_one_event_and_beyond_it_an_overflow_first() -> TestResult {
    let small = events_of(|send| pump_stdout(&mut Cursor::new(b"abc".to_vec()), CAP, send));
    assert!(matches!(small.as_slice(), [Event::Stdout(Ok(bytes))] if bytes == b"abc"));
    let exact = events_of(|send| pump_stdout(&mut Cursor::new(b"abcd".to_vec()), CAP, send));
    assert!(matches!(exact.as_slice(), [Event::Stdout(Ok(bytes))] if bytes == b"abcd"));
    let over = events_of(|send| pump_stdout(&mut Cursor::new(b"abcde-and-much-more".to_vec()), CAP, send));
    assert!(matches!(over.as_slice(), [Event::Overflow, Event::Stdout(Ok(bytes))] if bytes.is_empty()));
    Ok(())
}


#[test]
fn a_stdout_read_failure_is_an_event_and_a_failing_drain_is_only_logged() -> TestResult {
    let broken = events_of(|send| pump_stdout(&mut Failing { served: 0 }, CAP, send));
    assert!(matches!(broken.as_slice(), [Event::Stdout(Err(_))]));
    let drained = events_of(|send| pump_stdout(&mut Failing { served: CAP + 1 }, CAP, send));
    assert!(matches!(drained.as_slice(), [Event::Overflow, Event::Stdout(Ok(bytes))] if bytes.is_empty()));
    Ok(())
}


#[test]
fn stderr_is_counted_with_a_cut_flag_and_never_kept() -> TestResult {
    let few = events_of(|send| pump_stderr(&mut Cursor::new(b"secret".to_vec()), send));
    assert!(matches!(few.as_slice(), [Event::Stderr(Ok(report))] if *report == StderrReport { bytes: SECRET_BYTES, cut: false }));
    let many = events_of(|send| pump_stderr(&mut Cursor::new(vec![b'x'; usize::try_from(MAX_STDERR_BYTES).unwrap_or(0) + 1]), send));
    assert!(matches!(many.as_slice(), [Event::Stderr(Ok(report))] if report.cut && report.bytes == MAX_STDERR_BYTES + 1));
    let exact = events_of(|send| pump_stderr(&mut Cursor::new(vec![b'x'; usize::try_from(MAX_STDERR_BYTES).unwrap_or(0)]), send));
    assert!(matches!(exact.as_slice(), [Event::Stderr(Ok(report))] if !report.cut));
    let broken = events_of(|send| pump_stderr(&mut Failing { served: 0 }, send));
    assert!(matches!(broken.as_slice(), [Event::Stderr(Err(_))]));
    Ok(())
}


#[test]
fn stdin_gets_the_gate_byte_then_the_request_and_a_closed_pipe_is_not_an_error() -> TestResult {
    let mut sink = Sink {
        kind: None,
        flush_fails: false,
        bytes: Vec::new(),
    };
    let done = events_of(|send| pump_stdin(&mut sink, b"{}\n", send));
    assert!(matches!(done.as_slice(), [Event::Stdin(Ok(()))]));
    assert_eq!(sink.bytes, [GATE_RELEASE, b"{}\n"].concat());
    let mut closed = Sink {
        kind: Some(io::ErrorKind::BrokenPipe),
        flush_fails: false,
        bytes: Vec::new(),
    };
    assert!(matches!(
        events_of(|send| pump_stdin(&mut closed, b"x", send)).as_slice(),
        [Event::Stdin(Ok(()))]
    ));
    let mut denied = Sink {
        kind: Some(io::ErrorKind::PermissionDenied),
        flush_fails: false,
        bytes: Vec::new(),
    };
    assert!(matches!(
        events_of(|send| pump_stdin(&mut denied, b"x", send)).as_slice(),
        [Event::Stdin(Err(_))]
    ));
    let mut unflushed = Sink {
        kind: None,
        flush_fails: true,
        bytes: Vec::new(),
    };
    assert!(matches!(
        events_of(|send| pump_stdin(&mut unflushed, b"x", send)).as_slice(),
        [Event::Stdin(Err(_))]
    ));
    Ok(())
}


fn status(raw: i32) -> ExitStatus {
    ExitStatus::from_raw(raw)
}


fn finished(stdout: &[u8], exit: Option<Option<ExitStatus>>) -> Gathered {
    Gathered {
        stdout: Some(stdout.to_vec()),
        stderr: Some(StderrReport::default()),
        stdin_done: true,
        exit,
        cause: None,
    }
}


#[test]
fn every_event_is_applied_once_and_a_failure_sets_the_first_cause_only() -> TestResult {
    let state = [
        Event::Stdout(Ok(b"x".to_vec())),
        Event::Stderr(Ok(StderrReport::default())),
        Event::Stdin(Ok(())),
        Event::Exit(Ok(status(0))),
    ]
    .into_iter()
    .fold(Gathered::default(), apply);
    assert!(complete(&state) && state.cause.is_none());
    let overflow = apply(Gathered::default(), Event::Overflow);
    assert!(matches!(overflow.cause, Some(Cause::Overflow)));
    let first = apply(overflow, Event::Stdout(Err(io::Error::other("later"))));
    assert!(matches!(first.cause, Some(Cause::Overflow)) && first.stdout.is_some());
    let failures = [
        apply(Gathered::default(), Event::Stderr(Err(io::Error::other("e")))),
        apply(Gathered::default(), Event::Stdin(Err(io::Error::other("e")))),
        apply(Gathered::default(), Event::Exit(Err(io::Error::other("e")))),
    ];
    assert!(failures.iter().all(|failed| matches!(failed.cause, Some(Cause::Pipe(_)))));
    assert!(failures.first().is_some_and(|failed| failed.stderr.is_some()));
    assert!(failures.get(1).is_some_and(|failed| failed.stdin_done));
    assert!(failures.get(THIRD).is_some_and(|failed| matches!(failed.exit, Some(None))));
    Ok(())
}


#[test]
fn gather_stops_when_complete_on_a_cause_or_at_the_limit() -> TestResult {
    let (sender, events) = channel();
    let far = Instant::now() + Duration::from_secs(FAR_SECONDS);
    [
        Event::Stdout(Ok(Vec::new())),
        Event::Stderr(Ok(StderrReport::default())),
        Event::Stdin(Ok(())),
        Event::Exit(Ok(status(0))),
    ]
    .into_iter()
    .try_for_each(|event| sender.send(event))?;
    assert!(complete(&gather(&events, Gathered::default(), far, true)));
    sender.send(Event::Overflow)?;
    sender.send(Event::Stdin(Ok(())))?;
    let stopped = gather(&events, Gathered::default(), far, true);
    assert!(matches!(stopped.cause, Some(Cause::Overflow)) && !stopped.stdin_done);
    let drained = gather(&events, stopped, Instant::now() + Duration::from_millis(SETTLE_MILLISECONDS), false);
    assert!(drained.stdin_done);
    let expired = gather(&events, Gathered::default(), Instant::now(), true);
    assert!(matches!(expired.cause, Some(Cause::Timeout)));
    let kept = gather(&events, apply(Gathered::default(), Event::Overflow), Instant::now(), false);
    assert!(matches!(kept.cause, Some(Cause::Overflow)));
    Ok(())
}


#[test]
fn the_verdict_reads_the_cause_then_the_exit_then_the_reply() -> TestResult {
    let ok = verdict(finished(br#"{"status":"ok","result":1}"#, Some(Some(status(0)))))?;
    assert!(matches!(ok.reply, Reply::Success { .. }));
    assert!(matches!(
        verdict(finished(b"{}", Some(Some(status(EXIT_CODE_THREE))))),
        Err(ConnectorError::RunFailed { code: Some(EXIT_THREE_CODE) })
    ));
    assert!(matches!(
        verdict(finished(b"{}", Some(Some(status(KILLED_BY_NINE))))),
        Err(ConnectorError::RunFailed { code: None })
    ));
    assert!(matches!(
        verdict(finished(b"nonsense", Some(Some(status(0))))),
        Err(ConnectorError::MalformedReply)
    ));
    assert!(matches!(verdict(finished(b"{}", None)), Err(ConnectorError::RunTimeout)));
    assert!(matches!(verdict(finished(b"{}", Some(None))), Err(ConnectorError::RunTimeout)));
    assert!(matches!(verdict(Gathered::default()), Err(ConnectorError::RunTimeout)));
    let causes = [
        (Cause::Overflow, "overflow"),
        (Cause::Timeout, "timeout"),
        (Cause::Pipe(io::Error::other("pipe")), "pipe"),
    ];
    causes.into_iter().try_for_each(|(cause, label)| {
        let verdict = verdict(Gathered {
            cause: Some(cause),
            ..finished(b"{}", Some(Some(status(0))))
        });
        match (label, verdict) {
            ("overflow", Err(ConnectorError::ReplyTooLarge { .. })) => Ok(()),
            ("timeout", Err(ConnectorError::RunTimeout)) => Ok(()),
            ("pipe", Err(ConnectorError::Pipe(_))) => Ok(()),
            (other, result) => Err(format!("{other}: {result:?}")),
        }
    })?;
    Ok(())
}


#[test]
fn a_closed_receiver_a_failed_reap_and_a_failed_reaper_are_logged_not_fatal() -> TestResult {
    let (sender, events) = channel();
    drop(events);
    send_event(&sender, Event::Overflow);
    log_reaping(Ok(()), Ok(status(0)));
    log_reaping(Err(io::Error::other("kill")), Err(io::Error::other("wait")));
    let empty = tempfile::tempdir()?;
    let handle = std::fs::File::open(empty.path())?;
    let reaper = Reaper {
        host: &crate::support::kill_host(),
        leaf: std::os::fd::AsFd::as_fd(&handle),
        run_uid: crate::support::RUN_UID,
    };
    drop(reaper);
    Ok(())
}
