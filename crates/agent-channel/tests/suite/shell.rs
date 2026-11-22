use crate::harness::bounded;
use crate::services::{agent_identity, counter, settings};
use crate::shell_rig::{
    approve, attach, bounded_end, close_frame, data_frame, drained, empty_frame, ended_with, exited, keepalive_frame, next_event, open_frame,
    resize_frame, rig, rig_with, until_ended, Behavior, Rig, MAX_SECONDS, SESSION, START_DEADLINE,
};
use crate::types::TestResult;
use agent_channel::limits::{admit_request, open_slot, open_stream};
use agent_channel::model::{
    AgentCloseReason, AgentFrame, GateError, Identity, ShellEnd, ShellInput, ShellSinkEvent, SlotKind, MAX_SHELL_BYTES_PER_SESSION,
    MAX_SHELL_FRAMES_PER_SECOND, MAX_SHELL_FRAMES_PER_SESSION, MAX_SHELL_FRAME_BYTES, MAX_SHELL_MESSAGE_BYTES, MAX_SHELL_SESSIONS,
    SHELL_OPEN_SECONDS,
};
use agent_channel::proto::shell_frame::Frame;
use agent_channel::proto::{ShellCloseReason, ShellFrame};
use agent_channel::shell::{agent_close_reason, agent_frame, end_status, fresh_meter, input_frame, meter_frame, open_metered_shell, open_shell};
use agent_channel::shell_gate::{gate_add, gate_has_pending, gate_take, lock_gate, new_gate};
use agent_channel::types::ShellStream;
use futures_util::{stream, StreamExt};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tonic::{Code, Status};


const RACERS: usize = 16;


const RACE_ROUNDS: usize = 64;


const ESCAPE_ID: &str = "\u{1b}[31mmarker";


const LONG_ID_BYTES: usize = 10_240;


const FLOOD_FRAMES: usize = 1_001;


const AFTER_LIFETIME_SECONDS: u64 = 41;


const SHORT_SESSION_SECONDS: u64 = 10;


const PAST_DEADLINE: u64 = START_DEADLINE + 1;


const UNKNOWN_REASON: i32 = 99;


const WIDTH: u32 = 120;


const HEIGHT: u32 = 40;


const TOO_WIDE: u32 = 1_001;


const BAD_FIRSTS: u64 = 8;


const EXTRA_INPUTS: usize = 2;


const SMALL_WINDOW_LIMIT: u32 = 3;


const LONG_WINDOW_SECONDS: u64 = 3_600;


const FRAME_OVERHEAD: u64 = 16;


const PADDED_WIRE_BYTES: usize = 60_000;


const SESSION_LIMIT: usize = 64;


const TOP_CELLS: u32 = 1_000;


const MARKER_TEXT: &str = "marker";


fn expect_status<Value>(outcome: Result<Value, Status>) -> Result<Status, Box<dyn std::error::Error>> {
    match outcome {
        Err(status) => Ok(status),
        Ok(_) => Err("expected a refusal".into()),
    }
}


#[tokio::test]
async fn an_approved_session_streams_both_ways_through_the_sink_and_source() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let mut attached = attach(&rig, vec![open_frame(SESSION), data_frame(b"ls\n"), keepalive_frame()]).await?;
    assert_eq!(next_event(&mut rig).await?, ShellSinkEvent::Output(b"ls\n".to_vec()));
    assert_eq!(next_event(&mut rig).await?, ShellSinkEvent::Tick);
    rig.input.send(ShellInput::Data(b"whoami\n".to_vec())).await?;
    rig.input.send(ShellInput::Resize { cols: WIDTH, rows: HEIGHT }).await?;
    let first = bounded(attached.response.next()).await?;
    let second = bounded(attached.response.next()).await?;
    assert_eq!(first.and_then(|item| item.ok()), Some(data_frame(b"whoami\n")));
    assert_eq!(second.and_then(|item| item.ok()), Some(resize_frame(WIDTH, HEIGHT)));
    attached.frames.send(Ok(exited())).await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::AgentClosed(AgentCloseReason::Exited));
    assert!(drained(attached.response).await?.is_empty());
    assert_eq!(counter(&rig.state.counters.shell_opened), 1);
    assert_eq!(lock_gate(&rig.shell.gate).active, 0);
    Ok(())
}


#[tokio::test]
async fn an_attach_without_a_pending_session_is_refused_before_a_slot_or_a_frame() -> TestResult {
    let rig = rig();
    let status = expect_status(attach(&rig, vec![open_frame(SESSION)]).await)?;
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(counter(&rig.state.counters.shell_unexpected), 1);
    assert_eq!(counter(&rig.state.counters.shell_gate_refused), 0);
    assert!(open_slot(&rig.state, &agent_identity(), SlotKind::Shell).is_ok());
    Ok(())
}


#[tokio::test]
async fn a_session_approved_for_another_agent_is_refused() -> TestResult {
    let rig = rig();
    gate_add(&rig.shell.gate, "acme", "agent-2", SESSION, START_DEADLINE, MAX_SECONDS)?;
    let status = expect_status(attach(&rig, vec![open_frame(SESSION)]).await)?;
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(counter(&rig.state.counters.shell_unexpected), 1);
    assert!(gate_has_pending(
        &rig.shell.gate,
        &Identity {
            tenant: "acme".to_string(),
            agent_id: "agent-2".to_string()
        }
    ));
    Ok(())
}


#[tokio::test]
async fn the_same_session_id_under_another_tenant_is_refused_and_stays_pending() -> TestResult {
    let rig = rig();
    gate_add(&rig.shell.gate, "other", "agent-1", SESSION, START_DEADLINE, MAX_SECONDS)?;
    let status = expect_status(attach(&rig, vec![open_frame(SESSION)]).await)?;
    assert_eq!(status.code(), Code::PermissionDenied);
    approve(&rig, "session-2")?;
    let status_2 = expect_status(attach(&rig, vec![open_frame(SESSION)]).await)?;
    assert_eq!(status_2.code(), Code::PermissionDenied);
    assert_eq!(counter(&rig.state.counters.shell_gate_refused), 1);
    assert!(gate_has_pending(
        &rig.shell.gate,
        &Identity {
            tenant: "other".to_string(),
            agent_id: "agent-1".to_string()
        }
    ));
    Ok(())
}


#[tokio::test]
async fn a_session_past_its_start_deadline_is_refused_at_the_attach_and_at_the_take() -> TestResult {
    let rig = rig();
    approve(&rig, SESSION)?;
    rig.unix.store(PAST_DEADLINE, Ordering::Relaxed);
    let status = expect_status(attach(&rig, vec![open_frame(SESSION)]).await)?;
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(counter(&rig.state.counters.shell_unexpected), 1);
    rig.unix.store(0, Ordering::Relaxed);
    approve(&rig, "session-late")?;
    let (reached_sender, reached) = oneshot::channel();
    let (release_sender, release) = oneshot::channel::<()>();
    let inbound = stream::once(async move {
        let announced = reached_sender.send(());
        let released = release.await;
        (announced, released, Ok(open_frame("session-late")))
    })
    .map(|(_announced, _released, frame)| frame);
    let state = Arc::clone(&rig.state);
    let shell = Arc::clone(&rig.shell);
    let pending = tokio::spawn(async move { open_shell(state, shell, Ok(agent_identity()), inbound).await.map(|_response| ()) });
    reached.await?;
    rig.unix.store(PAST_DEADLINE, Ordering::Relaxed);
    release_sender.send(()).map_err(|()| "task gone")?;
    let status_2 = expect_status(pending.await?)?;
    assert_eq!(status_2.code(), Code::PermissionDenied);
    assert_eq!(counter(&rig.state.counters.shell_gate_refused), 1);
    assert_eq!(counter(&rig.state.counters.shell_unexpected), 1);
    Ok(())
}


#[tokio::test]
async fn a_used_session_id_is_refused_by_the_gate() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    approve(&rig, "session-2")?;
    let first = attach(&rig, vec![open_frame(SESSION)]).await?;
    first.frames.send(Ok(exited())).await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::AgentClosed(AgentCloseReason::Exited));
    drained(first.response).await?;
    let status = expect_status(attach(&rig, vec![open_frame(SESSION)]).await)?;
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(counter(&rig.state.counters.shell_gate_refused), 1);
    Ok(())
}


#[test]
fn two_racing_takes_of_one_session_give_exactly_one_winner() -> TestResult {
    let gate = new_gate(Box::new(|| 0));
    (0..RACE_ROUNDS).try_for_each(|round| {
        let session = format!("race-{round}");
        gate_add(&gate, "acme", "agent-1", &session, START_DEADLINE, MAX_SECONDS)?;
        let start = std::sync::Barrier::new(RACERS);
        let winners = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..RACERS)
                .map(|_racer| {
                    scope.spawn(|| {
                        start.wait();
                        gate_take(&gate, &agent_identity(), &session).is_some()
                    })
                })
                .collect();
            handles.into_iter().filter_map(|handle| handle.join().ok()).filter(|won| *won).count()
        });
        assert_eq!(winners, 1);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[tokio::test]
async fn a_second_attach_while_one_runs_is_limited_by_the_shell_slot() -> TestResult {
    let rig = rig();
    approve(&rig, SESSION)?;
    approve(&rig, "session-2")?;
    let first = attach(&rig, vec![open_frame(SESSION)]).await?;
    let status = expect_status(attach(&rig, vec![open_frame("session-2")]).await)?;
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(counter(&rig.state.counters.shell_limited), 1);
    drop(first);
    Ok(())
}


#[tokio::test]
async fn the_shell_slot_is_apart_from_the_events_streams() -> TestResult {
    let rig = rig_with(settings(|base| base.max_streams_per_agent = 1), Behavior::Record);
    let held = open_stream(&rig.state, &agent_identity())?;
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION)]).await?;
    assert!(open_stream(&rig.state, &agent_identity()).is_err());
    drop((held, attached));
    Ok(())
}


#[tokio::test]
async fn the_request_rate_is_checked_before_the_gate() -> TestResult {
    let rig = rig_with(settings(|base| base.max_requests_per_window = 0), Behavior::Record);
    let status = expect_status(attach(&rig, vec![open_frame(SESSION)]).await)?;
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(counter(&rig.state.counters.shell_unexpected), 0);
    Ok(())
}


#[tokio::test]
async fn a_request_without_an_identity_is_refused() -> TestResult {
    let rig = rig();
    let outcome = open_shell(
        Arc::clone(&rig.state),
        Arc::clone(&rig.shell),
        Err(Status::unauthenticated("none")),
        stream::empty(),
    )
    .await;
    assert_eq!(expect_status(outcome)?.code(), Code::Unauthenticated);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_stream_with_no_open_frame_ends_at_the_open_deadline() -> TestResult {
    let rig = rig();
    approve(&rig, SESSION)?;
    let outcome = open_shell(
        Arc::clone(&rig.state),
        Arc::clone(&rig.shell),
        Ok(agent_identity()),
        stream::pending::<Result<ShellFrame, Status>>(),
    )
    .await;
    assert_eq!(expect_status(outcome)?.code(), Code::DeadlineExceeded);
    assert_eq!(counter(&rig.state.counters.shell_open_timeouts), 1);
    assert_eq!(counter(&rig.state.counters.shell_opened), 0);
    assert!(open_slot(&rig.state, &agent_identity(), SlotKind::Shell).is_ok());
    const { assert!(SHELL_OPEN_SECONDS <= agent_channel::model::DEFAULT_REQUEST_TIMEOUT_SECONDS) };
    Ok(())
}


#[tokio::test]
async fn every_malformed_first_frame_is_refused_with_a_fixed_status() -> TestResult {
    let long_id = "a".repeat(LONG_ID_BYTES);
    let bad_firsts = vec![
        empty_frame(),
        data_frame(b"early"),
        keepalive_frame(),
        resize_frame(1, 1),
        exited(),
        open_frame(ESCAPE_ID),
        open_frame(&long_id),
        open_frame(""),
    ];
    let rig = rig();
    approve(&rig, SESSION)?;
    for first in bad_firsts {
        let status = expect_status(attach(&rig, vec![first]).await)?;
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "malformed shell open");
    }
    assert_eq!(counter(&rig.state.counters.shell_malformed), BAD_FIRSTS);
    assert!(gate_has_pending(&rig.shell.gate, &agent_identity()));
    Ok(())
}


#[tokio::test]
async fn a_stream_that_ends_before_its_open_frame_is_malformed() -> TestResult {
    let rig = rig();
    approve(&rig, SESSION)?;
    let outcome = open_shell(Arc::clone(&rig.state), Arc::clone(&rig.shell), Ok(agent_identity()), stream::empty()).await;
    assert_eq!(expect_status(outcome)?.code(), Code::InvalidArgument);
    Ok(())
}


#[tokio::test]
async fn a_transport_error_before_the_open_frame_is_counted_and_refused() -> TestResult {
    let rig = rig();
    approve(&rig, SESSION)?;
    let outcome = open_shell(
        Arc::clone(&rig.state),
        Arc::clone(&rig.shell),
        Ok(agent_identity()),
        stream::iter(vec![Err(Status::out_of_range("too large"))]),
    )
    .await;
    assert_eq!(expect_status(outcome)?.code(), Code::InvalidArgument);
    assert_eq!(counter(&rig.state.counters.oversized), 1);
    Ok(())
}


async fn malformed_run(bad: ShellFrame) -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION), data_frame(b"ok"), bad, data_frame(b"after")]).await?;
    let events = until_ended(&mut rig).await?;
    assert_eq!(
        events,
        vec![ShellSinkEvent::Output(b"ok".to_vec()), ShellSinkEvent::Ended(ShellEnd::Malformed)]
    );
    let received = drained(attached.response).await?;
    let status = expect_status(received.into_iter().next().ok_or("no item")?)?;
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(status.message(), "malformed shell frame");
    assert_eq!(counter(&rig.state.counters.shell_malformed), 1);
    Ok(())
}


#[tokio::test]
async fn a_frame_with_no_member_ends_the_stream() -> TestResult {
    malformed_run(empty_frame()).await
}


#[tokio::test]
async fn a_resize_from_the_agent_ends_the_stream() -> TestResult {
    malformed_run(resize_frame(WIDTH, HEIGHT)).await
}


#[tokio::test]
async fn a_second_open_ends_the_stream() -> TestResult {
    malformed_run(open_frame(SESSION)).await
}


#[tokio::test]
async fn an_empty_data_frame_ends_the_stream() -> TestResult {
    malformed_run(data_frame(b"")).await
}


#[tokio::test]
async fn a_data_frame_above_the_bound_ends_the_stream() -> TestResult {
    malformed_run(data_frame(&vec![0; MAX_SHELL_FRAME_BYTES + 1])).await
}


#[tokio::test]
async fn an_unknown_close_reason_ends_the_stream() -> TestResult {
    malformed_run(close_frame(UNKNOWN_REASON)).await
}


#[tokio::test]
async fn an_unspecified_close_reason_ends_the_stream() -> TestResult {
    malformed_run(close_frame(0)).await
}


#[tokio::test]
async fn an_agent_never_claims_a_platform_close_reason() -> TestResult {
    malformed_run(close_frame(i32::from(ShellCloseReason::RecordingFailed))).await
}


#[tokio::test]
async fn an_agent_error_close_is_reported_to_the_sink() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION), close_frame(i32::from(ShellCloseReason::AgentError))]).await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::AgentClosed(AgentCloseReason::AgentError));
    assert!(drained(attached.response).await?.is_empty());
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_keepalive_flood_ends_the_session_and_leaves_the_window_of_other_calls() -> TestResult {
    let mut rig = rig_with(
        settings(|base| {
            base.max_requests_per_window = SMALL_WINDOW_LIMIT;
            base.rate_window_seconds = LONG_WINDOW_SECONDS;
        }),
        Behavior::Record,
    );
    approve(&rig, SESSION)?;
    let mut first = vec![open_frame(SESSION)];
    first.extend((0..FLOOD_FRAMES).map(|_flood| keepalive_frame()));
    let attached = attach(&rig, first).await?;
    let events = until_ended(&mut rig).await?;
    let ticks = events.iter().filter(|event| **event == ShellSinkEvent::Tick).count();
    assert_eq!(ticks, usize::try_from(MAX_SHELL_FRAMES_PER_SECOND)?);
    assert_eq!(events.last(), Some(&ShellSinkEvent::Ended(ShellEnd::Budget)));
    assert_eq!(counter(&rig.state.counters.shell_budget), 1);
    let status = expect_status(drained(attached.response).await?.into_iter().next().ok_or("no item")?)?;
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert!(admit_request(&rig.state, &agent_identity()).is_ok());
    assert!(admit_request(&rig.state, &agent_identity()).is_ok());
    assert_eq!(counter(&rig.state.counters.rate_limited), 0);
    Ok(())
}


#[test]
fn the_budgets_count_frames_bytes_and_a_window_apart() -> TestResult {
    let now = Instant::now();
    let fresh = fresh_meter(now);
    let busy = agent_channel::model::ShellMeter {
        window_frames: MAX_SHELL_FRAMES_PER_SECOND,
        ..fresh
    };
    assert_eq!(meter_frame(busy, now, 1).err(), Some("frames per second"));
    assert_eq!(
        meter_frame(busy, now + Duration::from_secs(1), 1).map(|meter| meter.window_frames).ok(),
        Some(1)
    );
    let full = agent_channel::model::ShellMeter {
        frames: MAX_SHELL_FRAMES_PER_SESSION,
        ..fresh
    };
    assert_eq!(meter_frame(full, now, 1).err(), Some("frames per session"));
    let heavy = agent_channel::model::ShellMeter {
        bytes: MAX_SHELL_BYTES_PER_SESSION,
        ..fresh
    };
    assert_eq!(meter_frame(heavy, now, 1).err(), Some("bytes per session"));
    assert_eq!(meter_frame(fresh, now, 1).map(|meter| (meter.frames, meter.bytes)).ok(), Some((1, 1)));
    Ok(())
}


#[test]
fn the_constants_agree_with_the_remote_shell_recording_bounds() -> TestResult {
    const RECORDING_FRAME_BYTES: usize = 65_536;
    const RECORDING_BYTES: u64 = 268_435_456;
    const RECORDING_FRAMES: u64 = 10_000_000;
    assert_eq!(MAX_SHELL_FRAME_BYTES, RECORDING_FRAME_BYTES);
    assert!(MAX_SHELL_BYTES_PER_SESSION.saturating_add(MAX_SHELL_FRAMES_PER_SESSION.saturating_mul(FRAME_OVERHEAD)) <= RECORDING_BYTES);
    const { assert!(MAX_SHELL_FRAMES_PER_SESSION <= RECORDING_FRAMES) };
    let largest = ShellFrame {
        frame: Some(Frame::Data(vec![0; MAX_SHELL_FRAME_BYTES])),
    };
    assert_eq!(prost::Message::encoded_len(&largest), MAX_SHELL_MESSAGE_BYTES);
    assert_eq!(MAX_SHELL_SESSIONS, SESSION_LIMIT);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_stuck_sink_ends_the_session_at_its_deadline() -> TestResult {
    let mut rig = rig_with(settings(|_base| ()), Behavior::Hang);
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION), keepalive_frame()]).await?;
    assert_eq!(next_event(&mut rig).await?, ShellSinkEvent::Tick);
    let status = expect_status(drained(attached.response).await?.into_iter().next().ok_or("no item")?)?;
    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(counter(&rig.state.counters.shell_sink_timeouts), 1);
    Ok(())
}


#[tokio::test]
async fn a_failing_sink_ends_the_session_without_a_second_call() -> TestResult {
    let mut rig = rig_with(settings(|_base| ()), Behavior::FailAll);
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION), data_frame(b"x")]).await?;
    let status = expect_status(drained(attached.response).await?.into_iter().next().ok_or("no item")?)?;
    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(counter(&rig.state.counters.shell_sink_failed), 1);
    assert_eq!(next_event(&mut rig).await?, ShellSinkEvent::Output(b"x".to_vec()));
    assert!(rig.events.try_recv().is_err());
    Ok(())
}


#[tokio::test]
async fn a_sink_that_fails_the_end_notice_is_logged_and_the_status_still_goes_out() -> TestResult {
    let mut rig = rig_with(settings(|_base| ()), Behavior::FailEnded);
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION), empty_frame()]).await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::Malformed);
    let status = expect_status(drained(attached.response).await?.into_iter().next().ok_or("no item")?)?;
    assert_eq!(status.code(), Code::InvalidArgument);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn an_agent_that_never_reads_ends_the_session_at_the_send_deadline() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION)]).await?;
    let queued = agent_channel::model::SHELL_OUTBOUND_CAPACITY + EXTRA_INPUTS;
    (0..queued).try_for_each(|_item| rig.input.try_send(ShellInput::Data(b"x".to_vec())))?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::SendTimeout);
    assert_eq!(counter(&rig.state.counters.shell_send_timeouts), 1);
    drop(attached);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn an_agent_silent_for_the_dead_interval_is_closed() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION)]).await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::Dead);
    assert_eq!(counter(&rig.state.counters.shell_dead), 1);
    let status = expect_status(drained(attached.response).await?.into_iter().next().ok_or("no item")?)?;
    assert_eq!(status.code(), Code::DeadlineExceeded);
    drop(attached.frames);
    Ok(())
}


#[tokio::test]
async fn keepalives_past_the_lifetime_end_the_session() -> TestResult {
    let mut rig = rig();
    gate_add(&rig.shell.gate, "acme", "agent-1", SESSION, START_DEADLINE, SHORT_SESSION_SECONDS)?;
    let attached = attach(&rig, vec![open_frame(SESSION), keepalive_frame()]).await?;
    assert_eq!(next_event(&mut rig).await?, ShellSinkEvent::Tick);
    rig.offset.store(AFTER_LIFETIME_SECONDS, Ordering::Relaxed);
    attached.frames.send(Ok(keepalive_frame())).await?;
    attached.frames.send(Ok(exited())).await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::Lifetime);
    assert_eq!(counter(&rig.state.counters.shell_lifetime), 1);
    let status = expect_status(drained(attached.response).await?.into_iter().next().ok_or("no item")?)?;
    assert_eq!(status.code(), Code::DeadlineExceeded);
    Ok(())
}


#[tokio::test]
async fn a_closed_input_stream_ends_the_session_as_dropped() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION)]).await?;
    drop(attached.frames);
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::Dropped);
    assert!(drained(attached.response).await?.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_transport_failure_inside_the_session_is_counted_and_ends_it() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION)]).await?;
    attached.frames.send(Err(Status::out_of_range("too large"))).await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::Oversized);
    assert_eq!(counter(&rig.state.counters.oversized), 1);
    let status = expect_status(drained(attached.response).await?.into_iter().next().ok_or("no item")?)?;
    assert_eq!(status.code(), Code::OutOfRange);
    Ok(())
}


#[tokio::test]
async fn a_dropped_response_stream_does_not_stop_the_status_path_from_ending_the_session() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION), empty_frame()]).await?;
    drop(attached.response);
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::Malformed);
    Ok(())
}


#[tokio::test]
async fn platform_input_for_a_dropped_response_stream_ends_the_session_as_dropped() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION)]).await?;
    drop(attached.response);
    rig.input.send(ShellInput::Data(b"x".to_vec())).await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::Dropped);
    drop(attached.frames);
    Ok(())
}


#[tokio::test]
async fn the_platform_input_is_checked_before_it_reaches_the_agent() -> TestResult {
    let bad_inputs = vec![
        ShellInput::Data(Vec::new()),
        ShellInput::Data(vec![0; MAX_SHELL_FRAME_BYTES + 1]),
        ShellInput::Resize { cols: 0, rows: HEIGHT },
        ShellInput::Resize { cols: WIDTH, rows: 0 },
        ShellInput::Resize {
            cols: TOO_WIDE,
            rows: HEIGHT,
        },
        ShellInput::Resize { cols: WIDTH, rows: TOO_WIDE },
    ];
    for bad in bad_inputs {
        let mut rig = rig();
        approve(&rig, SESSION)?;
        let attached = attach(&rig, vec![open_frame(SESSION)]).await?;
        rig.input.send(bad).await?;
        assert_eq!(ended_with(&mut rig).await?, ShellEnd::Malformed);
        let status = expect_status(drained(attached.response).await?.into_iter().next().ok_or("no item")?)?;
        assert_eq!(status.code(), Code::InvalidArgument);
    }
    assert_eq!(
        input_frame(ShellInput::Resize { cols: 1, rows: 1 }),
        Some(crate::shell_rig::resize_frame(1, 1))
    );
    assert_eq!(
        input_frame(ShellInput::Resize {
            cols: TOP_CELLS,
            rows: TOP_CELLS
        }),
        Some(crate::shell_rig::resize_frame(TOP_CELLS, TOP_CELLS))
    );
    Ok(())
}


#[tokio::test]
async fn a_platform_close_is_forwarded_and_ends_the_session() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION)]).await?;
    rig.input.send(ShellInput::Close(ShellCloseReason::RecordingFailed)).await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::PlatformClosed);
    let received = drained(attached.response).await?;
    assert_eq!(received.len(), 1);
    assert_eq!(
        received.first().and_then(|item| item.as_ref().ok()),
        Some(&close_frame(i32::from(ShellCloseReason::RecordingFailed)))
    );
    Ok(())
}


#[tokio::test]
async fn an_ended_source_closes_the_session_toward_the_agent() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION)]).await?;
    drop(rig.input);
    let ended = bounded_end(&mut rig.events).await?;
    assert_eq!(ended, ShellEnd::PlatformClosed);
    let received = drained(attached.response).await?;
    assert_eq!(
        received.first().and_then(|item| item.as_ref().ok()),
        Some(&close_frame(i32::from(ShellCloseReason::UserClose)))
    );
    drop(attached.frames);
    Ok(())
}


#[test]
fn the_gate_refuses_a_full_table_a_bad_id_and_a_duplicate_and_prunes_the_expired() -> TestResult {
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let reader = Arc::clone(&clock);
    let gate = new_gate(Box::new(move || reader.load(Ordering::Relaxed)));
    assert_eq!(
        gate_add(&gate, "acme", "agent-1", "-bad", START_DEADLINE, 1),
        Err(GateError::InvalidSessionId)
    );
    gate_add(&gate, "acme", "agent-1", SESSION, START_DEADLINE, 1)?;
    assert_eq!(gate_add(&gate, "acme", "agent-1", SESSION, START_DEADLINE, 1), Err(GateError::Duplicate));
    (1..MAX_SHELL_SESSIONS).try_for_each(|index| gate_add(&gate, "acme", "agent-1", &format!("fill-{index}"), START_DEADLINE, 1))?;
    assert_eq!(gate_add(&gate, "acme", "agent-1", "one-more", START_DEADLINE, 1), Err(GateError::Full));
    clock.store(PAST_DEADLINE, Ordering::Relaxed);
    assert!(!gate_has_pending(&gate, &agent_identity()));
    gate_add(&gate, "acme", "agent-1", "after-prune", PAST_DEADLINE, 1)?;
    assert_eq!(lock_gate(&gate).pending.len(), 1);
    Ok(())
}


#[test]
fn an_active_session_counts_against_the_gate_until_it_is_dropped() -> TestResult {
    let gate = new_gate(Box::new(|| 0));
    gate_add(&gate, "acme", "agent-1", SESSION, START_DEADLINE, 1)?;
    let taken = gate_take(&gate, &agent_identity(), SESSION).ok_or("not taken")?;
    assert_eq!(taken.max_seconds, 1);
    assert_eq!(lock_gate(&gate).active, 1);
    (1..MAX_SHELL_SESSIONS).try_for_each(|index| gate_add(&gate, "acme", "agent-1", &format!("fill-{index}"), START_DEADLINE, 1))?;
    assert_eq!(gate_add(&gate, "acme", "agent-1", "one-more", START_DEADLINE, 1), Err(GateError::Full));
    drop(taken);
    assert_eq!(lock_gate(&gate).active, 0);
    gate_add(&gate, "acme", "agent-1", "one-more", START_DEADLINE, 1)?;
    Ok(())
}


#[test]
fn a_take_matches_the_whole_identity() -> TestResult {
    let gate = new_gate(Box::new(|| 0));
    gate_add(&gate, "acme", "agent-1", SESSION, START_DEADLINE, 1)?;
    let other = Identity {
        tenant: "other".to_string(),
        agent_id: "agent-1".to_string(),
    };
    assert!(gate_take(&gate, &other, SESSION).is_none());
    assert!(gate_take(&gate, &agent_identity(), SESSION).is_some());
    assert!(gate_take(&gate, &agent_identity(), SESSION).is_none());
    Ok(())
}


#[test]
fn every_end_has_a_fixed_status_or_none() -> TestResult {
    let silent = [
        ShellEnd::AgentClosed(AgentCloseReason::Exited),
        ShellEnd::PlatformClosed,
        ShellEnd::Dropped,
        ShellEnd::SendTimeout,
        ShellEnd::Transport,
    ];
    assert!(silent.iter().all(|end| end_status(*end).is_none()));
    let codes: Vec<Option<Code>> = [
        ShellEnd::Dead,
        ShellEnd::Lifetime,
        ShellEnd::Budget,
        ShellEnd::Malformed,
        ShellEnd::Oversized,
        ShellEnd::SinkTimeout,
        ShellEnd::SinkFailed,
    ]
    .iter()
    .map(|end| end_status(*end).map(|status| status.code()))
    .collect();
    assert_eq!(
        codes,
        vec![
            Some(Code::DeadlineExceeded),
            Some(Code::DeadlineExceeded),
            Some(Code::ResourceExhausted),
            Some(Code::InvalidArgument),
            Some(Code::OutOfRange),
            Some(Code::Unavailable),
            Some(Code::Unavailable),
        ]
    );
    assert!(end_status(ShellEnd::Malformed).is_some_and(|status| !status.message().contains(MARKER_TEXT)));
    Ok(())
}


#[test]
fn the_agent_frame_table_admits_only_data_keepalive_and_agent_closes() -> TestResult {
    assert_eq!(agent_frame(data_frame(b"x")), Some(AgentFrame::Data(b"x".to_vec())));
    assert_eq!(agent_frame(keepalive_frame()), Some(AgentFrame::Keepalive));
    assert_eq!(agent_frame(exited()), Some(AgentFrame::Close(AgentCloseReason::Exited)));
    assert_eq!(
        agent_frame(data_frame(&vec![0; MAX_SHELL_FRAME_BYTES])).map(|frame| matches!(frame, AgentFrame::Data(_))),
        Some(true)
    );
    assert!(agent_frame(open_frame(SESSION)).is_none());
    assert!(agent_frame(resize_frame(1, 1)).is_none());
    assert!(agent_close_reason(i32::from(ShellCloseReason::UserClose)).is_none());
    Ok(())
}


#[tokio::test]
async fn a_transport_failure_other_than_a_size_refusal_ends_as_transport() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let attached = attach(&rig, vec![open_frame(SESSION)]).await?;
    attached.frames.send(Err(Status::unavailable("reset"))).await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::Transport);
    assert_eq!(counter(&rig.state.counters.oversized), 0);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_silent_session_ends_at_its_lifetime_on_a_timer() -> TestResult {
    let mut rig = rig();
    gate_add(&rig.shell.gate, "acme", "agent-1", SESSION, START_DEADLINE, SHORT_SESSION_SECONDS)?;
    let attached = attach(&rig, vec![open_frame(SESSION)]).await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::Lifetime);
    assert_eq!(counter(&rig.state.counters.shell_lifetime), 1);
    assert_eq!(counter(&rig.state.counters.shell_dead), 0);
    let status = expect_status(drained(attached.response).await?.into_iter().next().ok_or("no item")?)?;
    assert_eq!(status.code(), Code::DeadlineExceeded);
    Ok(())
}


async fn attach_wire(rig: &Rig, frames: Vec<(ShellFrame, usize)>) -> Result<ShellStream, Status> {
    let (sender, receiver) = tokio::sync::mpsc::channel(frames.len() + 1);
    frames
        .into_iter()
        .try_for_each(|item| sender.try_send(Ok(item)).map_err(|_| Status::internal("test channel full")))?;
    let response = open_metered_shell(
        Arc::clone(&rig.state),
        Arc::clone(&rig.shell),
        Ok(agent_identity()),
        tokio_stream::wrappers::ReceiverStream::new(receiver),
    )
    .await?;
    Ok(response.into_inner())
}


#[tokio::test]
async fn a_frame_whose_wire_length_differs_from_its_decoded_one_ends_the_session() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let open = open_frame(SESSION);
    let open_length = prost::Message::encoded_len(&open);
    let keepalive = keepalive_frame();
    let _response = attach_wire(
        &rig,
        vec![
            (open, open_length),
            (keepalive.clone(), PADDED_WIRE_BYTES),
            (keepalive.clone(), prost::Message::encoded_len(&keepalive)),
        ],
    )
    .await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::Malformed);
    assert_eq!(counter(&rig.state.counters.shell_malformed), 1);
    Ok(())
}


#[tokio::test]
async fn a_frame_with_a_missing_wire_length_is_refused() -> TestResult {
    let mut rig = rig();
    approve(&rig, SESSION)?;
    let open = open_frame(SESSION);
    let open_length = prost::Message::encoded_len(&open);
    let _response = attach_wire(&rig, vec![(open, open_length), (keepalive_frame(), usize::MAX)]).await?;
    assert_eq!(ended_with(&mut rig).await?, ShellEnd::Malformed);
    Ok(())
}


#[tokio::test]
async fn an_open_frame_whose_wire_length_differs_is_refused() -> TestResult {
    let rig = rig();
    approve(&rig, SESSION)?;
    let outcome = attach_wire(&rig, vec![(open_frame(SESSION), PADDED_WIRE_BYTES)]).await;
    assert_eq!(expect_status(outcome)?.code(), Code::InvalidArgument);
    assert_eq!(counter(&rig.state.counters.shell_malformed), 1);
    Ok(())
}
