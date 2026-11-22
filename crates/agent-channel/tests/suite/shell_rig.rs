use crate::harness::{bounded, scoped_logging};
use crate::services::{agent_identity, patient_settings};
use crate::state::{discarding_audit, envelope_source, new_stored, recording_sink};
use agent_channel::model::{ChannelSettings, Counters, Identity, ServerState, ShellEnd, ShellInput, ShellSinkEvent, ShellState};
use agent_channel::proto::shell_frame::Frame;
use agent_channel::proto::{ShellClose, ShellCloseReason, ShellFrame, ShellKeepalive, ShellOpen, ShellResize};
use agent_channel::settings::shared_settings;
use agent_channel::shell::open_shell;
use agent_channel::shell_gate::{gate_add, new_gate};
use agent_channel::types::{SharedShell, SharedState, ShellInputStream, ShellSink, ShellSource, ShellStream};
use futures_util::{stream, Stream, StreamExt};
use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::subscriber::DefaultGuard;


pub const CHANNEL_DEPTH: usize = 4_096;


pub const SESSION: &str = "session-1";


pub const START_DEADLINE: u64 = 1_000;


pub const MAX_SECONDS: u64 = 600;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Behavior {
    Record,
    FailEnded,
    FailAll,
    Hang,
}


pub struct Rig {
    pub state: SharedState,
    pub shell: SharedShell,
    pub events: mpsc::UnboundedReceiver<ShellSinkEvent>,
    pub input: mpsc::Sender<ShellInput>,
    pub offset: Arc<AtomicU64>,
    pub unix: Arc<AtomicU64>,
    _logging: DefaultGuard,
}


pub struct Attached {
    pub frames: mpsc::Sender<Result<ShellFrame, Status>>,
    pub response: ShellStream,
}


pub fn recording_shell_sink(events: mpsc::UnboundedSender<ShellSinkEvent>, behavior: Behavior) -> ShellSink {
    Box::new(move |_identity: Identity, _session: String, event: ShellSinkEvent| {
        let ended = matches!(event, ShellSinkEvent::Ended(_));
        let gone = events.send(event).is_err();
        let failure = gone
            || match behavior {
                Behavior::FailAll => true,
                Behavior::FailEnded => ended,
                Behavior::Record | Behavior::Hang => false,
            };
        Box::pin(async move {
            if behavior == Behavior::Hang {
                std::future::pending::<Result<(), agent_channel::types::BoxError>>().await
            } else if failure {
                Err("sink down".into())
            } else {
                Ok(())
            }
        })
    })
}


pub fn one_shot_source(receiver: mpsc::Receiver<ShellInput>) -> ShellSource {
    let held = Arc::new(Mutex::new(Some(receiver)));
    Box::new(move |_identity: Identity, _session: String| {
        let taken = held.lock().ok().and_then(|mut slot| slot.take());
        match taken {
            Some(stream_receiver) => Box::pin(ReceiverStream::new(stream_receiver)) as ShellInputStream,
            None => Box::pin(stream::pending()),
        }
    })
}


pub fn rig_with(settings: ChannelSettings, behavior: Behavior) -> Rig {
    let logging = scoped_logging();
    let base = Instant::now();
    let offset = Arc::new(AtomicU64::new(0));
    let unix = Arc::new(AtomicU64::new(0));
    let clock_offset = Arc::clone(&offset);
    let state = Arc::new(ServerState {
        settings: shared_settings(settings),
        counters: Counters::default(),
        load: Mutex::new(HashMap::new()),
        events: recording_sink(new_stored()),
        commands: envelope_source(Vec::new()),
        presence: Mutex::new(HashMap::new()),
        audit: discarding_audit(),
        now: Box::new(move || base + Duration::from_secs(clock_offset.load(Ordering::Relaxed))),
    });
    let (events_sender, events) = mpsc::unbounded_channel();
    let (input, receiver) = mpsc::channel(CHANNEL_DEPTH);
    let clock_unix = Arc::clone(&unix);
    let shell = Arc::new(ShellState {
        gate: new_gate(Box::new(move || clock_unix.load(Ordering::Relaxed))),
        sink: recording_shell_sink(events_sender, behavior),
        source: one_shot_source(receiver),
    });
    Rig {
        state,
        shell,
        events,
        input,
        offset,
        unix,
        _logging: logging,
    }
}


pub fn rig() -> Rig {
    rig_with(patient_settings(), Behavior::Record)
}


pub fn approve(rig: &Rig, session: &str) -> Result<(), Box<dyn Error>> {
    let identity = agent_identity();
    Ok(gate_add(
        &rig.shell.gate,
        &identity.tenant,
        &identity.agent_id,
        session,
        START_DEADLINE,
        MAX_SECONDS,
    )?)
}


pub fn open_frame(session: &str) -> ShellFrame {
    ShellFrame {
        frame: Some(Frame::Open(ShellOpen {
            session_id: session.to_string(),
        })),
    }
}


pub fn data_frame(bytes: &[u8]) -> ShellFrame {
    ShellFrame {
        frame: Some(Frame::Data(bytes.to_vec())),
    }
}


pub fn keepalive_frame() -> ShellFrame {
    ShellFrame {
        frame: Some(Frame::Keepalive(ShellKeepalive {})),
    }
}


pub fn resize_frame(cols: u32, rows: u32) -> ShellFrame {
    ShellFrame {
        frame: Some(Frame::Resize(ShellResize { cols, rows })),
    }
}


pub fn close_frame(reason: i32) -> ShellFrame {
    ShellFrame {
        frame: Some(Frame::Close(ShellClose { reason })),
    }
}


pub fn exited() -> ShellFrame {
    close_frame(i32::from(ShellCloseReason::Exited))
}


pub fn empty_frame() -> ShellFrame {
    ShellFrame { frame: None }
}


pub async fn attach_as(rig: &Rig, identity: Identity, first: Vec<ShellFrame>) -> Result<Attached, Status> {
    let (frames, receiver) = mpsc::channel(CHANNEL_DEPTH);
    first
        .into_iter()
        .try_for_each(|frame| frames.try_send(Ok(frame)).map_err(|_| Status::internal("test channel full")))?;
    let response = open_shell(
        Arc::clone(&rig.state),
        Arc::clone(&rig.shell),
        Ok(identity),
        ReceiverStream::new(receiver),
    )
    .await?;
    Ok(Attached {
        frames,
        response: response.into_inner(),
    })
}


pub async fn attach(rig: &Rig, first: Vec<ShellFrame>) -> Result<Attached, Status> {
    attach_as(rig, agent_identity(), first).await
}


pub async fn next_event(rig: &mut Rig) -> Result<ShellSinkEvent, Box<dyn Error>> {
    bounded(rig.events.recv()).await?.ok_or_else(|| "sink channel closed".into())
}


pub fn events_until_end(events: &mut mpsc::UnboundedReceiver<ShellSinkEvent>) -> impl Stream<Item = ShellSinkEvent> + '_ {
    stream::unfold((events, false), |(receiver, done)| async move {
        if done {
            None
        } else {
            receiver.recv().await.map(|event| {
                let last = matches!(event, ShellSinkEvent::Ended(_));
                (event, (receiver, last))
            })
        }
    })
}


pub async fn until_ended(rig: &mut Rig) -> Result<Vec<ShellSinkEvent>, Box<dyn Error>> {
    bounded(events_until_end(&mut rig.events).collect::<Vec<_>>()).await
}


pub async fn ended_with(rig: &mut Rig) -> Result<ShellEnd, Box<dyn Error>> {
    let events = until_ended(rig).await?;
    match events.last() {
        Some(ShellSinkEvent::Ended(end)) => Ok(*end),
        other => Err(format!("no end event: {other:?}").into()),
    }
}


pub async fn drained(response: ShellStream) -> Result<Vec<Result<ShellFrame, Status>>, Box<dyn Error>> {
    bounded(response.collect::<Vec<_>>()).await
}


pub async fn bounded_end(events: &mut mpsc::UnboundedReceiver<ShellSinkEvent>) -> Result<ShellEnd, Box<dyn Error>> {
    let seen = bounded(events_until_end(events).collect::<Vec<_>>()).await?;
    match seen.last() {
        Some(ShellSinkEvent::Ended(end)) => Ok(*end),
        other => Err(format!("no end event: {other:?}").into()),
    }
}
