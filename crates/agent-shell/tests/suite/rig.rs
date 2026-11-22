use agent_channel::limits::system_now;
use agent_channel::model::{ChannelSettings, Counters, Identity, ServerState, ShellInput, ShellSinkEvent, ShellState};
use agent_channel::settings::shared_settings;
use agent_channel::shell::shell_router;
use agent_channel::shell_gate::{gate_add, new_gate};
use agent_channel::types::{ShellInputStream, ShellSink, ShellSource, SinkFuture};
use axum::{Extension, Router};
use core_audit::log::{append, genesis_log};
use futures_util::StreamExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use std::collections::HashMap;
use std::error::Error;
use std::future::ready;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Channel, Endpoint};


pub const LOOPBACK_NOW: u64 = 1_000_000;


pub const GATE_DEADLINE: u64 = LOOPBACK_NOW + 300;


pub const GATE_MAX_SECONDS: u64 = 3_600;


pub const INPUT_DEPTH: usize = 64;


pub struct Platform {
    pub channel: Channel,
    pub events: mpsc::UnboundedReceiver<ShellSinkEvent>,
    pub input: mpsc::Sender<ShellInput>,
    pub shell: Arc<ShellState>,
}


pub fn agent_identity() -> Identity {
    Identity {
        tenant: "acme".to_owned(),
        agent_id: "agent-1".to_owned(),
    }
}


pub fn recording_sink(events: mpsc::UnboundedSender<ShellSinkEvent>) -> ShellSink {
    Box::new(move |_identity: Identity, _session: String, event: ShellSinkEvent| {
        let sent = events.send(event).map_err(|_gone| "events receiver gone".into());
        let done: SinkFuture = Box::pin(ready(sent));
        done
    })
}


pub fn one_shot_source(receiver: mpsc::Receiver<ShellInput>) -> ShellSource {
    let held = Arc::new(Mutex::new(Some(receiver)));
    Box::new(move |_identity: Identity, _session: String| {
        let taken = held.lock().ok().and_then(|mut slot| slot.take());
        let stream: ShellInputStream = match taken {
            Some(feed) => Box::pin(ReceiverStream::new(feed)),
            None => Box::pin(futures_util::stream::pending()),
        };
        stream
    })
}


/// The T749 shell route behind a plain HTTP/2 listener on loopback; the agent identity is injected as the mTLS layer would.
pub async fn serve_plain(listener: TcpListener, router: Router) {
    TcpListenerStream::new(listener)
        .for_each(|accepted| {
            match accepted {
                Ok(stream) => {
                    let service = router.clone().layer(Extension(agent_identity()));
                    tokio::spawn(async move {
                        let served = Builder::new(TokioExecutor::new())
                            .http2_only()
                            .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service))
                            .await;
                        if let Err(error) = served {
                            tracing::warn!(%error, "loopback connection ended with an error");
                        }
                    });
                }
                Err(error) => tracing::warn!(%error, "loopback accept failed"),
            }
            ready(())
        })
        .await;
}


pub async fn start_platform() -> Result<Platform, Box<dyn Error>> {
    let (events_sender, events) = mpsc::unbounded_channel();
    let (input, feed) = mpsc::channel(INPUT_DEPTH);
    let shell = Arc::new(ShellState {
        gate: new_gate(Box::new(|| LOOPBACK_NOW)),
        sink: recording_sink(events_sender),
        source: one_shot_source(feed),
    });
    let log = genesis_log(io::sink());
    let state = Arc::new(ServerState {
        settings: shared_settings(ChannelSettings::default()),
        counters: Counters::default(),
        load: Mutex::new(HashMap::new()),
        events: Box::new(|_identity, _batch| Box::pin(ready(Ok(())))),
        commands: Box::new(|_identity| Box::pin(futures_util::stream::empty())),
        presence: Mutex::new(HashMap::new()),
        audit: Box::new(move |entry| append(&log, entry)),
        now: Box::new(system_now),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(serve_plain(listener, shell_router(state, Arc::clone(&shell))));
    let channel = Endpoint::from_shared(format!("http://{address}"))?.connect().await?;
    Ok(Platform {
        channel,
        events,
        input,
        shell,
    })
}


pub fn approve(platform: &Platform, session: &str) -> Result<(), Box<dyn Error>> {
    let identity = agent_identity();
    Ok(gate_add(
        &platform.shell.gate,
        &identity.tenant,
        &identity.agent_id,
        session,
        GATE_DEADLINE,
        GATE_MAX_SECONDS,
    )?)
}
