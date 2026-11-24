//! Usage: `shell_platform <server.yaml> <tenant> <agent-id> <session-id> <input-file>`: a lab stand-in for the platform, serving the command stream and the shell route over mTLS.
use agent_channel::app::{alerting_audit, reload_context, shared_log_audit};
use agent_channel::commands::command_source;
use agent_channel::limits::system_now;
use agent_channel::model::{Counters, ServerState, ServerTlsPaths, ShellInput, ShellSinkEvent, ShellState};
use agent_channel::presence::watch_silence;
use agent_channel::revocation::open_revocation_engine;
use agent_channel::server::serve;
use agent_channel::server_app::{file_events, load_server_file, SERVER_MODULE, SERVER_TENANT};
use agent_channel::settings::open_settings_engine;
use agent_channel::shell::shell_router;
use agent_channel::shell_gate::{gate_add, new_gate};
use agent_channel::tls::server_config;
use agent_channel::types::{ShellInputStream, ShellSink, ShellSource};
use agent_command::cli::seconds_since_epoch;
use core_audit::log::open_file_log;
use futures_util::{stream, FutureExt, StreamExt};
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;


const USAGE: &str = "usage: shell_platform <server.yaml> <tenant> <agent-id> <session-id> <input-file>";


const ARGUMENT_COUNT: usize = 5;


const START_DEADLINE_SECONDS: u64 = 3_600;


const MAX_SECONDS: u64 = 600;


const KEYSTROKE_PAUSE_SECONDS: u64 = 2;


const RUN_SECONDS: u64 = 900;


fn now_seconds() -> u64 {
    seconds_since_epoch(SystemTime::now().duration_since(UNIX_EPOCH))
}


fn print_sink() -> ShellSink {
    Box::new(|_identity, _session, event| {
        match event {
            ShellSinkEvent::Output(bytes) => {
                let mut out = stdout();
                if out.write_all(&bytes).and_then(|()| out.flush()).is_err() {
                    tracing::warn!("operator output not written");
                }
            }
            ShellSinkEvent::Tick | ShellSinkEvent::Ended(_) => {
                let mut out = stdout();
                if writeln!(out, "[platform event {event:?}]").is_err() {
                    tracing::warn!("operator event not written");
                }
            }
        }
        Box::pin(async { Ok(()) })
    })
}


fn typed_source(lines: Vec<String>) -> ShellSource {
    Box::new(move |_identity, _session| -> ShellInputStream {
        Box::pin(stream::iter(lines.clone()).then(|line| async move {
            tokio::time::sleep(Duration::from_secs(KEYSTROKE_PAUSE_SECONDS)).await;
            ShellInput::Data(format!("{line}\n").into_bytes())
        }))
    })
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let words: Vec<String> = std::env::args().skip(1).collect();
    let [config, tenant, agent_id, session_id, input] = <[String; ARGUMENT_COUNT]>::try_from(words).map_err(|_wrong| USAGE)?;
    let file = load_server_file(Path::new(&config))?;
    let lines: Vec<String> = std::fs::read_to_string(&input)?.lines().map(str::to_owned).collect();
    let log = Arc::new(open_file_log(&file.audit_file)?);
    let (settings_engine, settings) = open_settings_engine(
        file.settings_file.clone(),
        shared_log_audit(&log),
        reload_context(&file.settings_file, SERVER_MODULE, SERVER_TENANT, "settings-reload"),
        false,
    )?;
    let (revocation_engine, revocations) = open_revocation_engine(
        file.revocation_file.clone(),
        alerting_audit(shared_log_audit(&log)),
        reload_context(&file.revocation_file, SERVER_MODULE, SERVER_TENANT, "revocation-reload"),
    )?;
    let state = Arc::new(ServerState {
        settings,
        counters: Counters::default(),
        load: Mutex::default(),
        events: file_events(&file)?,
        commands: command_source(file.commands_dir.clone()),
        presence: Mutex::default(),
        audit: shared_log_audit(&log),
        now: Box::new(system_now),
    });
    let gate = new_gate(Box::new(now_seconds));
    for session in session_id.split(',') {
        gate_add(&gate, &tenant, &agent_id, session, now_seconds() + START_DEADLINE_SECONDS, MAX_SECONDS)?;
    }
    let shell = Arc::new(ShellState {
        gate,
        sink: print_sink(),
        source: typed_source(lines),
    });
    let tls = server_config(&ServerTlsPaths {
        certificate: file.certificate.clone(),
        key: file.key.clone(),
        agent_ca: file.agent_ca.clone(),
    })?;
    let listener = TcpListener::bind(&file.listen).await?;
    let stop = tokio::time::sleep(Duration::from_secs(RUN_SECONDS)).shared();
    let silence = tokio::spawn(watch_silence(Arc::clone(&state), stop.clone()));
    serve(
        Box::pin(TcpListenerStream::new(listener)),
        tls,
        shell_router(Arc::clone(&state), shell),
        state,
        revocations,
        Box::pin(stop),
    )
    .await;
    silence.await?;
    drop((settings_engine, revocation_engine));
    Ok(())
}
