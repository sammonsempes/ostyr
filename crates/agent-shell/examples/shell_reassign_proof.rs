//! Live proof of the per-session preparation: one session per stdin line (the line is the session id), run through `run_prepared` with the production hooks.

#[cfg(target_os = "linux")]
mod proof {
    use agent_channel::model::ShellClientEnd;
    use agent_channel::types::DialFuture;
    use agent_command::model::{Action, Command, KeyClass, NONCE_LENGTH};
    use agent_shell::hooks::production_hooks;
    use agent_shell::model::{ShellShared, VerifiedOpenShell};
    use agent_shell::session::run_prepared;
    use agent_shell::spawn::SHELL_ACCOUNT;
    use agent_shell::types::AttachFuture;
    use std::error::Error;
    use std::io::{BufRead, Write};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};


    const LIFETIME: u64 = 300;


    const SESSION_SECONDS: u32 = 60;


    const HOLD_SECONDS: u64 = 2;


    const ROOT_UID: u32 = 0;


    fn unix_seconds() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
    }


    fn order(session: &str) -> Result<VerifiedOpenShell, Box<dyn Error>> {
        let issued_at = unix_seconds();
        let command = Command {
            key_id: "key-1".to_owned(),
            key_class: KeyClass::Sensitive,
            agent_id: "agent-1".to_owned(),
            tenant: "acme".to_owned(),
            issued_at,
            expires_at: issued_at + LIFETIME,
            sequence: 1,
            nonce: [0; NONCE_LENGTH],
            action: Action::OpenShell {
                session_id: session.to_owned(),
                asset: "asset-1".to_owned(),
                ticket: "TCK-1".to_owned(),
                requester: "alice@example.org".to_owned(),
                approvers: vec!["bob@example.org".to_owned()],
                max_seconds: SESSION_SECONDS,
                idle_seconds: SESSION_SECONDS,
            },
        };
        Ok(VerifiedOpenShell::try_from(command)?)
    }


    fn dial() -> DialFuture {
        Box::pin(async { Ok(tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy()) })
    }


    fn attach(
        _channel: tonic::transport::Channel,
        _session: String,
        _reader: agent_channel::types::ShellReader,
        _writer: agent_channel::types::ShellWriter,
    ) -> AttachFuture {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(HOLD_SECONDS)).await;
            Ok(ShellClientEnd::ServerClosed)
        })
    }

    pub async fn run() -> Result<(), Box<dyn Error>> {
        let store = PathBuf::from(std::env::args().nth(1).ok_or("usage: shell_reassign_proof <store dir, root 0700>")?);
        let mut out = std::io::stdout();
        let shared = ShellShared {
            agent_id: "agent-1".to_owned(),
            store_directory: store,
            store_owner: ROOT_UID,
            store_lock: Mutex::new(()),
            clock: &unix_seconds,
            dial: &dial,
            attach: &attach,
            enabled: &|| true,
        };
        let mut previous = None;
        for line in std::io::stdin().lock().lines() {
            let session = line?;
            let (outcome, kept) = run_prepared(order(&session)?, &shared, SHELL_ACCOUNT, production_hooks, previous).await;
            previous = kept;
            writeln!(out, "session {session}: {outcome:?}")?;
        }
        Ok(())
    }
}


#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    proof::run().await
}


#[cfg(not(target_os = "linux"))]
fn main() {}
