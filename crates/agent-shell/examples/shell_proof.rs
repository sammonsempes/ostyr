//! Live proof of the real spawner and cleanup: runs the keystrokes of stdin in a shell of the account named by the first argument, then sweeps.

#[cfg(unix)]
mod proof {
    use agent_command::model::{Action, Command, KeyClass, NONCE_LENGTH};
    use agent_shell::account::{lookup_account, resolve_account, stat_home};
    use agent_shell::cleanup::cleanup_fn;
    use agent_shell::model::{PtyHandle, VerifiedOpenShell};
    use agent_shell::spawn::{spawn_fn, SHELL_ACCOUNT};
    use std::error::Error;
    use std::io::{Read, Write};
    use std::time::Duration;
    use tokio_stream::StreamExt;


    const ISSUED_AT: u64 = 1_000;


    const LIFETIME: u64 = 300;


    const SESSION_SECONDS: u32 = 120;


    const EXIT_WAIT_SECONDS: u64 = 60;


    const QUIET_SECONDS: u64 = 3;


    fn order() -> Result<VerifiedOpenShell, Box<dyn Error>> {
        let command = Command {
            key_id: "key-1".to_owned(),
            key_class: KeyClass::Sensitive,
            agent_id: "agent-1".to_owned(),
            tenant: "acme".to_owned(),
            issued_at: ISSUED_AT,
            expires_at: ISSUED_AT + LIFETIME,
            sequence: 1,
            nonce: [0; NONCE_LENGTH],
            action: Action::OpenShell {
                session_id: "proof-1".to_owned(),
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


    async fn transcript(handle: PtyHandle) -> Result<(bool, Vec<u8>), Box<dyn Error>> {
        let PtyHandle { output, input, exit } = handle;
        let exited = tokio::time::timeout(Duration::from_secs(EXIT_WAIT_SECONDS), exit).await;
        drop(input);
        let chunks = output
            .timeout(Duration::from_secs(QUIET_SECONDS))
            .map_while(Result::ok)
            .collect::<Vec<_>>()
            .await;
        Ok((exited.is_ok(), chunks.into_iter().collect::<Result<Vec<_>, _>>()?.concat()))
    }

    pub async fn run() -> Result<(), Box<dyn Error>> {
        let name = std::env::args().nth(1).unwrap_or_else(|| SHELL_ACCOUNT.to_owned());
        let mut out = std::io::stdout();
        let account = resolve_account(&name, lookup_account, stat_home)?;
        let mut keystrokes = Vec::new();
        std::io::stdin().read_to_end(&mut keystrokes)?;
        let spawn = spawn_fn(account.clone());
        let cleanup = cleanup_fn(&account);
        let handle = spawn(&order()?).await?;
        handle.input.send(keystrokes).await?;
        let (exited, shown) = transcript(handle).await?;
        out.write_all(&shown)?;
        writeln!(out, "\nshell exited by itself: {exited}")?;
        writeln!(out, "left after the session: {}", cleanup().await?)?;
        Ok(())
    }
}


#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    proof::run().await
}


#[cfg(not(unix))]
fn main() {}
