//! Usage: `rshell_register <pg.yaml> <tenant> open <session> <requester> <asset> <ticket> <opened_at> | close <session> <reason> <recording> | get <session> | page <limit> [<cursor>]`; the live proof of the session register.
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use remote_shell::backend::pg_execute;
use remote_shell::error::StoreError;
use remote_shell::recording::{read_recording, Header, Limits};
use remote_shell::serve::{get_session, list_page};
use remote_shell::session::CloseReason;
use remote_shell::store::{close_of, reason_token, register_close, register_open, MIGRATIONS, MIGRATION_NAMESPACE};
use remote_shell::store_model::{ListFilter, Statement};
use remote_shell::types::Row;
use std::fs::File;
use std::io::{stderr, stdout, BufReader, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tokio_postgres::Client;


const USAGE: &str = "usage: rshell_register <pg.yaml> <tenant> open <session> <requester> <asset> <ticket> <opened_at> | close <session> <reason> \
    <recording> | get <session> | page <limit> [<cursor>]";


const DEADLINE: Duration = Duration::from_secs(30);


const REASONS: [CloseReason; 6] = [
    CloseReason::IdleTimeout,
    CloseReason::MaxDuration,
    CloseReason::RecordingFailed,
    CloseReason::ChannelDead,
    CloseReason::UserClose,
    CloseReason::ClockSkew,
];


async fn execute(client: &Client, scope: TenantScope, statement: Statement) -> Result<Vec<Row>, StoreError> {
    pg_execute(client, DEADLINE, scope, statement).await
}


fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}


async fn scenario(settings_file: &Path, tenant: &str, command: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, &settings_file.display().to_string())?;
    let client = connect(&settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await?;
    let tenant_filter = tenant_scope(tenant)?;
    let mut exec = |scope: &TenantScope, statement: Statement| execute(&client, scope.clone(), statement);
    let mut out = stdout();
    match command {
        [verb, session, requester, asset, ticket, opened_at] if verb == "open" => {
            let header = Header {
                session_id: session.clone(),
                tenant: tenant.to_owned(),
                requester: requester.clone(),
                asset: asset.clone(),
                ticket: ticket.clone(),
                opened_at: opened_at.parse()?,
            };
            register_open(&mut exec, &tenant_filter, &header).await?;
            writeln!(out, "opened {session}")?;
        }
        [verb, session, reason, file] if verb == "close" => {
            let token = REASONS.iter().copied().find(|candidate| reason_token(*candidate) == reason);
            let chosen = token.ok_or("unknown close reason")?;
            let bytes = std::fs::metadata(file)?.len();
            let recording = read_recording(&mut BufReader::new(File::open(file)?), &Limits::default())?;
            let record = close_of(&tenant_filter, session, &recording, chosen, bytes)?;
            register_close(&mut exec, &tenant_filter, session, &record).await?;
            writeln!(
                out,
                "closed {session} frames={} bytes={} hash={}",
                record.frames,
                record.bytes,
                hex(&record.final_hash)
            )?;
        }
        [verb, session] if verb == "get" => {
            let found = get_session(&mut exec, &tenant_filter, session).await?;
            writeln!(out, "{found:?}")?;
        }
        [verb, limit, after @ ..] if verb == "page" => {
            let page = list_page(
                &mut exec,
                &tenant_filter,
                &ListFilter::default(),
                after.first().map(String::as_str),
                limit.parse()?,
            )
            .await?;
            page.rows
                .iter()
                .try_for_each(|row| writeln!(out, "{}\t{}\t{}", row.session_id, row.requester, row.opened_at))?;
            writeln!(out, "rows={} skipped={} next={:?}", page.rows.len(), page.skipped, page.next_cursor)?;
        }
        _ => writeln!(out, "{USAGE}")?,
    }
    Ok(())
}


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [settings, tenant, command @ ..] if !command.is_empty() => {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            match runtime.block_on(scenario(Path::new(settings), tenant, command)) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
            }
        }
        _ => writeln!(stderr(), "{USAGE}").map(|()| ExitCode::FAILURE),
    }
}
