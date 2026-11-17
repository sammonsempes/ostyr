//! Usage: `rshell_register <pg.yaml> <tenant> open <session> <requester> <asset> <ticket> <opened_at> | close <session> <reason> <recording> | list <limit> <asset|-> <requester|-> <open|all> [<after_opened_at> <after_session>]`; the live proof of the session register.
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::query::scoped_query;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use remote_shell::error::StoreError;
use remote_shell::recording::{read_recording, Header, Limits};
use remote_shell::session::CloseReason;
use remote_shell::store::{close_of, list_sessions, reason_token, register_close, register_open, MIGRATIONS, MIGRATION_NAMESPACE};
use remote_shell::store_model::{Cell, Cursor, ListFilter, Param, Statement};
use remote_shell::types::Row;
use std::fs::File;
use std::io::{stderr, stdout, BufReader, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;


const USAGE: &str = "usage: rshell_register <pg.yaml> <tenant> open <session> <requester> <asset> <ticket> <opened_at> | close <session> <reason> \
    <recording> | list <limit> <asset|-> <requester|-> <open|all> [<after_opened_at> <after_session>]";


const DEADLINE: Duration = Duration::from_secs(30);


const REASONS: [CloseReason; 6] = [
    CloseReason::IdleTimeout,
    CloseReason::MaxDuration,
    CloseReason::RecordingFailed,
    CloseReason::ChannelDead,
    CloseReason::UserClose,
    CloseReason::ClockSkew,
];


fn bound(params: &[Param]) -> Vec<Box<dyn ToSql + Sync>> {
    params
        .iter()
        .map(|param| -> Box<dyn ToSql + Sync> {
            match param {
                Param::Int(value) => Box::new(*value),
                Param::Text(value) => Box::new(value.clone()),
                Param::Bool(value) => Box::new(*value),
                Param::Bytes(value) => Box::new(value.clone()),
            }
        })
        .collect()
}


fn cell_of(row: &tokio_postgres::Row, index: usize) -> Result<Cell, StoreError> {
    let column = row.columns().get(index).ok_or(StoreError::BadRow { column: "cell" })?;
    let cell = match column.type_().name() {
        "int8" => row.try_get::<_, Option<i64>>(index).map(|value| value.map_or(Cell::Null, Cell::Int)),
        "bytea" => row
            .try_get::<_, Option<Vec<u8>>>(index)
            .map(|value| value.map_or(Cell::Null, Cell::Bytes)),
        _ => row.try_get::<_, Option<String>>(index).map(|value| value.map_or(Cell::Null, Cell::Text)),
    };
    cell.map_err(|_error| StoreError::BadRow { column: "cell" })
}


async fn execute(client: &Client, scope: TenantScope, statement: Statement) -> Result<Vec<Row>, StoreError> {
    let boxed = bound(&statement.params);
    let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|value| value.as_ref() as &(dyn ToSql + Sync)).collect();
    let rows = scoped_query(client, &scope, statement.sql, &refs, DEADLINE).await?;
    rows.iter().map(|row| (0..row.len()).map(|index| cell_of(row, index)).collect()).collect()
}


fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}


fn dash_to_none(value: &str) -> Option<String> {
    (value != "-").then(|| value.to_owned())
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
        [verb, limit, asset, requester, mode, after @ ..] if verb == "list" => {
            let filter = ListFilter {
                asset: dash_to_none(asset),
                requester: dash_to_none(requester),
                open_only: mode == "open",
            };
            let cursor = match after {
                [opened_at, session_id] => Some(Cursor {
                    opened_at: opened_at.parse()?,
                    session_id: session_id.clone(),
                }),
                _ => None,
            };
            let rows = list_sessions(&mut exec, &tenant_filter, &filter, cursor.as_ref(), limit.parse()?).await?;
            rows.iter().try_for_each(|row| {
                writeln!(
                    out,
                    "{}\t{}\t{}\t{}\topened={}\tclosed={:?}\treason={:?}\tframes={:?}\tbytes={:?}\thash={}",
                    row.session_id,
                    row.requester,
                    row.asset,
                    row.ticket,
                    row.opened_at,
                    row.closed_at,
                    row.close_reason,
                    row.recording_frames,
                    row.recording_bytes,
                    row.recording_hash.as_deref().map_or_else(String::new, hex)
                )
            })?;
            writeln!(out, "rows={}", rows.len())?;
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
