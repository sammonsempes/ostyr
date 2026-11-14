use core_pg::connect::connect;
use core_pg::error::{reduce, PgError};
use core_pg::migrate::migrate;
use core_pg::query::scoped_query;
use core_pg::scope::TenantScope;
use core_pg::settings::parse_settings;
use hunt_packs::model::HuntPack;
use hunt_packs::packs::load_packs;
use hunt_packs::run::{run_pack, HuntOutcome, RunError};
use hunt_packs::schedule::due_runs;
use hunt_packs::store::{Param, MIGRATIONS, MIGRATION_NAMESPACE, STATEMENT_DEADLINE};
use hunt_packs::tick::{tick, Hooks, TickLimits};
use metric_alerts::fetch::{agent_for, load_fetch_settings, read_key, FetchSettings};
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::OnceLock;
use std::time::Duration;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;
use ureq::Agent;


const USAGE: &str = "usage: hunt_tick <pg-settings.yaml> <ch-settings.yaml> <packs-dir> <tenant>... --now <seconds>";


const FIRST_COLUMN: usize = 0;


const SKIP_PROGRAM_NAME: usize = 1;


struct Context {
    agent: Agent,
    settings: FetchSettings,
    password: String,
}


static CONTEXT: OnceLock<Context> = OnceLock::new();


fn run_bound(pack: &HuntPack, tenant: &str, end: i64) -> Result<HuntOutcome, RunError> {
    let seconds = u64::try_from(end).map_err(|_| RunError::Window)?;
    CONTEXT.get().map_or(Err(RunError::Window), |context| {
        let remaining = Duration::from_millis(context.settings.timeout_ms);
        run_pack(&context.agent, &context.settings, &context.password, pack, tenant, seconds, remaining)
    })
}


async fn execute(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<i64>, PgError> {
    let boxed: Vec<Box<dyn ToSql + Sync>> = params
        .into_iter()
        .map(|param| -> Box<dyn ToSql + Sync> {
            match param {
                Param::Text(text) => Box::new(text),
                Param::Int(number) => Box::new(number),
            }
        })
        .collect();
    let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(|value| value.as_ref() as &(dyn ToSql + Sync)).collect();
    let rows = scoped_query(client, &scope, sql, &refs, STATEMENT_DEADLINE).await?;
    rows.iter().map(|row| row.try_get(FIRST_COLUMN).map_err(reduce)).collect()
}


async fn scenario(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [pg_file, ch_file, dir, rest @ ..] = args else { Err(USAGE)? };
    let split = rest.iter().position(|item| item == "--now").ok_or(USAGE)?;
    let (tenants, tail) = rest.split_at(split);
    let [_flag, now_text] = tail else { Err(USAGE)? };
    let now: i64 = now_text.parse()?;
    let fetch_settings = load_fetch_settings(Path::new(ch_file))?;
    let agent = agent_for(&fetch_settings)?;
    let password = read_key(&fetch_settings)?.to_string();
    CONTEXT
        .set(Context {
            agent,
            settings: fetch_settings,
            password,
        })
        .map_err(|_| "context already set")?;
    let packs: Vec<HuntPack> = load_packs(Path::new(dir))?.into_iter().map(|item| item.pack).collect();
    let settings = parse_settings(&std::fs::read_to_string(pg_file)?, pg_file)?;
    let client = connect(&settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, STATEMENT_DEADLINE).await?;
    let mut exec = |scope: &TenantScope, sql: &'static str, params: Vec<Param>| execute(&client, scope.clone(), sql, params);
    let hooks = Hooks {
        run: run_bound,
        due: due_runs,
    };
    let report = tick(tenants, &packs, now, &TickLimits::default(), &mut exec, &hooks).await?;
    let mut out = stdout();
    report.packs.iter().try_for_each(|entry| {
        let findings: Vec<bool> = entry.runs.iter().map(|run| run.finding).collect();
        writeln!(
            out,
            "{}\t{}\truns={}\tlast_end={:?}\tfindings={:?}\t{:?}",
            entry.tenant,
            entry.pack_id,
            entry.runs.len(),
            entry.last_end,
            findings,
            entry.status
        )
    })?;
    writeln!(out, "deferred={}\tskipped_osquery={}", report.deferred, report.skipped_osquery)?;
    Ok(())
}


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(SKIP_PROGRAM_NAME).collect();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    match runtime.block_on(scenario(&args)) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
