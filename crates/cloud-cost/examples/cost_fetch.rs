//! Usage: cost_fetch <sources.yaml> <clickhouse.yaml> <postgres.yaml>. One round: lists each source's bucket prefix, loads the CSV objects not loaded before.

use cloud_cost::fetch::fetch_new;
use cloud_cost::fetch_error::LedgerFailure;
use cloud_cost::fetch_model::FetchEnv;
use cloud_cost::fetch_settings::{load_fetch_settings, validate_settings};
use cloud_cost::ledger::LEDGER_DDL;
use cloud_cost::load::load_table;
use cloud_cost::model::Limits;
use cloud_cost::settings::{validate_config, CostLoadConfig};
use cloud_cost::transport::send;
use core_config::load::load_file;
use core_pg::connect::connect;
use core_pg::query::{column_text, execute_script, run_query};
use core_pg::settings::load_settings;
use core_pg::types::SqlParameter;
use std::error::Error;
use std::io::{stdout, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::runtime::Builder;


const ARGUMENT_SOURCES: usize = 1;


const ARGUMENT_CLICKHOUSE: usize = 2;


const ARGUMENT_POSTGRES: usize = 3;


const USAGE: &str = "usage: cost_fetch <sources.yaml> <clickhouse.yaml> <postgres.yaml>";


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    let sources_path = arguments.get(ARGUMENT_SOURCES).ok_or(USAGE)?;
    let clickhouse_path = arguments.get(ARGUMENT_CLICKHOUSE).ok_or(USAGE)?;
    let postgres_path = arguments.get(ARGUMENT_POSTGRES).ok_or(USAGE)?;
    let settings = load_fetch_settings(sources_path.as_ref())?;
    validate_settings(&settings)?;
    let template: CostLoadConfig = load_file(clickhouse_path.as_ref())?;
    validate_config(&template)?;
    let postgres = load_settings(postgres_path.as_ref())?;
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let client = runtime.block_on(connect(&postgres))?;
    let deadline = Duration::from_secs(postgres.statement_timeout_secs);
    runtime.block_on(execute_script(&client, LEDGER_DDL, deadline))?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let started = Instant::now();
    let exec = |sql: &str, params: &[String]| -> Result<Vec<Vec<String>>, LedgerFailure> {
        let bound: Vec<SqlParameter<'_>> = params.iter().map(|text| text as SqlParameter<'_>).collect();
        let rows = runtime
            .block_on(run_query(&client, sql, &bound, deadline))
            .map_err(|_failure| LedgerFailure)?;
        rows.iter()
            .map(|row| column_text(row, 0).map(|text| vec![text]))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_failure| LedgerFailure)
    };
    let load = |tenant: &str, export: &cloud_cost::source::Export| {
        let mut config = template.clone();
        config.tenant = tenant.to_owned();
        load_table(&config, export, now, &|| started.elapsed())
    };
    let limits = Limits::default();
    let env = FetchEnv {
        http: &send,
        exec: &exec,
        load: &load,
        limits: &limits,
    };
    let report = fetch_new(&settings, &env, now);
    let mut out = stdout();
    writeln!(
        out,
        "listed {} skipped_key {} already_loaded {} already_refused {} in_backoff {} loaded {} deferred {} incomplete_listings {} permanent_refused {} transient_refused {}",
        report.listed, report.skipped_key, report.already_loaded, report.already_refused, report.in_backoff, report.loaded, report.deferred, report.incomplete_listings, report.permanent_refused, report.transient_refused
    )?;
    writeln!(out, "refused {:?}", report.refused)?;
    writeln!(out, "failed_sources {:?}", report.failed_sources)?;
    Ok(())
}
