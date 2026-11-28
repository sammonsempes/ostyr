use alerts::pg::pg_executor;
use core_pg::settings::PgSettings;
use detection::pg::{commit_with, open_client, system_micros};
use detection::retro::{run_retro, RetroSettings, MAX_EXECUTION_SECONDS, MAX_ROWS_TO_READ};
use detection::retro_cursor::{load_cursors, save_cursors};
use detection::retro_rules::select_retro_rules;
use detection::retro_step::{retro_step, StepInput};
use sigma_sql::mapping::parse_mapping;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{stdout, Write};
use std::time::{Duration, Instant};
use stream_correlation::ruleset::parse_ruleset;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::runtime::Builder;


const USAGE: &str = "usage: retro_step <ch-url> <ch-user> <ch-password-file> <ch-ca|-> <database> <pg-settings.json> <tenant> <rule.yml> <mapping.yaml> <cursor-file> <now-rfc3339> <max-rows>";


const TIMEOUT_MS: u64 = 60_000;


fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args {
        [url, user, password_file, ca_file, database, pg_file, tenant, rule_file, mapping_file, cursor_file, now, max_rows] => {
            let settings = RetroSettings {
                url: url.clone(),
                user: user.clone(),
                password_file: password_file.into(),
                ca_file: (ca_file != "-").then(|| ca_file.into()),
                database: database.clone(),
                timeout_ms: TIMEOUT_MS,
                max_rows: max_rows.parse()?,
                max_execution_seconds: MAX_EXECUTION_SECONDS,
                max_rows_to_read: MAX_ROWS_TO_READ,
            };
            let mapping = parse_mapping(&fs::read_to_string(mapping_file)?)?;
            let texts = BTreeMap::from([("rule.yml".to_owned(), fs::read_to_string(rule_file)?)]);
            let selection = select_retro_rules(&parse_ruleset(&texts, &mapping)?);
            let rule = selection.rules.first().ok_or("the rule is not tagged ostyr.retro or has no usable id")?;
            let pg: PgSettings = serde_json::from_str(&fs::read_to_string(pg_file)?)?;
            let runtime = Builder::new_multi_thread().worker_threads(1).enable_all().build()?;
            let client = runtime.block_on(open_client(&pg))?;
            let exec = pg_executor(&client, Duration::from_secs(pg.statement_timeout_secs));
            let cursor_path = std::path::Path::new(cursor_file);
            let input = StepInput {
                rule,
                tenant,
                now: OffsetDateTime::parse(now, &Rfc3339)?,
            };
            let (cursors, report) = retro_step(
                &input,
                &load_cursors(cursor_path)?,
                &|query| {
                    let started = Instant::now();
                    run_retro(&settings, &mapping, query, &|| started.elapsed())
                },
                &|batch_tenant, records| commit_with(&runtime, &exec, batch_tenant, records, system_micros()),
                &|saved| save_cursors(cursor_path, saved),
            )?;
            writeln!(stdout(), "{report:?} entries={}", cursors.entries.len())?;
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}


fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|error| error.to_string())?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    run(&args)
}
