use alerts::pg::pg_executor;
use alerts::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::settings::parse_settings;
use metric_alerts::fetch::{agent_for, fetch_points, load_fetch_settings, read_key};
use metric_alerts::query::parse_tenant_id;
use metric_alerts::recover::recover_states;
use metric_alerts::round::{evaluate_round, store_round, RoundStates};
use metric_alerts::rules::load_rules;
use siem_schema::metrics::MetricsRetention;
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};


const USAGE: &str = "usage: metric_round <settings.yaml> <rules.yaml> <pg.yaml> <tenant> <rounds>";


const DEADLINE: Duration = Duration::from_secs(30);


const ROUND_STEP_SECONDS: u64 = 60;


async fn scenario(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let (settings_file, rules_file, pg_file, tenant, rounds) = match arguments {
        [settings_file, rules_file, pg_file, tenant, rounds] => Ok((settings_file, rules_file, pg_file, tenant, rounds)),
        _ => Err(USAGE),
    }?;
    let fetch_settings = load_fetch_settings(Path::new(settings_file))?;
    let agent = agent_for(&fetch_settings)?;
    let password = read_key(&fetch_settings)?;
    let rules = load_rules(Path::new(rules_file))?;
    let scope = parse_tenant_id(tenant)?;
    let pg_settings = parse_settings(&std::fs::read_to_string(pg_file)?, pg_file)?;
    let client = connect(&pg_settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await?;
    let exec = pg_executor(&client, DEADLINE);
    let retention = MetricsRetention::default();
    let start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let fetch = |query: &_| {
        fetch_points(
            &agent,
            &fetch_settings,
            &password,
            query,
            Duration::from_millis(fetch_settings.timeout_ms),
        )
    };
    let mut states = RoundStates::default();
    let mut out = stdout();
    for round in 0..rounds.parse::<u64>()? {
        let now = start + round * ROUND_STEP_SECONDS;
        let recovered = recover_states(&exec, &scope, &rules, &mut states).await?;
        let outcome = evaluate_round(&rules, &scope, now, &retention, &fetch, &mut states)?;
        let stored = store_round(&exec, &scope, &outcome, now).await?;
        writeln!(
            out,
            "round {round} now {now}: recovered {recovered} {:?} firings {} stored {stored}",
            outcome.counts,
            outcome.firings.len()
        )?;
    }
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(scenario(&arguments))
}
