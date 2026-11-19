use ai_gateway::budget::{budgeted_chat, BudgetDeps, Stores, MIGRATIONS, MIGRATION_NAMESPACE, STATEMENT_DEADLINE};
use ai_gateway::chat::production_deps;
use ai_gateway::error::AiError;
use ai_gateway::pg::pg_budget_executor;
use ai_gateway::settings::{validate_ai, AiSettings};
use alerts::pg::pg_executor;
use alerts::store::{MIGRATIONS as ALERTS_MIGRATIONS, MIGRATION_NAMESPACE as ALERTS_NAMESPACE};
use core_config::load::load_file;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use serde_json::json;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::JoinSet;


const USAGE: &str = "usage: ai_budget <pg-settings.yaml> <ai.yaml> <tenant> <calls>";


const MIGRATION_DEADLINE: Duration = Duration::from_secs(120);


pub fn wall_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros() as u64)
}


async fn one_call(client: Arc<tokio_postgres::Client>, settings: Arc<AiSettings>, scope: TenantScope) -> String {
    let budget = pg_budget_executor(&client, STATEMENT_DEADLINE);
    let alerts = pg_executor(&client, STATEMENT_DEADLINE);
    let stores = Stores {
        budget: &budget,
        alerts: &alerts,
    };
    let deps = BudgetDeps {
        chat: production_deps(),
        wall_clock: wall_micros,
    };
    let outcome = budgeted_chat(&stores, &scope, &settings, "Summarise the alert.", &json!({"host": "web-1"}), &deps).await;
    match outcome {
        Ok(answer) => format!("answered {:?} {:?}", answer.prompt_tokens, answer.completion_tokens),
        Err(AiError::BudgetSpent) => "BudgetSpent".to_owned(),
        Err(error) => format!("failed: {error}"),
    }
}


async fn scenario(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [pg_file, ai_file, tenant, calls] = args else { Err(USAGE)? };
    let pg_settings = parse_settings(&std::fs::read_to_string(pg_file)?, pg_file)?;
    let client = Arc::new(connect(&pg_settings).await?);
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, MIGRATION_DEADLINE).await?;
    migrate(&client, ALERTS_NAMESPACE, &ALERTS_MIGRATIONS, MIGRATION_DEADLINE).await?;
    let settings: AiSettings = load_file(Path::new(ai_file))?;
    validate_ai(&settings)?;
    let shared = Arc::new(settings);
    let scope = tenant_scope(tenant)?;
    let mut tasks = JoinSet::new();
    (0..calls.parse::<usize>()?).for_each(|_index| {
        tasks.spawn(one_call(Arc::clone(&client), Arc::clone(&shared), scope.clone()));
    });
    let mut out = stdout();
    tasks.join_all().await.iter().try_for_each(|line| writeln!(out, "{line}"))?;
    Ok(())
}


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    tracing_subscriber::fmt().with_writer(stderr).init();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    match runtime.block_on(scenario(&args)) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
