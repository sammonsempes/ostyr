use ai_gateway::budget::{new_gate, Gate, MIGRATIONS, MIGRATION_NAMESPACE};
use ai_gateway::error::AiError;
use ai_gateway::limits::MAX_WAITING_RESERVATIONS;
use ai_gateway::pg::pg_chat;
use ai_gateway::settings::{validate_ai, AiSettings};
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
use std::time::Duration;
use tokio::task::JoinSet;


const USAGE: &str = "usage: ai_budget <pg-settings.yaml> <ai.yaml> <tenant> <calls> [data-padding-bytes|zero] [long]";


const SHORT_INSTRUCTIONS: &str = "Summarise the alert.";


const LONG_INSTRUCTIONS: &str =
    "Summarise the alert for the analyst on duty in the operations centre, in plain language, and name every host, user and process it mentions.";


const MIGRATION_DEADLINE: Duration = Duration::from_secs(120);


async fn one_call(
    client: Arc<tokio_postgres::Client>,
    settings: Arc<AiSettings>,
    scope: TenantScope,
    gate: Arc<Gate>,
    padding: Option<usize>,
    instructions: &'static str,
) -> String {
    let data = padding.map_or(json!(0), |bytes| json!({"host": "web-1", "padding": "x".repeat(bytes)}));
    let outcome = pg_chat(&client, &gate, &scope, &settings, instructions, &data).await;
    match outcome {
        Ok(answer) => format!("answered {:?} {:?}", answer.prompt_tokens, answer.completion_tokens),
        Err(AiError::BudgetSpent) => "BudgetSpent".to_owned(),
        Err(AiError::BudgetBusy) => "BudgetBusy".to_owned(),
        Err(error) => format!("failed: {error}"),
    }
}


async fn scenario(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [pg_file, ai_file, tenant, calls, rest @ ..] = args else {
        Err(USAGE)?
    };
    let instructions = if rest.get(1).map(String::as_str) == Some("long") {
        LONG_INSTRUCTIONS
    } else {
        SHORT_INSTRUCTIONS
    };
    let padding = match rest.first().map(String::as_str) {
        Some("zero") => None,
        Some(text) => Some(text.parse::<usize>()?),
        None => Some(0),
    };
    let pg_settings = parse_settings(&std::fs::read_to_string(pg_file)?, pg_file)?;
    let client = Arc::new(connect(&pg_settings).await?);
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, MIGRATION_DEADLINE).await?;
    migrate(&client, ALERTS_NAMESPACE, &ALERTS_MIGRATIONS, MIGRATION_DEADLINE).await?;
    let settings: AiSettings = load_file(Path::new(ai_file))?;
    validate_ai(&settings)?;
    let shared = Arc::new(settings);
    let scope = tenant_scope(tenant)?;
    let gate = Arc::new(new_gate(MAX_WAITING_RESERVATIONS));
    let mut tasks = JoinSet::new();
    (0..calls.parse::<usize>()?).for_each(|_index| {
        tasks.spawn(one_call(
            Arc::clone(&client),
            Arc::clone(&shared),
            scope.clone(),
            Arc::clone(&gate),
            padding,
            instructions,
        ));
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
