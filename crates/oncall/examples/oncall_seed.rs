use alerts::id::alert_id;
use alerts::model::{Alert as SourceAlert, Severity, Summary};
use alerts::pg::pg_executor;
use alerts::store::{insert_alerts, MIGRATIONS as ALERT_MIGRATIONS, MIGRATION_NAMESPACE as ALERT_NAMESPACE};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::tenant_scope;
use core_pg::settings::parse_settings;
use oncall::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use std::io::{stderr, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;


const USAGE: &str = "usage: oncall_seed <pg.yaml> <tenant> <first-index> <count> [<title>]";


const DEFAULT_TITLE: &str = "<!channel> alert";


const DEADLINE: Duration = Duration::from_secs(30);


const SUMMARY_BYTES: u64 = 2;


const BASE_CREATED: u64 = 1_000;


fn source_alert(tenant: &str, index: u64, title: &str) -> SourceAlert {
    let event_ids = vec![format!("event-{index}")];
    SourceAlert {
        id: alert_id(tenant, "rule", &event_ids),
        tenant: tenant.to_owned(),
        rule_id: "rule".to_owned(),
        rule_title: format!("{title} {index}"),
        severity: Severity::High,
        event_time: "2026-11-10T00:00:00Z".to_owned(),
        created_micros: BASE_CREATED + index,
        host_name: Some("web-1".to_owned()),
        user_name: None,
        event_ids,
        summary: Summary {
            text: "{}".to_owned(),
            truncated: false,
            original_bytes: SUMMARY_BYTES,
        },
    }
}


async fn seed(pg_file: &Path, tenant: &str, first: u64, count: u64, title: &str) -> Result<(), Box<dyn std::error::Error>> {
    let settings = parse_settings(&std::fs::read_to_string(pg_file)?, &pg_file.display().to_string())?;
    let client = connect(&settings).await?;
    migrate(&client, ALERT_NAMESPACE, &ALERT_MIGRATIONS, DEADLINE).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await?;
    let alerts_exec = pg_executor(&client, DEADLINE);
    let batch: Vec<SourceAlert> = (first..first + count).map(|index| source_alert(tenant, index, title)).collect();
    insert_alerts(&alerts_exec, &tenant_scope(tenant)?, &batch).await?;
    Ok(())
}


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let outcome = match args.iter().map(String::as_str).collect::<Vec<&str>>().as_slice() {
        [pg, tenant, first, count] => {
            Some(runtime.block_on(async { seed(Path::new(pg), tenant, first.parse()?, count.parse()?, DEFAULT_TITLE).await }))
        }
        [pg, tenant, first, count, title] => {
            Some(runtime.block_on(async { seed(Path::new(pg), tenant, first.parse()?, count.parse()?, title).await }))
        }
        _ => None,
    };
    match outcome {
        Some(Ok(())) => Ok(ExitCode::SUCCESS),
        Some(Err(error)) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
        None => writeln!(stderr(), "{USAGE}").map(|()| ExitCode::FAILURE),
    }
}
