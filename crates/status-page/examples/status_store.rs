//! Usage: `status_store <pg.yaml> <tenant-a> <tenant-b>`; the live proof of the incident store (migrate, write for two tenants, render tenant A).
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use status_page::model::{ComponentConfig, PageConfig, DEFAULT_LIMITS};
use status_page::pg::execute;
use status_page::render::render;
use status_page::store::{add_update, create_incident, published_incidents, resolve_incident, MAX_PUBLISHED, MIGRATIONS, MIGRATION_NAMESPACE};
use status_page::store_model::{IncidentRef, NewIncident, Statement};
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;


const USAGE: &str = "usage: status_store <pg.yaml> <tenant-a> <tenant-b>";


const DEADLINE: Duration = Duration::from_secs(30);


const STARTED: i64 = 1_700_000_000;


const STEP: i64 = 60;


const SERVICE: &str = "svc-web-internal";


const SECRET_NOTE: &str = "internal 10.0.0.5 SECRET-NOTE";


fn incident(title: &str, started_at: i64) -> NewIncident {
    NewIncident {
        service: SERVICE.to_owned(),
        title: title.to_owned(),
        published: true,
        started_at,
        internal_note: SECRET_NOTE.to_owned(),
    }
}


fn page_config(tenant: &str) -> PageConfig {
    PageConfig {
        id: "main".to_owned(),
        tenant: tenant.to_owned(),
        title: "Status".to_owned(),
        checks: Vec::new(),
        components: vec![ComponentConfig {
            name: "Website".to_owned(),
            service: SERVICE.to_owned(),
            objective_ppm: None,
            rule: None,
        }],
    }
}


async fn scenario(settings_file: &Path, tenant_a: &str, tenant_b: &str) -> Result<(), Box<dyn std::error::Error>> {
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, &settings_file.display().to_string())?;
    let client = connect(&settings).await?;
    let mut out = stdout();
    writeln!(
        out,
        "migrations applied: {:?}",
        migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await?
    )?;
    let scope_a = tenant_scope(tenant_a)?;
    let scope_b = tenant_scope(tenant_b)?;
    let mut exec = |scope: &TenantScope, statement: Statement| execute(&client, scope.clone(), statement, DEADLINE);
    let first = create_incident(&mut exec, &scope_a, &incident("Website down", STARTED)).await?;
    let second = create_incident(&mut exec, &scope_a, &incident("Mail slow", STARTED + STEP)).await?;
    let other = create_incident(&mut exec, &scope_b, &incident("Globex outage", STARTED)).await?;
    writeln!(out, "ids: A {} and {}, B {}", first.id, second.id, other.id)?;
    let updated = add_update(
        &mut exec,
        &scope_a,
        first,
        STARTED + STEP,
        "Investigating",
        "root cause SECRET-UPDATE-NOTE",
    )
    .await?;
    writeln!(out, "A first incident version after update: {}", updated.version)?;
    let stale = add_update(&mut exec, &scope_a, first, STARTED + STEP, "stale", "").await;
    writeln!(out, "stale version: {stale:?}")?;
    let foreign = IncidentRef {
        id: first.id,
        version: updated.version,
    };
    writeln!(
        out,
        "B updates A's id: {:?}",
        add_update(&mut exec, &scope_b, foreign, STARTED, "hijack", "").await
    )?;
    writeln!(
        out,
        "B resolves A's id: {:?}",
        resolve_incident(&mut exec, &scope_b, foreign, STARTED).await
    )?;
    writeln!(
        out,
        "A resolves its own: {:?}",
        resolve_incident(&mut exec, &scope_a, updated, STARTED + STEP).await?
    )?;
    let services = vec![SERVICE.to_owned()];
    let published = published_incidents(&mut exec, &scope_a, &services, MAX_PUBLISHED).await?;
    let page = render(&page_config(tenant_a), &[], &published, &[], STARTED + STEP, &DEFAULT_LIMITS)?;
    writeln!(out, "-- tenant A page JSON\n{}", page.json)?;
    writeln!(
        out,
        "page holds a note: {} ; holds tenant B data: {}",
        page.json.contains("SECRET") || page.html.contains("SECRET"),
        page.json.contains("Globex") || page.html.contains("Globex")
    )?;
    Ok(())
}


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [settings, tenant_a, tenant_b] => {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            match runtime.block_on(scenario(Path::new(settings), tenant_a, tenant_b)) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
            }
        }
        _ => writeln!(stderr(), "{USAGE}").map(|()| ExitCode::FAILURE),
    }
}
