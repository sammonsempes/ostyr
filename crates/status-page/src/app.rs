use crate::config::load_config;
use crate::error::StatusPageError;
use crate::limiter::{new_state, system_millis};
use crate::model::{ComponentState, IncidentInput, PageConfig, ServiceState, DEFAULT_LIMITS};
use crate::render::render;
use crate::serve::serve;
use crate::server::status_router;
use crate::settings::open_settings_engine;
use crate::snapshot::{publish, snapshot_of};
use crate::types::ShutdownSignal;
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_config::reload::{ReloadContext, RELOAD_DECLARED_KEYS};
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;


pub const APP_MODULE: &str = "status_page";


pub const DEBOUNCE_MILLIS: u64 = 300;


pub const SAMPLE_INCIDENT_TITLE: &str = "Sample incident";


/// The example server file: the page layout, the settings file (reloaded live) and the audit log of reloads.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppFile {
    pub page_file: PathBuf,
    pub settings_file: PathBuf,
    pub audit_file: PathBuf,
}


pub const AUDIT_DECLARED_KEYS: [&str; 5] = RELOAD_DECLARED_KEYS;


/// An audit function appending declared keys only (values are already cut by `reload_entry`) to the audit log file.
pub fn file_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let shared = Arc::clone(log);
    Box::new(move |entry| append_declared(&shared, entry, &AUDIT_DECLARED_KEYS))
}


pub fn reload_context(file: &AppFile, tenant: &str) -> ReloadContext {
    ReloadContext {
        actor_id: APP_MODULE.to_owned(),
        tenant: tenant.to_owned(),
        module: APP_MODULE.to_owned(),
        target: file.settings_file.display().to_string(),
        request_id: "settings-reload".to_owned(),
    }
}


/// Sample inputs for the example: the first component degraded with one published incident, the others operational.
pub fn sample_inputs(config: &PageConfig) -> (Vec<ServiceState>, Vec<IncidentInput>) {
    let states = config
        .components
        .iter()
        .enumerate()
        .map(|(position, component)| ServiceState {
            tenant: config.tenant.clone(),
            service: component.service.clone(),
            state: if position == 0 {
                ComponentState::Degraded
            } else {
                ComponentState::Operational
            },
        })
        .collect();
    let incidents = config
        .components
        .first()
        .map(|component| IncidentInput {
            tenant: config.tenant.clone(),
            service: component.service.clone(),
            published: true,
            public_title: SAMPLE_INCIDENT_TITLE.to_owned(),
            started_at: 0,
            resolved_at: None,
            updates: Vec::new(),
            internal_note: String::new(),
            assignee: String::new(),
            asset_ids: Vec::new(),
            addresses: Vec::new(),
        })
        .into_iter()
        .collect();
    (states, incidents)
}


/// Serves the sample page until `shutdown` completes; the settings reload on file change, every reload is audited.
pub async fn run_app(file: AppFile, listener: TcpListener, shutdown: ShutdownSignal) -> Result<(), StatusPageError> {
    let config = load_config(&file.page_file, &DEFAULT_LIMITS)?;
    let log = Arc::new(open_file_log(&file.audit_file)?);
    let (engine, settings) = open_settings_engine(file.settings_file.clone(), file_audit(&log), reload_context(&file, &config.tenant))?;
    let _watch = watch_files(
        Arc::new(engine),
        std::slice::from_ref(&file.settings_file),
        Duration::from_millis(DEBOUNCE_MILLIS),
    )?;
    let state = Arc::new(new_state(config.tenant.clone(), settings, Box::new(system_millis)));
    let (states, incidents) = sample_inputs(&config);
    let rendered = render(&config, &states, &incidents, &[], 0, &DEFAULT_LIMITS)?;
    publish(&state, snapshot_of(&config.tenant, &rendered))?;
    serve(
        Box::pin(TcpListenerStream::new(listener)),
        status_router(Arc::clone(&state)),
        state,
        shutdown,
    )
    .await;
    Ok(())
}
