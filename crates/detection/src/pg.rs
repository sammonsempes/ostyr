use crate::error::SinkError;
use crate::model::{AlertRecord, AlertStore, PgStore, HOST_FIELD, MICROS_PER_SECOND, NANOS_PER_MILLI, REPLACEMENT, USER_FIELD};
use crate::store::bound_record;
use crate::types::MicrosFn;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::pg::pg_executor;
use alerts::store::{
    insert_alerts, summarise, MAX_ENTITY_CHARS, MAX_EVENT_IDS, MAX_EVENT_ID_CHARS, MAX_RULE_ID_CHARS, MAX_TITLE_CHARS, MIGRATIONS,
    MIGRATION_NAMESPACE,
};
use alerts::types::Executor;
use core_config::reload::{current_config, ReloadEngine};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::tenant_scope;
use core_pg::settings::PgSettings;
use serde_json::json;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::runtime::{Builder, Runtime};
use tokio_postgres::Client;
use tracing::debug;


pub const DATABASE_WORKERS: usize = 1;


pub const SEVERITY: Severity = Severity::Medium;


/// At most `max` characters, a NUL replaced (PostgreSQL refuses it in text), so an honest alert is never refused for its content.
pub fn bounded_text(text: &str, max: usize) -> String {
    text.chars()
        .take(max)
        .map(|character| if character == '\0' { REPLACEMENT } else { character })
        .collect()
}


/// An event identity is at most `MAX_EVENT_ID_CHARS` by construction; a longer one is refused rather than cut, so its payload hash is never lost.
pub fn checked_event_id(event_id: &str) -> Result<String, SinkError> {
    if event_id.chars().count() > MAX_EVENT_ID_CHARS {
        Err(SinkError::EventIdTooLong { max: MAX_EVENT_ID_CHARS })
    } else {
        Ok(bounded_text(event_id, MAX_EVENT_ID_CHARS))
    }
}


pub fn system_micros() -> u64 {
    let now = OffsetDateTime::now_utc();
    (now.unix_timestamp() as u64) * MICROS_PER_SECOND + u64::from(now.microsecond())
}


pub fn event_time_text(last_ms: i64) -> Result<String, SinkError> {
    let moment = OffsetDateTime::from_unix_timestamp_nanos(i128::from(last_ms) * NANOS_PER_MILLI).map_err(SinkError::EventTimeRange)?;
    moment.format(&Rfc3339).map_err(SinkError::EventTimeFormat)
}


pub fn entity_of(record: &AlertRecord, field: &str) -> Option<String> {
    record
        .group
        .get(field)
        .map(|value| bounded_text(value, MAX_ENTITY_CHARS))
        .filter(|value| !value.is_empty())
}


/// The store's alert: texts bounded, at most `MAX_EVENT_IDS` event ids (the first sorted ones), and an id derived from what is stored.
pub fn alert_of(record: &AlertRecord, created_micros: u64) -> Result<Alert, SinkError> {
    let rule_id = bounded_text(&record.rule_id, MAX_RULE_ID_CHARS);
    let mut event_ids: Vec<String> = record
        .event_ids
        .iter()
        .map(|event_id| checked_event_id(event_id))
        .collect::<Result<_, SinkError>>()?;
    event_ids.sort();
    event_ids.truncate(MAX_EVENT_IDS);
    let summary = summarise(&json!({
        "group": bound_record(record).group,
        "first_ms": record.first_ms,
        "last_ms": record.last_ms,
        "events": record.event_ids.len(),
    }));
    Ok(Alert {
        id: alert_id(&record.tenant, &rule_id, &event_ids),
        tenant: record.tenant.clone(),
        rule_id,
        rule_title: bounded_text(&record.rule_title, MAX_TITLE_CHARS),
        severity: SEVERITY,
        event_time: event_time_text(record.last_ms)?,
        created_micros,
        host_name: entity_of(record, HOST_FIELD),
        user_name: entity_of(record, USER_FIELD),
        event_ids,
        summary,
    })
}


/// Inserts the batch under the subject tenant through `exec`; the scope is the tenant of the batch, so an alert of another tenant is refused by the store.
pub fn commit_with(
    runtime: &Runtime,
    exec: Executor<'_, '_>,
    tenant: &str,
    records: &[AlertRecord],
    created_micros: u64,
) -> Result<usize, SinkError> {
    let scope = tenant_scope(tenant).map_err(SinkError::Database)?;
    let mapped: Result<Vec<Alert>, SinkError> = records.iter().map(|record| alert_of(record, created_micros)).collect();
    runtime.block_on(insert_alerts(exec, &scope, &mapped?)).map_err(SinkError::Store)
}


/// A connection with the given settings snapshot, with the schema brought up to date.
pub async fn open_client(settings: &PgSettings) -> Result<Client, SinkError> {
    let client = connect(settings).await.map_err(SinkError::Database)?;
    let deadline = Duration::from_secs(settings.statement_timeout_secs);
    let applied = migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, deadline)
        .await
        .map_err(SinkError::Database)?;
    debug!(applied = applied.len(), "alert schema ready");
    Ok(client)
}


pub fn open_pg_store(settings: Arc<ReloadEngine<PgSettings>>, clock: MicrosFn) -> Result<PgStore, SinkError> {
    let runtime = Builder::new_multi_thread()
        .worker_threads(DATABASE_WORKERS)
        .enable_all()
        .build()
        .map_err(SinkError::Runtime)?;
    Ok(PgStore {
        runtime,
        settings,
        link: Mutex::new(None),
        clock,
    })
}


/// Commits through the kept connection, opening one when there is none or it closed; a failed commit drops the connection, so the retry reconnects with the settings then in force.
pub fn commit_pg(store: &PgStore, tenant: &str, records: &[AlertRecord]) -> Result<usize, SinkError> {
    if records.is_empty() {
        Ok(0)
    } else {
        commit_records(store, tenant, records)
    }
}


fn commit_records(store: &PgStore, tenant: &str, records: &[AlertRecord]) -> Result<usize, SinkError> {
    let settings = current_config(&store.settings);
    let mut slot = store.link.lock().unwrap_or_else(PoisonError::into_inner);
    let client = match slot.take() {
        Some(open) if !open.is_closed() => open,
        _ => store.runtime.block_on(open_client(&settings))?,
    };
    let deadline = Duration::from_secs(settings.statement_timeout_secs);
    let stored = {
        let exec = pg_executor(&client, deadline);
        commit_with(&store.runtime, &exec, tenant, records, (store.clock)())?
    };
    *slot = Some(client);
    Ok(stored)
}


pub fn pg_commit(store: &AlertStore, tenant: &str, records: &[AlertRecord]) -> Result<usize, SinkError> {
    match store {
        AlertStore::Postgres(inner) => commit_pg(inner, tenant, records),
        AlertStore::File(_) => Err(SinkError::WrongStore),
    }
}
