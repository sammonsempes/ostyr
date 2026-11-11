use crate::error::SinkError;
use crate::model::{
    AlertRecord, AlertStore, PgStore, HOST_FIELD, MAX_EVENT_MS, MICROS_PER_SECOND, MIN_EVENT_MS, NANOS_PER_MILLI, REPLACEMENT, USER_FIELD,
};
use crate::store::bound_record;
use crate::types::MicrosFn;
use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::pg::pg_executor;
use alerts::store::{
    check_alert, insert_alerts, summarise, MAX_ALERTS_PER_INSERT, MAX_ENTITY_CHARS, MAX_EVENT_IDS, MAX_EVENT_ID_CHARS, MAX_RULE_ID_CHARS,
    MAX_TITLE_CHARS, MIGRATIONS, MIGRATION_NAMESPACE,
};
use alerts::types::Executor;
use core_config::reload::{current_config, ReloadEngine};
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::PgSettings;
use serde_json::json;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use stream_correlation::level::Level;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::runtime::{Builder, Runtime};
use tokio_postgres::Client;
use tracing::debug;


pub const DATABASE_WORKERS: usize = 1;


pub fn severity_of(level: Level) -> Severity {
    match level {
        Level::Informational => Severity::Informational,
        Level::Low => Severity::Low,
        Level::Medium => Severity::Medium,
        Level::High => Severity::High,
        Level::Critical => Severity::Critical,
    }
}


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


/// The event time as RFC 3339, clamped into years 0 to 9999 (the range the text can express); `clamped_ms` says which instant is written.
pub fn clamped_ms(last_ms: i64) -> i64 {
    last_ms.clamp(MIN_EVENT_MS, MAX_EVENT_MS)
}


pub fn event_time_text(last_ms: i64) -> Result<String, SinkError> {
    let moment = OffsetDateTime::from_unix_timestamp_nanos(i128::from(clamped_ms(last_ms)) * NANOS_PER_MILLI).map_err(SinkError::EventTimeRange)?;
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
        "event_time_clamped": clamped_ms(record.last_ms) != record.last_ms,
    }));
    Ok(Alert {
        id: alert_id(&record.tenant, &rule_id, &event_ids),
        tenant: record.tenant.clone(),
        rule_id,
        rule_title: bounded_text(&record.rule_title, MAX_TITLE_CHARS),
        severity: severity_of(record.level),
        event_time: event_time_text(record.last_ms)?,
        created_micros,
        host_name: entity_of(record, HOST_FIELD),
        user_name: entity_of(record, USER_FIELD),
        event_ids,
        summary,
    })
}


/// Every check the store makes before any SQL, run in memory on one record.
pub fn check_record(scope: &TenantScope, record: &AlertRecord) -> Result<(), SinkError> {
    let alert = alert_of(record, 0)?;
    check_alert(scope, &alert).map_err(SinkError::Store)
}


/// The records the store would accept and the refusals of the others, found without a connection.
pub fn screen_records(tenant: &str, records: &[AlertRecord]) -> Result<(Vec<AlertRecord>, Vec<SinkError>), SinkError> {
    let scope = tenant_scope(tenant).map_err(SinkError::Database)?;
    let (valid, refused): (Vec<_>, Vec<_>) = records
        .iter()
        .map(|record| check_record(&scope, record).map(|()| record.clone()))
        .partition(Result::is_ok);
    Ok((
        valid.into_iter().flatten().collect(),
        refused.into_iter().filter_map(Result::err).collect(),
    ))
}


/// Only a transport or connection failure spoils the connection; a refusal or an answer the server gave leaves it usable.
pub fn is_transport(error: &SinkError) -> bool {
    matches!(error, SinkError::Store(StoreError::Pg(inner)) if !matches!(inner, PgError::Server { .. }))
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
    let mapped: Vec<Alert> = records
        .iter()
        .map(|record| alert_of(record, created_micros))
        .collect::<Result<_, SinkError>>()?;
    mapped.chunks(MAX_ALERTS_PER_INSERT).try_fold(0, |stored, chunk| {
        runtime
            .block_on(insert_alerts(exec, &scope, chunk))
            .map(|fresh| stored + fresh)
            .map_err(SinkError::Store)
    })
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


/// Commits through the kept connection, opening one when there is none or it closed; a transport failure drops the connection, so the retry reconnects with the settings then in force.
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
    let outcome = {
        let exec = pg_executor(&client, deadline);
        commit_with(&store.runtime, &exec, tenant, records, (store.clock)())
    };
    if !outcome.as_ref().is_err_and(is_transport) {
        *slot = Some(client);
    }
    outcome
}


pub fn pg_commit(store: &AlertStore, tenant: &str, records: &[AlertRecord]) -> Result<usize, SinkError> {
    match store {
        AlertStore::Postgres(inner) => commit_pg(inner, tenant, records),
        AlertStore::File(_) => Err(SinkError::WrongStore),
    }
}
