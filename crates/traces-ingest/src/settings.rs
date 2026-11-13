use crate::model::Limits;
use core_config::load::load_file;
use metrics_ingest::settings::{check_limit_rows, default_timeout_ms, to_u64, validate_connection, LoadError, MetricsSettings, SettingsError};
use metrics_ingest::types::LimitRow;
use serde::Deserialize;
use std::path::{Path, PathBuf};


pub const CEILING_FACTOR: u64 = 10;


pub const LIMIT_COUNT: usize = 20;


pub const MAX_RETENTION_SECONDS_CEILING: u64 = 2_592_000;


/// Read afresh at every run; the password is only a path here, and `limits` keeps the decode, encode and batch caps.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TracesSettings {
    pub url: String,
    pub user: String,
    pub password_file: PathBuf,
    pub ca_file: Option<PathBuf>,
    pub database: String,
    pub table: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub limits: Limits,
}


/// The connection part for metrics-ingest's sender; its own `limits` stay at their defaults and are unused.
pub fn to_metrics_settings(settings: &TracesSettings) -> MetricsSettings {
    MetricsSettings {
        url: settings.url.clone(),
        user: settings.user.clone(),
        password_file: settings.password_file.clone(),
        ca_file: settings.ca_file.clone(),
        database: settings.database.clone(),
        table: settings.table.clone(),
        timeout_ms: settings.timeout_ms,
        limits: metrics_ingest::model::Limits::default(),
    }
}


/// Ten times the default: the largest value whose worst accepted shape was not measured.
pub fn ceiling(default: usize) -> u64 {
    to_u64(default) * CEILING_FACTOR
}


/// Every field of `Limits` within its floor and its ceiling; the first one outside is named.
pub fn validate_trace_limits(limits: &Limits) -> Result<(), SettingsError> {
    let defaults = Limits::default();
    let rows: [LimitRow; LIMIT_COUNT] = [
        (
            "max_request_bytes",
            to_u64(limits.max_request_bytes),
            1,
            ceiling(defaults.max_request_bytes),
        ),
        (
            "max_resource_spans",
            to_u64(limits.max_resource_spans),
            1,
            ceiling(defaults.max_resource_spans),
        ),
        ("max_spans", to_u64(limits.max_spans), 1, ceiling(defaults.max_spans)),
        (
            "max_total_attributes",
            to_u64(limits.max_total_attributes),
            1,
            ceiling(defaults.max_total_attributes),
        ),
        ("max_events_total", to_u64(limits.max_events_total), 1, ceiling(defaults.max_events_total)),
        ("max_links_total", to_u64(limits.max_links_total), 1, ceiling(defaults.max_links_total)),
        (
            "max_value_elements_total",
            to_u64(limits.max_value_elements_total),
            1,
            ceiling(defaults.max_value_elements_total),
        ),
        (
            "max_entity_refs_total",
            to_u64(limits.max_entity_refs_total),
            1,
            ceiling(defaults.max_entity_refs_total),
        ),
        (
            "max_entity_keys_total",
            to_u64(limits.max_entity_keys_total),
            1,
            ceiling(defaults.max_entity_keys_total),
        ),
        (
            "max_attributes_per_span",
            to_u64(limits.max_attributes_per_span),
            1,
            ceiling(defaults.max_attributes_per_span),
        ),
        (
            "max_events_per_span",
            to_u64(limits.max_events_per_span),
            1,
            ceiling(defaults.max_events_per_span),
        ),
        (
            "max_links_per_span",
            to_u64(limits.max_links_per_span),
            1,
            ceiling(defaults.max_links_per_span),
        ),
        ("max_name_bytes", to_u64(limits.max_name_bytes), 1, ceiling(defaults.max_name_bytes)),
        (
            "max_attribute_key_bytes",
            to_u64(limits.max_attribute_key_bytes),
            1,
            ceiling(defaults.max_attribute_key_bytes),
        ),
        (
            "max_attribute_value_bytes",
            to_u64(limits.max_attribute_value_bytes),
            1,
            ceiling(defaults.max_attribute_value_bytes),
        ),
        (
            "max_status_message_bytes",
            to_u64(limits.max_status_message_bytes),
            1,
            ceiling(defaults.max_status_message_bytes),
        ),
        (
            "max_future_skew_seconds",
            limits.max_future_skew_seconds,
            0,
            defaults.max_future_skew_seconds * CEILING_FACTOR,
        ),
        ("max_batch_rows", to_u64(limits.max_batch_rows), 1, ceiling(defaults.max_batch_rows)),
        ("max_batch_bytes", to_u64(limits.max_batch_bytes), 1, ceiling(defaults.max_batch_bytes)),
        ("retention_seconds", limits.retention_seconds, 1, MAX_RETENTION_SECONDS_CEILING),
    ];
    check_limit_rows(&rows)
}


/// Strict YAML through core-config, then connection and limits validated; called once per run so a changed file applies at the next one.
pub fn load_traces_settings(path: &Path) -> Result<TracesSettings, LoadError> {
    let settings = load_file::<TracesSettings>(path)?;
    validate_connection(&to_metrics_settings(&settings))?;
    validate_trace_limits(&settings.limits)?;
    Ok(settings)
}
