use crate::types::{Dropped, Labels};
use serde::Deserialize;
use std::fmt::{Display, Formatter, Result as FmtResult};


pub const DEFAULT_MAX_REQUEST_BYTES: usize = 4_194_304;


pub const DEFAULT_MAX_RESOURCES: usize = 256;


pub const DEFAULT_MAX_DATA_POINTS: usize = 50_000;


pub const DEFAULT_MAX_TOTAL_ATTRIBUTES: usize = 250_000;


pub const DEFAULT_MAX_ENTITY_REFS_TOTAL: usize = 1_024;


pub const DEFAULT_MAX_ENTITY_KEYS_TOTAL: usize = 4_096;


pub const DEFAULT_MAX_LABELS: usize = 32;


pub const DEFAULT_MAX_LABEL_KEY_BYTES: usize = 128;


pub const DEFAULT_MAX_LABEL_VALUE_BYTES: usize = 256;


pub const DEFAULT_MAX_NAME_BYTES: usize = 256;


pub const DEFAULT_MAX_BUCKETS: usize = 160;


pub const DEFAULT_MAX_SERIES_PER_TENANT: usize = 100_000;


pub const DEFAULT_MAX_VALUES_PER_LABEL: usize = 10_000;


pub const DEFAULT_MAX_LABEL_KEYS_PER_TENANT: usize = 1_000;


pub const DEFAULT_MAX_STATE_BYTES_PER_TENANT: usize = 67_108_864;


pub const DEFAULT_MAX_BATCH_ROWS: usize = 10_000;


pub const DEFAULT_MAX_BATCH_BYTES: usize = 4_194_304;


pub const DEFAULT_MAX_FUTURE_SKEW_SECONDS: u64 = 300;


pub const DEFAULT_RAW_RETENTION_SECONDS: u64 = 604_800;


#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub max_request_bytes: usize,
    pub max_resources: usize,
    pub max_data_points: usize,
    pub max_total_attributes: usize,
    pub max_entity_refs_total: usize,
    pub max_entity_keys_total: usize,
    pub max_labels: usize,
    pub max_label_key_bytes: usize,
    pub max_label_value_bytes: usize,
    pub max_name_bytes: usize,
    pub max_buckets: usize,
    pub max_series_per_tenant: usize,
    pub max_values_per_label: usize,
    pub max_label_keys_per_tenant: usize,
    pub max_state_bytes_per_tenant: usize,
    pub max_batch_rows: usize,
    pub max_batch_bytes: usize,
    pub max_future_skew_seconds: u64,
    pub raw_retention_seconds: u64,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_resources: DEFAULT_MAX_RESOURCES,
            max_data_points: DEFAULT_MAX_DATA_POINTS,
            max_total_attributes: DEFAULT_MAX_TOTAL_ATTRIBUTES,
            max_entity_refs_total: DEFAULT_MAX_ENTITY_REFS_TOTAL,
            max_entity_keys_total: DEFAULT_MAX_ENTITY_KEYS_TOTAL,
            max_labels: DEFAULT_MAX_LABELS,
            max_label_key_bytes: DEFAULT_MAX_LABEL_KEY_BYTES,
            max_label_value_bytes: DEFAULT_MAX_LABEL_VALUE_BYTES,
            max_name_bytes: DEFAULT_MAX_NAME_BYTES,
            max_buckets: DEFAULT_MAX_BUCKETS,
            max_series_per_tenant: DEFAULT_MAX_SERIES_PER_TENANT,
            max_values_per_label: DEFAULT_MAX_VALUES_PER_LABEL,
            max_label_keys_per_tenant: DEFAULT_MAX_LABEL_KEYS_PER_TENANT,
            max_state_bytes_per_tenant: DEFAULT_MAX_STATE_BYTES_PER_TENANT,
            max_batch_rows: DEFAULT_MAX_BATCH_ROWS,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            max_future_skew_seconds: DEFAULT_MAX_FUTURE_SKEW_SECONDS,
            raw_retention_seconds: DEFAULT_RAW_RETENTION_SECONDS,
        }
    }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricKind {
    Gauge,
    Counter,
    Histogram,
}


#[derive(Clone, Debug, PartialEq)]
pub struct Bucket {
    pub upper_bound: f64,
    pub count: u64,
}


#[derive(Clone, Debug, PartialEq)]
pub struct SampleRow {
    pub tenant: String,
    pub name: String,
    pub unit: String,
    pub kind: MetricKind,
    pub monotonic: bool,
    pub labels: Labels,
    pub timestamp_nanos: u64,
    pub value: f64,
    pub buckets: Vec<Bucket>,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DropReason {
    EmptyName,
    TextTooLong,
    ControlCharacter,
    TooManyLabels,
    UnsupportedLabelValue,
    MissingValue,
    MissingData,
    TooManyBuckets,
    MalformedHistogram,
    UnsupportedExponentialHistogram,
    UnsupportedSummary,
    SeriesCap,
    LabelValueCap,
    LabelKeyCap,
    StateBytesCap,
}


/// Wire counts of one request (points, scopes and exemplars share `max_data_points`): resources, scopes, metrics counted as at least one point, exemplars, attributes and value elements, entity references and their keys.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub resources: usize,
    pub scopes: usize,
    pub points: usize,
    pub extras: usize,
    pub attributes: usize,
    pub entity_refs: usize,
    pub entity_keys: usize,
}


/// The wire field numbers of one metric data kind: the data message, and in its points the attributes and the exemplars or quantiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PointKind {
    pub data_field: u32,
    pub attributes_field: u32,
    pub extras_field: u32,
}


#[derive(Clone, Debug, PartialEq)]
pub enum Refusal {
    TooLarge { bytes: usize },
    Malformed(prost::DecodeError),
    TooManyResources { count: usize },
    TooManyDataPoints { count: usize },
    TooManyAttributes { count: usize },
    TooManyEntityRefs { count: usize },
    TooManyEntityKeys { count: usize },
}


impl From<prost::DecodeError> for Refusal {
    fn from(error: prost::DecodeError) -> Self {
        Refusal::Malformed(error)
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct Outcome {
    pub tenant: String,
    pub rows: Vec<SampleRow>,
    pub dropped: Dropped,
    pub refusal: Option<Refusal>,
}


impl Display for DropReason {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        let name = match self {
            Self::EmptyName => "empty_name",
            Self::TextTooLong => "text_too_long",
            Self::ControlCharacter => "control_character",
            Self::TooManyLabels => "too_many_labels",
            Self::UnsupportedLabelValue => "unsupported_label_value",
            Self::MissingValue => "missing_value",
            Self::MissingData => "missing_data",
            Self::TooManyBuckets => "too_many_buckets",
            Self::MalformedHistogram => "malformed_histogram",
            Self::UnsupportedExponentialHistogram => "unsupported_exponential_histogram",
            Self::UnsupportedSummary => "unsupported_summary",
            Self::SeriesCap => "series_cap",
            Self::LabelValueCap => "label_value_cap",
            Self::LabelKeyCap => "label_key_cap",
            Self::StateBytesCap => "state_bytes_cap",
        };
        formatter.write_str(name)
    }
}
