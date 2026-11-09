use crate::types::{Dropped, Labels};
use std::fmt::{Display, Formatter, Result as FmtResult};


pub const DEFAULT_MAX_REQUEST_BYTES: usize = 4_194_304;


pub const DEFAULT_MAX_RESOURCES: usize = 256;


pub const DEFAULT_MAX_DATA_POINTS: usize = 50_000;


pub const DEFAULT_MAX_TOTAL_ATTRIBUTES: usize = 2_000_000;


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


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_request_bytes: usize,
    pub max_resources: usize,
    pub max_data_points: usize,
    pub max_total_attributes: usize,
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
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_resources: DEFAULT_MAX_RESOURCES,
            max_data_points: DEFAULT_MAX_DATA_POINTS,
            max_total_attributes: DEFAULT_MAX_TOTAL_ATTRIBUTES,
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


#[derive(Clone, Debug, PartialEq)]
pub enum Refusal {
    TooLarge { bytes: usize },
    Malformed(prost::DecodeError),
    TooManyResources { count: usize },
    TooManyDataPoints { count: usize },
    TooManyAttributes { count: usize },
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
