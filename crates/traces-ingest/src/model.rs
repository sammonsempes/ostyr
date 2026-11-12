use crate::types::{Attributes, Dropped, SpanId, TraceId};
use core_pg::error::PgError;
use opentelemetry_proto::tonic::trace::v1::{span::SpanKind, status::StatusCode};
use std::fmt::{Display, Formatter, Result as FmtResult};
use thiserror::Error;


pub const TRACE_ID_BYTES: usize = 16;


pub const SPAN_ID_BYTES: usize = 8;


pub const DEFAULT_MAX_REQUEST_BYTES: usize = 4_194_304;


pub const DEFAULT_MAX_RESOURCE_SPANS: usize = 256;


pub const DEFAULT_MAX_SPANS: usize = 50_000;


pub const DEFAULT_MAX_TOTAL_ATTRIBUTES: usize = 500_000;


pub const DEFAULT_MAX_EVENTS_TOTAL: usize = 100_000;


pub const DEFAULT_MAX_LINKS_TOTAL: usize = 100_000;


pub const DEFAULT_MAX_VALUE_ELEMENTS_TOTAL: usize = 200_000;


pub const DEFAULT_MAX_ENTITY_REFS_TOTAL: usize = 1_024;


pub const DEFAULT_MAX_ENTITY_KEYS_TOTAL: usize = 4_096;


pub const DEFAULT_MAX_ATTRIBUTES_PER_SPAN: usize = 128;


pub const DEFAULT_MAX_EVENTS_PER_SPAN: usize = 128;


pub const DEFAULT_MAX_LINKS_PER_SPAN: usize = 128;


pub const DEFAULT_MAX_NAME_BYTES: usize = 256;


pub const DEFAULT_MAX_ATTRIBUTE_KEY_BYTES: usize = 128;


pub const DEFAULT_MAX_ATTRIBUTE_VALUE_BYTES: usize = 1_024;


pub const DEFAULT_MAX_STATUS_MESSAGE_BYTES: usize = 1_024;


pub const DEFAULT_MAX_FUTURE_SKEW_SECONDS: u64 = 300;


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_request_bytes: usize,
    pub max_resource_spans: usize,
    pub max_spans: usize,
    pub max_total_attributes: usize,
    pub max_events_total: usize,
    pub max_links_total: usize,
    pub max_value_elements_total: usize,
    pub max_entity_refs_total: usize,
    pub max_entity_keys_total: usize,
    pub max_attributes_per_span: usize,
    pub max_events_per_span: usize,
    pub max_links_per_span: usize,
    pub max_name_bytes: usize,
    pub max_attribute_key_bytes: usize,
    pub max_attribute_value_bytes: usize,
    pub max_status_message_bytes: usize,
    pub max_future_skew_seconds: u64,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_resource_spans: DEFAULT_MAX_RESOURCE_SPANS,
            max_spans: DEFAULT_MAX_SPANS,
            max_total_attributes: DEFAULT_MAX_TOTAL_ATTRIBUTES,
            max_events_total: DEFAULT_MAX_EVENTS_TOTAL,
            max_links_total: DEFAULT_MAX_LINKS_TOTAL,
            max_value_elements_total: DEFAULT_MAX_VALUE_ELEMENTS_TOTAL,
            max_entity_refs_total: DEFAULT_MAX_ENTITY_REFS_TOTAL,
            max_entity_keys_total: DEFAULT_MAX_ENTITY_KEYS_TOTAL,
            max_attributes_per_span: DEFAULT_MAX_ATTRIBUTES_PER_SPAN,
            max_events_per_span: DEFAULT_MAX_EVENTS_PER_SPAN,
            max_links_per_span: DEFAULT_MAX_LINKS_PER_SPAN,
            max_name_bytes: DEFAULT_MAX_NAME_BYTES,
            max_attribute_key_bytes: DEFAULT_MAX_ATTRIBUTE_KEY_BYTES,
            max_attribute_value_bytes: DEFAULT_MAX_ATTRIBUTE_VALUE_BYTES,
            max_status_message_bytes: DEFAULT_MAX_STATUS_MESSAGE_BYTES,
            max_future_skew_seconds: DEFAULT_MAX_FUTURE_SKEW_SECONDS,
        }
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct SpanRow {
    pub tenant: String,
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: Option<SpanId>,
    pub service_name: String,
    pub name: String,
    pub kind: SpanKind,
    pub start_nanos: u64,
    pub end_nanos: u64,
    pub status_code: StatusCode,
    pub status_message: String,
    pub attributes: Attributes,
    pub event_count: u64,
    pub link_count: u64,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DropReason {
    BadId,
    BadTime,
    FutureSkew,
    BadKind,
    BadStatus,
    BadText,
    TextTooLong,
    UnsupportedValue,
    TooManyAttributes,
    TooManyEvents,
    TooManyLinks,
}


#[derive(Debug, Error)]
pub enum Refusal {
    #[error("the tenant is not a valid scope")]
    InvalidTenant(#[source] PgError),
    #[error("the request is {bytes} bytes, over the limit")]
    TooLarge { bytes: usize },
    #[error("the request is not a valid protobuf message")]
    Malformed(#[from] prost::DecodeError),
    #[error("{count} resource spans, over the limit")]
    TooManyResourceSpans { count: usize },
    #[error("{count} spans or scopes, over the limit")]
    TooManySpans { count: usize },
    #[error("{count} attributes, over the limit")]
    TooManyAttributes { count: usize },
    #[error("{count} events, over the limit")]
    TooManyEvents { count: usize },
    #[error("{count} links, over the limit")]
    TooManyLinks { count: usize },
    #[error("{count} array or key-value list elements, over the limit")]
    TooManyValueElements { count: usize },
    #[error("{count} resource entity references, over the limit")]
    TooManyEntityRefs { count: usize },
    #[error("{count} entity reference keys, over the limit")]
    TooManyEntityKeys { count: usize },
}


/// Wire counts of one request, summed over every resource, scope, span, event, link and attribute value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub resources: usize,
    pub scopes: usize,
    pub spans: usize,
    pub events: usize,
    pub links: usize,
    pub attributes: usize,
    pub elements: usize,
    pub entity_refs: usize,
    pub entity_keys: usize,
}


#[derive(Debug)]
pub struct Outcome {
    pub tenant: String,
    pub rows: Vec<SpanRow>,
    pub dropped: Dropped,
    pub sampled_out: u64,
    pub refusal: Option<Refusal>,
}


impl Display for DropReason {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        let name = match self {
            Self::BadId => "bad_id",
            Self::BadTime => "bad_time",
            Self::FutureSkew => "future_skew",
            Self::BadKind => "bad_kind",
            Self::BadStatus => "bad_status",
            Self::BadText => "bad_text",
            Self::TextTooLong => "text_too_long",
            Self::UnsupportedValue => "unsupported_value",
            Self::TooManyAttributes => "too_many_attributes",
            Self::TooManyEvents => "too_many_events",
            Self::TooManyLinks => "too_many_links",
        };
        formatter.write_str(name)
    }
}
