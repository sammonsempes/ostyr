use crate::model::{DropReason, Limits, Outcome, Refusal, SpanRow};
use crate::sampling::{keep_span, Sampling};
use crate::types::{Attributes, ServiceName, SpanId, TraceId, WireField};
use core_pg::scope::tenant_scope;
use metrics_ingest::decode::{is_forbidden, to_count};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value::Value as AnyKind, ArrayValue, KeyValue};
use opentelemetry_proto::tonic::trace::v1::{span::SpanKind, status::StatusCode, Span};
use prost::encoding::{decode_key, decode_varint, skip_field, DecodeContext, WireType};
use prost::{DecodeError, Message};
use std::collections::BTreeMap;


pub const SERVICE_NAME_KEY: &str = "service.name";


pub const UNKNOWN_SERVICE: &str = "unknown_service";


pub const NANOS_PER_SECOND: u64 = 1_000_000_000;


pub const RESOURCE_SPANS_FIELD: u32 = 1;


pub const SCOPE_SPANS_FIELD: u32 = 2;


pub const SPANS_FIELD: u32 = 2;


pub const BYTES_PER_HEX_PAIR: usize = 2;


pub struct Context<'a> {
    pub limits: &'a Limits,
    pub sampling: &'a Sampling,
    pub now_nanos: u64,
}


pub fn count_drop(outcome: &mut Outcome, reason: DropReason, amount: usize) {
    let total = outcome.dropped.entry(reason).or_insert(0);
    *total = total.saturating_add(to_count(amount));
}


/// Decodes one OTLP trace export for `tenant`, which the caller authenticated; the payload never chooses it.
pub fn decode_traces(bytes: &[u8], tenant: &str, limits: &Limits, sampling: &Sampling, now_nanos: u64) -> Outcome {
    let mut outcome = Outcome {
        tenant: String::new(),
        rows: Vec::new(),
        dropped: BTreeMap::new(),
        sampled_out: 0,
        refusal: None,
    };
    let context = Context { limits, sampling, now_nanos };
    let parsed = tenant_scope(tenant)
        .map_err(Refusal::InvalidTenant)
        .and_then(|_| parse_request(bytes, limits));
    match parsed {
        Ok(request) => {
            outcome.tenant = tenant.to_string();
            collect(&request, &context, &mut outcome);
        }
        Err(refusal) => outcome.refusal = Some(refusal),
    }
    outcome
}


pub fn parse_request(bytes: &[u8], limits: &Limits) -> Result<ExportTraceServiceRequest, Refusal> {
    check_size(bytes.len(), limits)?;
    scan_counts(bytes, limits)?;
    let request = ExportTraceServiceRequest::decode(bytes).map_err(Refusal::Malformed)?;
    check_counts(&request, limits)?;
    Ok(request)
}


pub fn read_field<'a>(buf: &mut &'a [u8]) -> WireField<'a> {
    let (tag, wire_type) = decode_key(buf)?;
    let context = DecodeContext::default();
    if wire_type == WireType::LengthDelimited {
        let mut peek = *buf;
        let declared = decode_varint(&mut peek)?;
        skip_field(wire_type, tag, buf, context)?;
        Ok((tag, usize::try_from(declared).ok().and_then(|size| peek.get(..size))))
    } else {
        skip_field(wire_type, tag, buf, context)?;
        Ok((tag, None))
    }
}


/// The fields of one message, in order; each step consumes at least one byte, so the walk ends with the buffer.
pub fn fields(bytes: &[u8]) -> impl Iterator<Item = WireField<'_>> {
    let mut rest = bytes;
    std::iter::from_fn(move || if rest.is_empty() { None } else { Some(read_field(&mut rest)) })
}


pub fn count_one(_payload: &[u8]) -> Result<usize, DecodeError> {
    Ok(1)
}


/// Sums `inner` over the length-delimited fields with `tag` of one message, without decoding anything.
pub fn sum_nested(bytes: &[u8], tag: u32, inner: fn(&[u8]) -> Result<usize, DecodeError>) -> Result<usize, DecodeError> {
    fields(bytes).try_fold(usize::default(), |total, field| {
        let (found, payload) = field?;
        match payload {
            Some(nested) if found == tag => inner(nested).map(|count| total.saturating_add(count)),
            _ => Ok(total),
        }
    })
}


pub fn scopes_in_resource(resource: &[u8]) -> Result<usize, DecodeError> {
    sum_nested(resource, SCOPE_SPANS_FIELD, count_one)
}


pub fn spans_in_scope(scope: &[u8]) -> Result<usize, DecodeError> {
    sum_nested(scope, SPANS_FIELD, count_one)
}


pub fn spans_in_resource(resource: &[u8]) -> Result<usize, DecodeError> {
    sum_nested(resource, SCOPE_SPANS_FIELD, spans_in_scope)
}


/// Counts resource spans, scopes and spans on the wire (three fixed levels) and refuses before prost allocates a message per span.
pub fn scan_counts(bytes: &[u8], limits: &Limits) -> Result<(), Refusal> {
    let resources = sum_nested(bytes, RESOURCE_SPANS_FIELD, count_one).map_err(Refusal::Malformed)?;
    if resources > limits.max_resource_spans {
        Err(Refusal::TooManyResourceSpans { count: resources })
    } else {
        let scopes = sum_nested(bytes, RESOURCE_SPANS_FIELD, scopes_in_resource).map_err(Refusal::Malformed)?;
        let spans = sum_nested(bytes, RESOURCE_SPANS_FIELD, spans_in_resource).map_err(Refusal::Malformed)?;
        let widest = scopes.max(spans);
        if widest > limits.max_spans {
            Err(Refusal::TooManySpans { count: widest })
        } else {
            Ok(())
        }
    }
}


pub fn check_size(bytes: usize, limits: &Limits) -> Result<(), Refusal> {
    if bytes > limits.max_request_bytes {
        Err(Refusal::TooLarge { bytes })
    } else {
        Ok(())
    }
}


pub fn attributes_in(span: &Span) -> usize {
    let events: usize = span.events.iter().map(|event| event.attributes.len()).sum();
    let links: usize = span.links.iter().map(|link| link.attributes.len()).sum();
    span.attributes.len().saturating_add(events).saturating_add(links)
}


/// The attribute total of the decoded message, checked before any row is built; resource and span counts were refused by the wire scan.
pub fn check_counts(request: &ExportTraceServiceRequest, limits: &Limits) -> Result<(), Refusal> {
    let spans = || {
        request
            .resource_spans
            .iter()
            .flat_map(|resource| resource.scope_spans.iter())
            .flat_map(|scope| scope.spans.iter())
    };
    let resource_attributes: usize = request
        .resource_spans
        .iter()
        .map(|resource| resource.resource.as_ref().map_or(0, |described| described.attributes.len()))
        .sum();
    let attributes = spans().map(attributes_in).sum::<usize>().saturating_add(resource_attributes);
    if attributes > limits.max_total_attributes {
        Err(Refusal::TooManyAttributes { count: attributes })
    } else {
        Ok(())
    }
}


pub fn collect(request: &ExportTraceServiceRequest, context: &Context, outcome: &mut Outcome) {
    request.resource_spans.iter().for_each(|resource| {
        let attributes = resource.resource.as_ref().map_or(&[][..], |described| described.attributes.as_slice());
        let service = service_name(attributes, context.limits);
        resource.scope_spans.iter().flat_map(|scope| scope.spans.iter()).for_each(|span| {
            handle_span(context, &service, span, outcome);
        });
    });
}


pub fn count_unsupported(outcome: &mut Outcome, unsupported: usize) {
    if unsupported > 0 {
        count_drop(outcome, DropReason::UnsupportedValue, unsupported);
    }
}


pub fn handle_span(context: &Context, service: &ServiceName, span: &Span, outcome: &mut Outcome) {
    match build_row(context, service, span, &outcome.tenant) {
        Ok((row, unsupported)) => {
            count_unsupported(outcome, unsupported);
            if keep_span(context.sampling, &row.service_name, &row.trace_id, row.status_code == StatusCode::Error) {
                outcome.rows.push(row);
            } else {
                outcome.sampled_out = outcome.sampled_out.saturating_add(1);
            }
        }
        Err(reason) => count_drop(outcome, reason, 1),
    }
}


/// The text of `service.name` when it is a valid string, `unknown_service` when absent or not a string.
pub fn service_name(resource: &[KeyValue], limits: &Limits) -> ServiceName {
    let found = resource
        .iter()
        .find(|pair| pair.key == SERVICE_NAME_KEY)
        .and_then(|pair| pair.value.as_ref())
        .and_then(|any| any.value.as_ref());
    match found {
        Some(AnyKind::StringValue(text)) if !text.is_empty() => text_checked(text, limits.max_name_bytes),
        _ => Ok(UNKNOWN_SERVICE.to_string()),
    }
}


pub fn text_problem(text: &str, max_bytes: usize) -> Option<DropReason> {
    if text.len() > max_bytes {
        Some(DropReason::TextTooLong)
    } else if text.chars().any(is_forbidden) {
        Some(DropReason::BadText)
    } else {
        None
    }
}


pub fn text_checked(text: &str, max_bytes: usize) -> Result<String, DropReason> {
    text_problem(text, max_bytes).map_or_else(|| Ok(text.to_string()), Err)
}


pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}


pub fn is_nonzero(id: &[u8]) -> bool {
    id.iter().any(|byte| *byte != 0)
}


pub fn trace_id_of(bytes: &[u8]) -> Result<TraceId, DropReason> {
    TraceId::try_from(bytes).ok().filter(|id| is_nonzero(id)).ok_or(DropReason::BadId)
}


pub fn span_id_of(bytes: &[u8]) -> Result<SpanId, DropReason> {
    SpanId::try_from(bytes).ok().filter(|id| is_nonzero(id)).ok_or(DropReason::BadId)
}


pub fn parent_id_of(bytes: &[u8]) -> Result<Option<SpanId>, DropReason> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        span_id_of(bytes).map(Some)
    }
}


pub fn check_times(span: &Span, limits: &Limits, now_nanos: u64) -> Result<(), DropReason> {
    let newest = now_nanos.saturating_add(limits.max_future_skew_seconds.saturating_mul(NANOS_PER_SECOND));
    if span.end_time_unix_nano < span.start_time_unix_nano {
        Err(DropReason::BadTime)
    } else if span.end_time_unix_nano > newest {
        Err(DropReason::FutureSkew)
    } else {
        Ok(())
    }
}


pub fn check_span_counts(span: &Span, limits: &Limits) -> Result<(), DropReason> {
    if span.attributes.len() > limits.max_attributes_per_span {
        Err(DropReason::TooManyAttributes)
    } else if span.events.len() > limits.max_events_per_span {
        Err(DropReason::TooManyEvents)
    } else if span.links.len() > limits.max_links_per_span {
        Err(DropReason::TooManyLinks)
    } else {
        Ok(())
    }
}


/// The status code and its message, bounded; an absent status is unset.
pub fn status_of(span: &Span, limits: &Limits) -> Result<(StatusCode, String), DropReason> {
    match &span.status {
        Some(status) => {
            let code = StatusCode::try_from(status.code).map_err(|_| DropReason::BadStatus)?;
            text_checked(&status.message, limits.max_status_message_bytes).map(|message| (code, message))
        }
        None => Ok((StatusCode::Unset, String::new())),
    }
}


pub fn scalar_text(value: &AnyKind, max_bytes: usize) -> Result<String, DropReason> {
    match value {
        AnyKind::StringValue(text) => text_checked(text, max_bytes),
        AnyKind::BoolValue(flag) => text_checked(&flag.to_string(), max_bytes),
        AnyKind::IntValue(number) => text_checked(&number.to_string(), max_bytes),
        AnyKind::DoubleValue(number) => text_checked(&number.to_string(), max_bytes),
        AnyKind::BytesValue(bytes) if bytes.len().saturating_mul(BYTES_PER_HEX_PAIR) <= max_bytes => Ok(to_hex(bytes)),
        AnyKind::BytesValue(_) => Err(DropReason::TextTooLong),
        _ => Err(DropReason::UnsupportedValue),
    }
}


/// Elements of an array through `scalar_text`, comma-joined; stops as soon as the joined text passes `max_bytes`.
pub fn array_text(array: &ArrayValue, max_bytes: usize) -> Result<String, DropReason> {
    array.values.iter().try_fold(String::new(), |joined, element| {
        let text = scalar_text(element.value.as_ref().ok_or(DropReason::UnsupportedValue)?, max_bytes)?;
        let separator = if joined.is_empty() { 0 } else { 1 };
        if joined.len().saturating_add(separator).saturating_add(text.len()) > max_bytes {
            Err(DropReason::TextTooLong)
        } else if joined.is_empty() {
            Ok(text)
        } else {
            Ok(format!("{joined},{text}"))
        }
    })
}


/// Scalars as `scalar_text`, arrays of scalars comma-joined one level deep; nested arrays, key-value lists and empty values are unsupported.
pub fn value_text(value: Option<&AnyKind>, max_bytes: usize) -> Result<String, DropReason> {
    match value {
        Some(AnyKind::ArrayValue(array)) => array_text(array, max_bytes),
        Some(scalar) => scalar_text(scalar, max_bytes),
        None => Err(DropReason::UnsupportedValue),
    }
}


pub fn attribute_pair(pair: &KeyValue, limits: &Limits) -> Result<(String, String), DropReason> {
    let value = value_text(pair.value.as_ref().and_then(|any| any.value.as_ref()), limits.max_attribute_value_bytes)?;
    if pair.key.is_empty() {
        Err(DropReason::BadText)
    } else {
        text_checked(&pair.key, limits.max_attribute_key_bytes).map(|key| (key, value))
    }
}


/// Attributes sorted by key (last value wins on a repeated key) and the count of attributes left out as unsupported values.
pub fn attributes_of(span: &Span, limits: &Limits) -> Result<(Attributes, usize), DropReason> {
    let results = span.attributes.iter().map(|pair| attribute_pair(pair, limits));
    let (kept, unsupported) = results
        .into_iter()
        .try_fold((BTreeMap::new(), usize::default()), |(mut pairs, skipped), result| match result {
            Ok((key, value)) => {
                pairs.insert(key, value);
                Ok((pairs, skipped))
            }
            Err(DropReason::UnsupportedValue) => Ok((pairs, skipped.saturating_add(1))),
            Err(reason) => Err(reason),
        })?;
    Ok((kept.into_iter().collect(), unsupported))
}


pub fn build_row(context: &Context, service: &ServiceName, span: &Span, tenant: &str) -> Result<(SpanRow, usize), DropReason> {
    let limits = context.limits;
    let service_name = service.clone()?;
    check_span_counts(span, limits)?;
    let trace_id = trace_id_of(&span.trace_id)?;
    let span_id = span_id_of(&span.span_id)?;
    let parent_span_id = parent_id_of(&span.parent_span_id)?;
    check_times(span, limits, context.now_nanos)?;
    let kind = SpanKind::try_from(span.kind).map_err(|_| DropReason::BadKind)?;
    let (status_code, status_message) = status_of(span, limits)?;
    let name = text_checked(&span.name, limits.max_name_bytes)?;
    let (attributes, unsupported) = attributes_of(span, limits)?;
    let row = SpanRow {
        tenant: tenant.to_string(),
        trace_id,
        span_id,
        parent_span_id,
        service_name,
        name,
        kind,
        start_nanos: span.start_time_unix_nano,
        end_nanos: span.end_time_unix_nano,
        status_code,
        status_message,
        attributes,
        event_count: to_count(span.events.len()),
        link_count: to_count(span.links.len()),
    };
    Ok((row, unsupported))
}
