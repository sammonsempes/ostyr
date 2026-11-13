use crate::cardinality::{admit_series, CardinalityState};
use crate::model::{Bucket, DropReason, Limits, MetricKind, Outcome, Refusal, SampleRow};
use crate::scan::scan_request;
use crate::types::{LabelMap, Labels, ResourceLabels};
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value::Value as AnyKind, KeyValue};
use opentelemetry_proto::tonic::metrics::v1::{metric::Data, number_data_point::Value as NumberKind, HistogramDataPoint, Metric, NumberDataPoint};
use prost::Message;
use std::collections::BTreeMap;
use std::iter::once;
use std::mem::size_of;
use unicode_general_category::{get_general_category, GeneralCategory};


pub const MIN_ALLOCATION_BYTES: usize = 32;


pub const ALLOCATION_ALIGN_BYTES: usize = 16;


pub const ALLOCATION_HEADER_BYTES: usize = 8;


pub const ROWS_CAPACITY_FACTOR: usize = 3;


pub struct Series<'a> {
    pub name: &'a str,
    pub unit: &'a str,
    pub kind: MetricKind,
    pub monotonic: bool,
    pub resource: &'a ResourceLabels,
}


pub struct Point<'a> {
    pub attributes: &'a [KeyValue],
    pub timestamp_nanos: u64,
    pub value: f64,
    pub buckets: Vec<Bucket>,
}


pub fn to_count(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}


pub fn count_drop(outcome: &mut Outcome, reason: DropReason, amount: usize) {
    let total = outcome.dropped.entry(reason).or_insert(0);
    *total = total.saturating_add(to_count(amount));
}


/// Decodes one OTLP export request for `tenant`; the payload never chooses the tenant.
pub fn decode_request(bytes: &[u8], tenant: &str, limits: &Limits, state: &mut CardinalityState) -> Outcome {
    let mut outcome = Outcome {
        tenant: tenant.to_string(),
        rows: Vec::new(),
        dropped: BTreeMap::new(),
        refusal: None,
        row_bytes: 0,
    };
    match parse_request(bytes, limits) {
        Ok(request) => collect(&request, limits, state, &mut outcome),
        Err(refusal) => outcome.refusal = Some(refusal),
    }
    outcome
}


pub fn parse_request(bytes: &[u8], limits: &Limits) -> Result<ExportMetricsServiceRequest, Refusal> {
    check_size(bytes.len(), limits)?;
    scan_request(bytes, limits)?;
    ExportMetricsServiceRequest::decode(bytes).map_err(Refusal::Malformed)
}


pub fn check_size(bytes: usize, limits: &Limits) -> Result<(), Refusal> {
    if bytes > limits.max_request_bytes {
        Err(Refusal::TooLarge { bytes })
    } else {
        Ok(())
    }
}


pub fn points_in(metric: &Metric) -> usize {
    match &metric.data {
        Some(Data::Gauge(gauge)) => gauge.data_points.len(),
        Some(Data::Sum(sum)) => sum.data_points.len(),
        Some(Data::Histogram(histogram)) => histogram.data_points.len(),
        Some(Data::ExponentialHistogram(histogram)) => histogram.data_points.len(),
        Some(Data::Summary(summary)) => summary.data_points.len(),
        None => 1,
    }
}


pub fn collect(request: &ExportMetricsServiceRequest, limits: &Limits, state: &mut CardinalityState, outcome: &mut Outcome) {
    request.resource_metrics.iter().for_each(|resource| {
        let attributes = resource.resource.as_ref().map_or(&[][..], |described| described.attributes.as_slice());
        let labels = resource_labels(attributes, limits);
        resource.scope_metrics.iter().flat_map(|scope| scope.metrics.iter()).for_each(|metric| {
            handle_metric(&labels, metric, limits, state, outcome);
        });
    });
}


/// Unicode control, format, line and paragraph separator characters, plus the bidirectional marks, Hangul fillers, the combining grapheme joiner and invisible characters listed below.
pub fn is_forbidden(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::Control | GeneralCategory::Format | GeneralCategory::LineSeparator | GeneralCategory::ParagraphSeparator
    ) || matches!(
        character,
        '\u{034f}' | '\u{061c}' | '\u{115f}' | '\u{1160}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}' | '\u{2066}'..='\u{2069}' | '\u{3164}' | '\u{feff}' | '\u{ffa0}'
    )
}


pub fn text_problem(text: &str, max_bytes: usize) -> Option<DropReason> {
    if text.len() > max_bytes {
        Some(DropReason::TextTooLong)
    } else if text.chars().any(is_forbidden) {
        Some(DropReason::ControlCharacter)
    } else {
        None
    }
}


pub fn header_problem(metric: &Metric, limits: &Limits) -> Option<DropReason> {
    if metric.name.is_empty() {
        Some(DropReason::EmptyName)
    } else {
        text_problem(&metric.name, limits.max_name_bytes).or_else(|| text_problem(&metric.unit, limits.max_name_bytes))
    }
}


pub fn handle_metric(resource: &ResourceLabels, metric: &Metric, limits: &Limits, state: &mut CardinalityState, outcome: &mut Outcome) {
    let series = |kind: MetricKind, monotonic: bool| Series {
        name: &metric.name,
        unit: &metric.unit,
        kind,
        monotonic,
        resource,
    };
    match (header_problem(metric, limits), &metric.data) {
        (Some(reason), _) => count_drop(outcome, reason, points_in(metric)),
        (None, Some(Data::Gauge(gauge))) => gauge.data_points.iter().for_each(|point| {
            number_point(&series(MetricKind::Gauge, false), point, limits, state, outcome);
        }),
        (None, Some(Data::Sum(sum))) => sum.data_points.iter().for_each(|point| {
            number_point(&series(MetricKind::Counter, sum.is_monotonic), point, limits, state, outcome);
        }),
        (None, Some(Data::Histogram(histogram))) => histogram.data_points.iter().for_each(|point| {
            histogram_point(&series(MetricKind::Histogram, false), point, limits, state, outcome);
        }),
        (None, Some(Data::ExponentialHistogram(histogram))) => {
            count_drop(outcome, DropReason::UnsupportedExponentialHistogram, histogram.data_points.len());
        }
        (None, Some(Data::Summary(summary))) => count_drop(outcome, DropReason::UnsupportedSummary, summary.data_points.len()),
        (None, None) => count_drop(outcome, DropReason::MissingData, 1),
    }
}


pub fn number_point(series: &Series, point: &NumberDataPoint, limits: &Limits, state: &mut CardinalityState, outcome: &mut Outcome) {
    let value = match point.value {
        Some(NumberKind::AsDouble(number)) => Some(number),
        Some(NumberKind::AsInt(number)) => Some(number as f64),
        None => None,
    };
    match value {
        Some(number) => {
            let built = Point {
                attributes: &point.attributes,
                timestamp_nanos: point.time_unix_nano,
                value: number,
                buckets: Vec::new(),
            };
            admit_point(series, built, limits, state, outcome);
        }
        None => count_drop(outcome, DropReason::MissingValue, 1),
    }
}


pub fn histogram_buckets(point: &HistogramDataPoint, limits: &Limits) -> Result<Vec<Bucket>, DropReason> {
    let counts = &point.bucket_counts;
    if counts.len() > limits.max_buckets {
        Err(DropReason::TooManyBuckets)
    } else if !counts.is_empty() && point.explicit_bounds.len() + 1 != counts.len() {
        Err(DropReason::MalformedHistogram)
    } else {
        Ok(point
            .explicit_bounds
            .iter()
            .copied()
            .chain(once(f64::INFINITY))
            .zip(counts.iter().copied())
            .map(|(upper_bound, count)| Bucket { upper_bound, count })
            .collect())
    }
}


pub fn histogram_point(series: &Series, point: &HistogramDataPoint, limits: &Limits, state: &mut CardinalityState, outcome: &mut Outcome) {
    let built = histogram_buckets(point, limits).and_then(|buckets| {
        point.sum.ok_or(DropReason::MissingValue).map(|value| Point {
            attributes: &point.attributes,
            timestamp_nanos: point.time_unix_nano,
            value,
            buckets,
        })
    });
    match built {
        Ok(ready) => admit_point(series, ready, limits, state, outcome),
        Err(reason) => count_drop(outcome, reason, 1),
    }
}


/// Validates the attributes of one resource once; more raw attributes than `max_labels` is refused before any work.
pub fn resource_labels(resource: &[KeyValue], limits: &Limits) -> ResourceLabels {
    if resource.len() > limits.max_labels {
        Err(DropReason::TooManyLabels)
    } else {
        resource.iter().map(|pair| label_pair(pair, limits)).collect::<Result<LabelMap, _>>()
    }
}


/// Resource labels first, then point attributes: on a shared key the point value wins.
pub fn point_labels(resource: &ResourceLabels, point: &[KeyValue], limits: &Limits) -> Result<Labels, DropReason> {
    let base = resource.as_ref().map_err(|reason| *reason)?;
    if point.len() > limits.max_labels {
        Err(DropReason::TooManyLabels)
    } else {
        let pairs = point.iter().map(|pair| label_pair(pair, limits)).collect::<Result<Vec<_>, _>>()?;
        let mut merged = base.clone();
        merged.extend(pairs);
        if merged.len() > limits.max_labels {
            Err(DropReason::TooManyLabels)
        } else {
            Ok(merged.into_iter().collect())
        }
    }
}


pub fn label_pair(pair: &KeyValue, limits: &Limits) -> Result<(String, String), DropReason> {
    let value = pair
        .value
        .as_ref()
        .and_then(|any| any.value.as_ref())
        .and_then(scalar_text)
        .ok_or(DropReason::UnsupportedLabelValue)?;
    if pair.key.is_empty() {
        Err(DropReason::EmptyName)
    } else {
        match text_problem(&pair.key, limits.max_label_key_bytes).or_else(|| text_problem(&value, limits.max_label_value_bytes)) {
            Some(reason) => Err(reason),
            None => Ok((pair.key.clone(), value)),
        }
    }
}


pub fn scalar_text(value: &AnyKind) -> Option<String> {
    match value {
        AnyKind::StringValue(text) => Some(text.clone()),
        AnyKind::BoolValue(flag) => Some(flag.to_string()),
        AnyKind::IntValue(number) => Some(number.to_string()),
        AnyKind::DoubleValue(number) => Some(number.to_string()),
        _ => None,
    }
}


/// Bytes the allocator hands out for `length` bytes: 0 when empty, else `length` plus an 8-byte header rounded up to 16, at least 32 (glibc minimum chunk).
pub fn allocation_bytes(length: usize) -> usize {
    if length == 0 {
        0
    } else {
        length
            .saturating_add(ALLOCATION_HEADER_BYTES)
            .div_ceil(ALLOCATION_ALIGN_BYTES)
            .saturating_mul(ALLOCATION_ALIGN_BYTES)
            .max(MIN_ALLOCATION_BYTES)
    }
}


/// Bytes one row will own: `SampleRow` three times (the `rows` vector reallocates: old and new block live together), plus every heap block at its allocated capacity.
pub fn row_bytes(tenant: &str, series: &Series, labels: &Labels, buckets: &[Bucket]) -> usize {
    let strings = [tenant.len(), series.name.len(), series.unit.len()]
        .iter()
        .fold(ROWS_CAPACITY_FACTOR * size_of::<SampleRow>(), |total, length| {
            total.saturating_add(allocation_bytes(*length))
        });
    let label_bytes = labels.iter().fold(
        allocation_bytes(labels.len().saturating_mul(size_of::<(String, String)>())),
        |total, (key, value)| {
            total
                .saturating_add(allocation_bytes(key.capacity()))
                .saturating_add(allocation_bytes(value.capacity()))
        },
    );
    strings
        .saturating_add(label_bytes)
        .saturating_add(allocation_bytes(buckets.len().saturating_mul(size_of::<Bucket>())))
}


pub fn admit_point(series: &Series, point: Point, limits: &Limits, state: &mut CardinalityState, outcome: &mut Outcome) {
    if outcome.refusal.is_none() {
        admit_new_point(series, point, limits, state, outcome);
    }
}


pub fn admit_new_point(series: &Series, point: Point, limits: &Limits, state: &mut CardinalityState, outcome: &mut Outcome) {
    let built =
        point_labels(series.resource, point.attributes, limits).map(|labels| (row_bytes(&outcome.tenant, series, &labels, &point.buckets), labels));
    match built {
        Ok((cost, labels)) => {
            let total = outcome.row_bytes.saturating_add(cost);
            if total > limits.max_row_bytes_total {
                outcome.rows = Vec::new();
                outcome.refusal = Some(Refusal::TooManyRowBytes { bytes: total });
            } else {
                match admit_series(state, &outcome.tenant, series.name, &labels, limits) {
                    Ok(()) => push_row(series, point, labels, total, outcome),
                    Err(reason) => count_drop(outcome, reason, 1),
                }
            }
        }
        Err(reason) => count_drop(outcome, reason, 1),
    }
}


pub fn push_row(series: &Series, point: Point, labels: Labels, total: usize, outcome: &mut Outcome) {
    outcome.row_bytes = total;
    outcome.rows.push(SampleRow {
        tenant: outcome.tenant.clone(),
        name: series.name.to_string(),
        unit: series.unit.to_string(),
        kind: series.kind,
        monotonic: series.monotonic,
        labels,
        timestamp_nanos: point.timestamp_nanos,
        value: point.value,
        buckets: point.buckets,
    });
}
