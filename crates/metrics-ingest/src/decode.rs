use crate::cardinality::{admit_series, CardinalityState};
use crate::model::{Bucket, DropReason, Limits, MetricKind, Outcome, Refusal, SampleRow};
use crate::types::Labels;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value::Value as AnyKind, KeyValue};
use opentelemetry_proto::tonic::metrics::v1::{metric::Data, number_data_point::Value as NumberKind, HistogramDataPoint, Metric, NumberDataPoint};
use prost::Message;
use std::collections::BTreeMap;
use std::iter::once;


pub struct Series<'a> {
    pub name: &'a str,
    pub unit: &'a str,
    pub kind: MetricKind,
    pub monotonic: bool,
    pub resource: &'a [KeyValue],
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
    };
    match parse_request(bytes, limits) {
        Ok(request) => collect(&request, limits, state, &mut outcome),
        Err(refusal) => outcome.refusal = Some(refusal),
    }
    outcome
}


pub fn parse_request(bytes: &[u8], limits: &Limits) -> Result<ExportMetricsServiceRequest, Refusal> {
    check_size(bytes.len(), limits)?;
    let request = ExportMetricsServiceRequest::decode(bytes).map_err(Refusal::Malformed)?;
    check_counts(&request, limits)?;
    Ok(request)
}


pub fn check_size(bytes: usize, limits: &Limits) -> Result<(), Refusal> {
    if bytes > limits.max_request_bytes {
        Err(Refusal::TooLarge { bytes })
    } else {
        Ok(())
    }
}


pub fn check_counts(request: &ExportMetricsServiceRequest, limits: &Limits) -> Result<(), Refusal> {
    let resources = request.resource_metrics.len();
    let points: usize = request
        .resource_metrics
        .iter()
        .flat_map(|resource| resource.scope_metrics.iter())
        .flat_map(|scope| scope.metrics.iter())
        .map(points_in)
        .sum();
    if resources > limits.max_resources {
        Err(Refusal::TooManyResources { count: resources })
    } else if points > limits.max_data_points {
        Err(Refusal::TooManyDataPoints { count: points })
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
        resource.scope_metrics.iter().flat_map(|scope| scope.metrics.iter()).for_each(|metric| {
            handle_metric(attributes, metric, limits, state, outcome);
        });
    });
}


pub fn text_problem(text: &str, max_bytes: usize) -> Option<DropReason> {
    if text.len() > max_bytes {
        Some(DropReason::TextTooLong)
    } else if text.chars().any(char::is_control) {
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


pub fn handle_metric(resource: &[KeyValue], metric: &Metric, limits: &Limits, state: &mut CardinalityState, outcome: &mut Outcome) {
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


/// Resource attributes first, then point attributes: on a shared key the point value wins.
pub fn point_labels(resource: &[KeyValue], point: &[KeyValue], limits: &Limits) -> Result<Labels, DropReason> {
    let pairs = resource
        .iter()
        .chain(point.iter())
        .map(|pair| label_pair(pair, limits))
        .collect::<Result<Vec<_>, _>>()?;
    let merged: BTreeMap<String, String> = pairs.into_iter().collect();
    if merged.len() > limits.max_labels {
        Err(DropReason::TooManyLabels)
    } else {
        Ok(merged.into_iter().collect())
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


pub fn admit_point(series: &Series, point: Point, limits: &Limits, state: &mut CardinalityState, outcome: &mut Outcome) {
    let admitted = point_labels(series.resource, point.attributes, limits)
        .and_then(|labels| admit_series(state, &outcome.tenant, series.name, &labels, limits).map(|()| labels));
    match admitted {
        Ok(labels) => outcome.rows.push(SampleRow {
            tenant: outcome.tenant.clone(),
            name: series.name.to_string(),
            unit: series.unit.to_string(),
            kind: series.kind,
            monotonic: series.monotonic,
            labels,
            timestamp_nanos: point.timestamp_nanos,
            value: point.value,
            buckets: point.buckets,
        }),
        Err(reason) => count_drop(outcome, reason, 1),
    }
}
