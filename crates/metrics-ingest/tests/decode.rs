mod common;


use common::types::TestResult;
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::decode::{allocation_bytes, decode_request, to_count};
use metrics_ingest::model::{DropReason, Limits, MetricKind, Outcome, Refusal};
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value::Value as AnyKind, AnyValue, ArrayValue, KeyValue};
use opentelemetry_proto::tonic::metrics::v1::{
    metric::Data, number_data_point::Value as NumberKind, ExponentialHistogram, Gauge, Histogram, HistogramDataPoint, Metric, NumberDataPoint,
    ResourceMetrics, ScopeMetrics, Sum, Summary, SummaryDataPoint,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;


const TENANT_A: &str = "tenant-a";


const TENANT_B: &str = "tenant-b";


const STAMP: u64 = 1_700_000_000_000_000_000;


const SMALL: usize = 2;


const BUDGET: usize = 400;


const LONG_VALUE: usize = 200;


const THREE: usize = 3;


const FIVE: usize = 5;


const COUNT_TWO: u64 = 2;


const SIX: usize = 6;


const EIGHT: usize = 8;


const COUNT_THREE: u64 = 3;


const COUNT_FIFTY_FOUR: u64 = 54;


const CUMULATIVE: i32 = 2;


const RATE_VALUE: f64 = 2.5;


const SUM_VALUE: f64 = 7.5;


const HALF: f64 = 0.5;


const ONE_F: f64 = 1.0;


const TWO_F: f64 = 2.0;


const CODE: i64 = 7;


const BAD_BYTE: u8 = 0xff;


fn pair(key: &str, value: AnyKind) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue { value: Some(value) }),
        ..Default::default()
    }
}


fn text(key: &str, value: &str) -> KeyValue {
    pair(key, AnyKind::StringValue(value.to_string()))
}


fn number(attributes: Vec<KeyValue>, value: Option<NumberKind>) -> NumberDataPoint {
    NumberDataPoint {
        attributes,
        time_unix_nano: STAMP,
        value,
        ..Default::default()
    }
}


fn metric(name: &str, data: Option<Data>) -> Metric {
    Metric {
        name: name.to_string(),
        unit: "ms".to_string(),
        data,
        ..Default::default()
    }
}


fn gauge(name: &str, points: Vec<NumberDataPoint>) -> Metric {
    metric(name, Some(Data::Gauge(Gauge { data_points: points })))
}


fn one_gauge(name: &str, attributes: Vec<KeyValue>) -> Metric {
    gauge(name, vec![number(attributes, Some(NumberKind::AsInt(1)))])
}


fn histogram(counts: Vec<u64>, bounds: Vec<f64>, sum: Option<f64>) -> Metric {
    let point = HistogramDataPoint {
        time_unix_nano: STAMP,
        bucket_counts: counts,
        explicit_bounds: bounds,
        sum,
        ..Default::default()
    };
    metric(
        "latency",
        Some(Data::Histogram(Histogram {
            data_points: vec![point],
            aggregation_temporality: 0,
        })),
    )
}


fn encode(resource_attributes: Vec<KeyValue>, metrics: Vec<Metric>) -> Vec<u8> {
    let resource = ResourceMetrics {
        resource: Some(Resource {
            attributes: resource_attributes,
            ..Default::default()
        }),
        scope_metrics: vec![ScopeMetrics {
            metrics,
            ..Default::default()
        }],
        ..Default::default()
    };
    ExportMetricsServiceRequest {
        resource_metrics: vec![resource],
    }
    .encode_to_vec()
}


fn run(bytes: &[u8], limits: &Limits) -> Outcome {
    decode_request(bytes, TENANT_A, limits, &mut CardinalityState::default())
}


fn dropped(outcome: &Outcome, reason: DropReason) -> Option<u64> {
    outcome.dropped.get(&reason).copied()
}


#[test]
fn oversized_request_is_refused_before_decoding() -> TestResult {
    let limits = Limits {
        max_request_bytes: SMALL,
        ..Limits::default()
    };
    let mut state = CardinalityState::default();
    let outcome = decode_request(&[BAD_BYTE; THREE], TENANT_A, &limits, &mut state);
    assert_eq!(outcome.refusal, Some(Refusal::TooLarge { bytes: THREE }));
    assert!(outcome.rows.is_empty());
    assert!(state.tenants.is_empty());
    Ok(())
}


#[test]
fn request_at_the_size_limit_is_decoded() -> TestResult {
    let bytes = encode(Vec::new(), vec![one_gauge("cpu", Vec::new())]);
    let limits = Limits {
        max_request_bytes: bytes.len(),
        ..Limits::default()
    };
    assert_eq!(run(&bytes, &limits).rows.len(), 1);
    Ok(())
}


#[test]
fn malformed_bytes_are_refused() -> TestResult {
    let outcome = run(&[BAD_BYTE; THREE], &Limits::default());
    assert!(matches!(outcome.refusal, Some(Refusal::Malformed(_))));
    Ok(())
}


#[test]
fn too_many_resources_are_refused() -> TestResult {
    let resource = ResourceMetrics::default();
    let bytes = ExportMetricsServiceRequest {
        resource_metrics: vec![resource.clone(), resource],
    }
    .encode_to_vec();
    let limits = Limits {
        max_resources: 1,
        ..Limits::default()
    };
    assert_eq!(run(&bytes, &limits).refusal, Some(Refusal::TooManyResources { count: SMALL }));
    Ok(())
}


#[test]
fn resource_without_description_is_decoded() -> TestResult {
    let resource = ResourceMetrics {
        scope_metrics: vec![ScopeMetrics {
            metrics: vec![one_gauge("cpu", Vec::new())],
            ..Default::default()
        }],
        ..Default::default()
    };
    let bytes = ExportMetricsServiceRequest {
        resource_metrics: vec![resource],
    }
    .encode_to_vec();
    let outcome = run(&bytes, &Limits::default());
    assert_eq!(outcome.rows.len(), 1);
    assert!(outcome.rows.iter().all(|row| row.labels.is_empty()));
    Ok(())
}


#[test]
fn data_point_count_is_bounded_over_every_type() -> TestResult {
    let limits = Limits {
        max_data_points: 1,
        ..Limits::default()
    };
    let two = vec![number(Vec::new(), None), number(Vec::new(), None)];
    let exponential = metric(
        "e",
        Some(Data::ExponentialHistogram(ExponentialHistogram {
            data_points: Vec::new(),
            aggregation_temporality: 0,
        })),
    );
    let summary = metric(
        "s",
        Some(Data::Summary(Summary {
            data_points: vec![SummaryDataPoint::default()],
        })),
    );
    let sum = metric(
        "c",
        Some(Data::Sum(Sum {
            data_points: Vec::new(),
            aggregation_temporality: 0,
            is_monotonic: true,
        })),
    );
    let bytes = encode(
        Vec::new(),
        vec![
            gauge("g", two),
            exponential,
            summary,
            sum,
            histogram(Vec::new(), Vec::new(), None),
            metric("x", None),
        ],
    );
    assert_eq!(run(&bytes, &limits).refusal, Some(Refusal::TooManyDataPoints { count: EIGHT }));
    let exact = Limits {
        max_data_points: EIGHT,
        ..Limits::default()
    };
    assert_eq!(run(&bytes, &exact).refusal, None);
    Ok(())
}


#[test]
fn gauges_sums_and_histograms_become_rows() -> TestResult {
    let sum = metric(
        "requests",
        Some(Data::Sum(Sum {
            data_points: vec![number(Vec::new(), Some(NumberKind::AsDouble(RATE_VALUE)))],
            aggregation_temporality: CUMULATIVE,
            is_monotonic: true,
        })),
    );
    let latency = histogram(vec![1, COUNT_TWO, COUNT_THREE], vec![HALF, ONE_F], Some(SUM_VALUE));
    let bytes = encode(Vec::new(), vec![one_gauge("cpu", Vec::new()), sum, latency]);
    let outcome = run(&bytes, &Limits::default());
    let kinds: Vec<(MetricKind, bool, f64)> = outcome.rows.iter().map(|row| (row.kind, row.monotonic, row.value)).collect();
    assert_eq!(
        kinds,
        vec![
            (MetricKind::Gauge, false, ONE_F),
            (MetricKind::Counter, true, RATE_VALUE),
            (MetricKind::Histogram, false, SUM_VALUE)
        ]
    );
    let row = outcome.rows.last().ok_or("no row")?;
    let bounds: Vec<(f64, u64)> = row.buckets.iter().map(|bucket| (bucket.upper_bound, bucket.count)).collect();
    assert_eq!(bounds, vec![(HALF, 1), (ONE_F, COUNT_TWO), (f64::INFINITY, COUNT_THREE)]);
    assert_eq!((row.unit.as_str(), row.timestamp_nanos, row.name.as_str()), ("ms", STAMP, "latency"));
    assert!(outcome.dropped.is_empty());
    Ok(())
}


#[test]
fn histogram_without_buckets_is_kept_and_bad_ones_counted() -> TestResult {
    let bare = run(
        &encode(Vec::new(), vec![histogram(Vec::new(), Vec::new(), Some(ONE_F))]),
        &Limits::default(),
    );
    assert_eq!(bare.rows.len(), 1);
    let limits = Limits {
        max_buckets: SMALL,
        ..Limits::default()
    };
    let many = run(
        &encode(
            Vec::new(),
            vec![histogram(vec![1, COUNT_TWO, COUNT_THREE], vec![ONE_F, TWO_F], Some(ONE_F))],
        ),
        &limits,
    );
    assert_eq!(dropped(&many, DropReason::TooManyBuckets), Some(1));
    let exact = run(
        &encode(Vec::new(), vec![histogram(vec![1, COUNT_TWO], vec![ONE_F], Some(ONE_F))]),
        &limits,
    );
    assert_eq!(exact.rows.len(), 1);
    let skewed = run(
        &encode(Vec::new(), vec![histogram(vec![1, COUNT_TWO], vec![ONE_F, TWO_F], Some(ONE_F))]),
        &Limits::default(),
    );
    assert_eq!(dropped(&skewed, DropReason::MalformedHistogram), Some(1));
    let no_sum = run(&encode(Vec::new(), vec![histogram(vec![1], Vec::new(), None)]), &Limits::default());
    assert_eq!(dropped(&no_sum, DropReason::MissingValue), Some(1));
    Ok(())
}


#[test]
fn unsupported_and_empty_metrics_are_counted() -> TestResult {
    let exponential = metric(
        "e",
        Some(Data::ExponentialHistogram(ExponentialHistogram {
            data_points: vec![Default::default(), Default::default()],
            aggregation_temporality: 0,
        })),
    );
    let summary = metric(
        "s",
        Some(Data::Summary(Summary {
            data_points: vec![SummaryDataPoint::default()],
        })),
    );
    let outcome = run(
        &encode(
            Vec::new(),
            vec![exponential, summary, metric("none", None), gauge("g", vec![number(Vec::new(), None)])],
        ),
        &Limits::default(),
    );
    assert!(outcome.rows.is_empty());
    assert_eq!(dropped(&outcome, DropReason::UnsupportedExponentialHistogram), Some(COUNT_TWO));
    assert_eq!(dropped(&outcome, DropReason::UnsupportedSummary), Some(1));
    assert_eq!(dropped(&outcome, DropReason::MissingData), Some(1));
    assert_eq!(dropped(&outcome, DropReason::MissingValue), Some(1));
    Ok(())
}


#[test]
fn names_and_units_are_checked() -> TestResult {
    let long = "n".repeat(Limits::default().max_name_bytes + 1);
    let mut bad_unit = one_gauge("unit", Vec::new());
    bad_unit.unit = "m\u{7}s".to_string();
    let metrics = vec![
        one_gauge("", Vec::new()),
        one_gauge(&long, Vec::new()),
        one_gauge("bad\nname", Vec::new()),
        bad_unit,
    ];
    let outcome = run(&encode(Vec::new(), metrics), &Limits::default());
    assert!(outcome.rows.is_empty());
    assert_eq!(dropped(&outcome, DropReason::EmptyName), Some(1));
    assert_eq!(dropped(&outcome, DropReason::TextTooLong), Some(1));
    assert_eq!(dropped(&outcome, DropReason::ControlCharacter), Some(COUNT_TWO));
    Ok(())
}


#[test]
fn labels_are_checked() -> TestResult {
    let limits = Limits {
        max_label_key_bytes: SMALL,
        max_label_value_bytes: SMALL,
        max_labels: SMALL,
        ..Limits::default()
    };
    let points = vec![
        number(vec![text("ab", "abc")], Some(NumberKind::AsInt(1))),
        number(vec![text("abc", "a")], Some(NumberKind::AsInt(1))),
        number(vec![text("a\u{1b}", "a")], Some(NumberKind::AsInt(1))),
        number(vec![text("a", "\r")], Some(NumberKind::AsInt(1))),
        number(vec![text("", "a")], Some(NumberKind::AsInt(1))),
        number(vec![text("a", "1"), text("b", "1"), text("c", "1")], Some(NumberKind::AsInt(1))),
        number(vec![pair("a", AnyKind::ArrayValue(ArrayValue::default()))], Some(NumberKind::AsInt(1))),
        number(
            vec![KeyValue {
                key: "a".to_string(),
                value: None,
                ..Default::default()
            }],
            Some(NumberKind::AsInt(1)),
        ),
        number(
            vec![KeyValue {
                key: "a".to_string(),
                value: Some(AnyValue { value: None }),
                ..Default::default()
            }],
            Some(NumberKind::AsInt(1)),
        ),
    ];
    let outcome = run(&encode(Vec::new(), vec![gauge("g", points)]), &limits);
    assert!(outcome.rows.is_empty());
    assert_eq!(dropped(&outcome, DropReason::TextTooLong), Some(COUNT_TWO));
    assert_eq!(dropped(&outcome, DropReason::ControlCharacter), Some(COUNT_TWO));
    assert_eq!(dropped(&outcome, DropReason::EmptyName), Some(1));
    assert_eq!(dropped(&outcome, DropReason::TooManyLabels), Some(1));
    assert_eq!(dropped(&outcome, DropReason::UnsupportedLabelValue), Some(COUNT_THREE));
    Ok(())
}


#[test]
fn labels_merge_with_point_precedence_and_sorted() -> TestResult {
    let resource = vec![text("zone", "res"), text("host", "h1")];
    let attributes = vec![
        text("zone", "point"),
        pair("on", AnyKind::BoolValue(true)),
        pair("code", AnyKind::IntValue(CODE)),
        pair("ratio", AnyKind::DoubleValue(HALF)),
    ];
    let outcome = run(&encode(resource, vec![one_gauge("cpu", attributes)]), &Limits::default());
    let row = outcome.rows.first().ok_or("no row")?;
    let labels: Vec<(&str, &str)> = row.labels.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
    assert_eq!(
        labels,
        vec![("code", "7"), ("host", "h1"), ("on", "true"), ("ratio", "0.5"), ("zone", "point")]
    );
    Ok(())
}


#[test]
fn tenant_attribute_in_the_payload_is_ignored() -> TestResult {
    let resource = vec![text("tenant", TENANT_B), text("tenant_id", TENANT_B)];
    let outcome = run(&encode(resource, vec![one_gauge("cpu", Vec::new())]), &Limits::default());
    assert_eq!(outcome.tenant, TENANT_A);
    assert!(outcome.rows.iter().all(|row| row.tenant == TENANT_A));
    let row = outcome.rows.first().ok_or("no row")?;
    assert!(row.labels.contains(&("tenant".to_string(), TENANT_B.to_string())));
    Ok(())
}


#[test]
fn series_cap_is_per_tenant() -> TestResult {
    let limits = Limits {
        max_series_per_tenant: 1,
        ..Limits::default()
    };
    let mut state = CardinalityState::default();
    let first = encode(Vec::new(), vec![one_gauge("one", Vec::new()), one_gauge("two", Vec::new())]);
    let outcome_a = decode_request(&first, TENANT_A, &limits, &mut state);
    assert_eq!(outcome_a.rows.len(), 1);
    assert_eq!(dropped(&outcome_a, DropReason::SeriesCap), Some(1));
    let outcome_b = decode_request(&first, TENANT_B, &limits, &mut state);
    assert_eq!((outcome_b.rows.len(), outcome_b.tenant.as_str()), (1, TENANT_B));
    let again = decode_request(&encode(Vec::new(), vec![one_gauge("one", Vec::new())]), TENANT_A, &limits, &mut state);
    assert_eq!(again.rows.len(), 1);
    assert!(again.dropped.is_empty());
    Ok(())
}


#[test]
fn label_value_cap_is_per_tenant_and_commits_nothing_on_refusal() -> TestResult {
    let limits = Limits {
        max_values_per_label: 1,
        ..Limits::default()
    };
    let mut state = CardinalityState::default();
    let metrics = vec![
        one_gauge("cpu", vec![text("host", "h1")]),
        one_gauge("cpu", vec![text("host", "h2")]),
        one_gauge("cpu", vec![text("host", "h1")]),
        one_gauge("mem", vec![text("host", "h1")]),
    ];
    let outcome_a = decode_request(&encode(Vec::new(), metrics), TENANT_A, &limits, &mut state);
    assert_eq!(outcome_a.rows.len(), THREE);
    assert_eq!(dropped(&outcome_a, DropReason::LabelValueCap), Some(1));
    let other = encode(Vec::new(), vec![one_gauge("cpu", vec![text("host", "h2")])]);
    assert_eq!(decode_request(&other, TENANT_B, &limits, &mut state).rows.len(), 1);
    let tenant_a = state.tenants.get(TENANT_A).ok_or("no state")?;
    assert_eq!(tenant_a.values.get("host").map(|values| values.len()), Some(1));
    assert_eq!(tenant_a.series.len(), SMALL);
    Ok(())
}


#[test]
fn zero_value_cap_admits_no_labelled_series() -> TestResult {
    let limits = Limits {
        max_values_per_label: 0,
        ..Limits::default()
    };
    let outcome = run(
        &encode(
            Vec::new(),
            vec![one_gauge("cpu", vec![text("host", "h1")]), one_gauge("bare", Vec::new())],
        ),
        &limits,
    );
    assert_eq!(outcome.rows.len(), 1);
    assert_eq!(dropped(&outcome, DropReason::LabelValueCap), Some(1));
    Ok(())
}


#[test]
fn reasons_have_stable_names() -> TestResult {
    let reasons = [
        DropReason::EmptyName,
        DropReason::TextTooLong,
        DropReason::ControlCharacter,
        DropReason::TooManyLabels,
        DropReason::UnsupportedLabelValue,
        DropReason::MissingValue,
        DropReason::MissingData,
        DropReason::TooManyBuckets,
        DropReason::MalformedHistogram,
        DropReason::UnsupportedExponentialHistogram,
        DropReason::UnsupportedSummary,
        DropReason::SeriesCap,
        DropReason::LabelValueCap,
        DropReason::LabelKeyCap,
        DropReason::StateBytesCap,
    ];
    let names: Vec<String> = reasons.iter().map(ToString::to_string).collect();
    assert_eq!(names.iter().collect::<std::collections::BTreeSet<_>>().len(), reasons.len());
    assert_eq!(names.first().map(String::as_str), Some("empty_name"));
    Ok(())
}


#[test]
fn defaults_and_counts() -> TestResult {
    let limits = Limits::default();
    assert!(limits.max_series_per_tenant > 0 && limits.max_request_bytes > 0);
    assert_eq!(to_count(THREE), COUNT_THREE);
    Ok(())
}


fn typed_metrics(attributes: &[KeyValue]) -> Vec<Metric> {
    let numbers = vec![number(attributes.to_vec(), Some(NumberKind::AsInt(1)))];
    let histogram_point = HistogramDataPoint {
        attributes: attributes.to_vec(),
        ..Default::default()
    };
    vec![
        metric(
            "g",
            Some(Data::Gauge(Gauge {
                data_points: numbers.clone(),
            })),
        ),
        metric(
            "c",
            Some(Data::Sum(Sum {
                data_points: numbers,
                aggregation_temporality: 0,
                is_monotonic: false,
            })),
        ),
        metric(
            "h",
            Some(Data::Histogram(Histogram {
                data_points: vec![histogram_point],
                aggregation_temporality: 0,
            })),
        ),
        metric(
            "e",
            Some(Data::ExponentialHistogram(ExponentialHistogram {
                data_points: vec![opentelemetry_proto::tonic::metrics::v1::ExponentialHistogramDataPoint {
                    attributes: attributes.to_vec(),
                    ..Default::default()
                }],
                aggregation_temporality: 0,
            })),
        ),
        metric(
            "s",
            Some(Data::Summary(Summary {
                data_points: vec![SummaryDataPoint {
                    attributes: attributes.to_vec(),
                    ..Default::default()
                }],
            })),
        ),
        metric("x", None),
    ]
}


#[test]
fn total_attribute_count_is_bounded_over_every_type() -> TestResult {
    let attributes = vec![text("a", "1")];
    let bytes = encode(vec![text("r", "1")], typed_metrics(&attributes));
    let limits = Limits {
        max_total_attributes: FIVE,
        ..Limits::default()
    };
    assert_eq!(run(&bytes, &limits).refusal, Some(Refusal::TooManyAttributes { count: SIX }));
    let exact = Limits {
        max_total_attributes: SIX,
        ..Limits::default()
    };
    assert_eq!(run(&bytes, &exact).refusal, None);
    Ok(())
}


#[test]
fn duplicate_raw_attributes_are_refused_before_merging() -> TestResult {
    let limits = Limits {
        max_labels: SMALL,
        ..Limits::default()
    };
    let duplicates = vec![text("a", "1"), text("a", "2"), text("a", "3")];
    let bytes = encode(
        duplicates.clone(),
        vec![one_gauge("on_resource", Vec::new()), one_gauge("on_point", duplicates)],
    );
    let outcome = run(&bytes, &limits);
    assert!(outcome.rows.is_empty());
    assert_eq!(dropped(&outcome, DropReason::TooManyLabels), Some(COUNT_TWO));
    Ok(())
}


#[test]
fn resource_labels_are_validated_once_and_merged_per_point() -> TestResult {
    let limits = Limits {
        max_labels: SMALL,
        ..Limits::default()
    };
    let bad_resource = encode(vec![text("a\n", "1")], vec![one_gauge("g", Vec::new())]);
    assert_eq!(dropped(&run(&bad_resource, &limits), DropReason::ControlCharacter), Some(1));
    let merged_over = encode(vec![text("a", "1"), text("b", "1")], vec![one_gauge("g", vec![text("c", "1")])]);
    let outcome = run(&merged_over, &limits);
    assert!(outcome.rows.is_empty());
    assert_eq!(dropped(&outcome, DropReason::TooManyLabels), Some(1));
    Ok(())
}


#[test]
fn bidirectional_and_separator_characters_are_refused() -> TestResult {
    let forbidden = [
        "\u{202e}", "\u{2028}", "\u{2029}", "\u{200f}", "\u{2066}", "\u{61c}", "\u{200b}", "\u{feff}", "\u{200c}", "\u{200d}", "\u{2060}",
        "\u{180e}", "\u{ad}", "\u{34f}", "\u{115f}", "\u{1160}", "\u{3164}", "\u{ffa0}",
    ];
    let metrics: Vec<Metric> = forbidden
        .iter()
        .map(|character| one_gauge(&format!("n{character}"), Vec::new()))
        .collect();
    let labelled = forbidden
        .iter()
        .map(|character| one_gauge("g", vec![text("k", &format!("v{character}"))]));
    let keyed = forbidden
        .iter()
        .map(|character| one_gauge("g", vec![text(&format!("k{character}"), "v")]));
    let outcome = run(
        &encode(Vec::new(), metrics.into_iter().chain(labelled).chain(keyed).collect()),
        &Limits::default(),
    );
    assert!(outcome.rows.is_empty());
    assert_eq!(dropped(&outcome, DropReason::ControlCharacter), Some(COUNT_FIFTY_FOUR));
    let fine = run(
        &encode(Vec::new(), vec![one_gauge("g", vec![text("k", "caf\u{e9} \u{2013} \u{4e2d}")])]),
        &Limits::default(),
    );
    assert_eq!(fine.rows.len(), 1);
    Ok(())
}


#[test]
fn a_refused_header_counts_every_point_of_every_type() -> TestResult {
    let metrics: Vec<Metric> = typed_metrics(&[])
        .into_iter()
        .map(|described| Metric {
            name: "n\u{202e}".to_string(),
            ..described
        })
        .collect();
    let outcome = run(&encode(Vec::new(), metrics), &Limits::default());
    assert_eq!(dropped(&outcome, DropReason::ControlCharacter), Some(to_count(SIX)));
    Ok(())
}


#[test]
fn label_key_cap_is_per_tenant() -> TestResult {
    let limits = Limits {
        max_label_keys_per_tenant: SMALL,
        ..Limits::default()
    };
    let mut state = CardinalityState::default();
    let metrics = vec![
        one_gauge("a", vec![text("k1", "v")]),
        one_gauge("b", vec![text("k2", "v")]),
        one_gauge("c", vec![text("k3", "v")]),
        one_gauge("d", vec![text("k1", "w"), text("k2", "w")]),
    ];
    let bytes = encode(Vec::new(), metrics);
    let outcome_a = decode_request(&bytes, TENANT_A, &limits, &mut state);
    assert_eq!(outcome_a.rows.len(), THREE);
    assert_eq!(dropped(&outcome_a, DropReason::LabelKeyCap), Some(1));
    let outcome_b = decode_request(&bytes, TENANT_B, &limits, &mut state);
    assert_eq!(outcome_b.rows.len(), THREE);
    Ok(())
}


#[test]
fn state_byte_budget_is_per_tenant_and_counts_new_text_only() -> TestResult {
    let limits = Limits {
        max_state_bytes_per_tenant: BUDGET,
        ..Limits::default()
    };
    let mut state = CardinalityState::default();
    let metrics = vec![
        one_gauge("m", vec![text("k", "v1")]),
        one_gauge("m", vec![text("k", "v1")]),
        one_gauge("m", vec![text("k", &"x".repeat(LONG_VALUE))]),
        one_gauge("n", Vec::new()),
    ];
    let bytes = encode(Vec::new(), metrics);
    let outcome_a = decode_request(&bytes, TENANT_A, &limits, &mut state);
    assert_eq!(outcome_a.rows.len(), THREE);
    assert_eq!(dropped(&outcome_a, DropReason::StateBytesCap), Some(1));
    let tenant_a = state.tenants.get(TENANT_A).ok_or("no state")?;
    assert!(tenant_a.bytes <= limits.max_state_bytes_per_tenant);
    let outcome_b = decode_request(&bytes, TENANT_B, &limits, &mut state);
    assert_eq!(dropped(&outcome_b, DropReason::StateBytesCap), Some(1));
    Ok(())
}


const ROW_BYTES_PLAIN: usize = 528;


const THREE_ROWS: usize = 3;


const STATE_BYTES_PLAIN: usize = 67;


const STATE_BYTES_HISTOGRAM: usize = 71;


const STATE_BYTES_WITH_LABEL: usize = 329;


const STATE_BYTES_SECOND_SERIES: usize = 264;


const ROW_BYTES_WITH_LABEL: usize = 656 + STATE_BYTES_WITH_LABEL;


const ROW_BYTES_HISTOGRAM: usize = 592 + STATE_BYTES_HISTOGRAM;


const POINTS_PAST_THE_ROW_BUDGET: usize = 4;


const THIRD_ROW_BYTES: usize = 3 * ROW_BYTES_PLAIN + STATE_BYTES_PLAIN;


fn row_limit(bytes: usize) -> Limits {
    Limits {
        max_row_bytes_total: bytes,
        ..Limits::default()
    }
}


fn gauge_of(points: usize, attributes: &[KeyValue]) -> Vec<u8> {
    let list = (0..points).map(|_| number(attributes.to_vec(), Some(NumberKind::AsInt(1)))).collect();
    encode(Vec::new(), vec![gauge("cpu", list)])
}


#[test]
fn rows_within_the_row_byte_budget_are_kept_and_counted() -> TestResult {
    let outcome = run(&gauge_of(SMALL, &[]), &row_limit(SMALL * ROW_BYTES_PLAIN + STATE_BYTES_PLAIN));
    assert!(outcome.refusal.is_none());
    assert_eq!(
        (outcome.rows.len(), outcome.row_bytes),
        (SMALL, SMALL * ROW_BYTES_PLAIN + STATE_BYTES_PLAIN)
    );
    Ok(())
}


#[test]
fn rows_past_the_row_byte_budget_refuse_the_whole_request() -> TestResult {
    let outcome = run(
        &gauge_of(POINTS_PAST_THE_ROW_BUDGET, &[]),
        &row_limit(SMALL * ROW_BYTES_PLAIN + STATE_BYTES_PLAIN),
    );
    assert_eq!(outcome.refusal, Some(Refusal::TooManyRowBytes { bytes: THIRD_ROW_BYTES }));
    assert!(outcome.rows.is_empty());
    Ok(())
}


#[test]
fn a_label_counts_its_bytes_and_its_fixed_size() -> TestResult {
    let labels = [text("k", "vv")];
    let kept = run(&gauge_of(1, &labels), &row_limit(ROW_BYTES_WITH_LABEL));
    assert_eq!((kept.rows.len(), kept.row_bytes), (1, ROW_BYTES_WITH_LABEL));
    let refused = run(&gauge_of(1, &labels), &row_limit(ROW_BYTES_WITH_LABEL - 1));
    assert_eq!(refused.refusal, Some(Refusal::TooManyRowBytes { bytes: ROW_BYTES_WITH_LABEL }));
    Ok(())
}


#[test]
fn a_new_series_counts_its_state_bytes_in_the_row_budget() -> TestResult {
    let list = vec![
        number(vec![text("k", "vv")], Some(NumberKind::AsInt(1))),
        number(vec![text("k", "ww")], Some(NumberKind::AsInt(1))),
        number(vec![text("k", "ww")], Some(NumberKind::AsInt(1))),
    ];
    let bytes = encode(Vec::new(), vec![gauge("cpu", list)]);
    let rows_bytes = THREE_ROWS * (ROW_BYTES_WITH_LABEL - STATE_BYTES_WITH_LABEL);
    let total = rows_bytes + STATE_BYTES_WITH_LABEL + STATE_BYTES_SECOND_SERIES;
    let kept = run(&bytes, &row_limit(total));
    assert_eq!((kept.rows.len(), kept.row_bytes), (THREE_ROWS, total));
    let refused = run(&bytes, &row_limit(total - 1));
    assert!(refused.refusal.is_some());
    Ok(())
}


#[test]
fn buckets_count_in_the_row_bytes() -> TestResult {
    let bytes = encode(
        Vec::new(),
        vec![histogram(vec![1, COUNT_TWO, COUNT_THREE], vec![HALF, ONE_F], Some(SUM_VALUE))],
    );
    let kept = run(&bytes, &row_limit(ROW_BYTES_HISTOGRAM));
    assert_eq!((kept.rows.len(), kept.row_bytes), (1, ROW_BYTES_HISTOGRAM));
    let refused = run(&bytes, &row_limit(ROW_BYTES_HISTOGRAM - 1));
    assert!(refused.refusal.is_some());
    Ok(())
}


const ALLOCATION_CASES: [(usize, usize); 7] = [(0, 0), (1, 32), (24, 32), (25, 48), (40, 48), (41, 64), (usize::MAX, usize::MAX)];


#[test]
fn allocations_round_to_the_allocator_chunk() -> TestResult {
    ALLOCATION_CASES
        .iter()
        .for_each(|(length, bytes)| assert_eq!(allocation_bytes(*length), *bytes));
    Ok(())
}
