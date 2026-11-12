mod common;


use common::types::TestResult;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value::Value as AnyKind, AnyValue, ArrayValue, KeyValue, KeyValueList};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{
    span::{Event, Link, SpanKind},
    status::StatusCode,
    ResourceSpans, ScopeSpans, Span, Status,
};
use prost::Message;
use traces_ingest::decode::{decode_traces, to_hex};
use traces_ingest::model::{DropReason, Limits, Outcome, Refusal};
use traces_ingest::sampling::{trace_hash, Sampling};


const TENANT: &str = "tenant-a";


const NOW: u64 = 1_700_000_000_000_000_000;


const SECOND: u64 = 1_000_000_000;


const SKEW: u64 = 300;


const GOLDEN: u128 = 0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C835;


const BAD_BYTE: u8 = 0xff;


const SMALL: usize = 2;


const THREE: usize = 3;


const FIVE: usize = 5;


const SIX: usize = 6;


const SEED_TWO: u8 = 2;


const SEED_THREE: u8 = 3;


const COUNT_TWO: u64 = 2;


const ID_LEN: usize = 16;


const SHORT_ID: usize = 15;


const SPAN_LEN: usize = 8;


const ZERO_F: f64 = 0.0;


const ONE_F: f64 = 1.0;


const TRACES: u8 = 64;


const MILLION: usize = 1_000_000;


const DEPTH: usize = 10_000;


const MEBIBYTE: usize = 1_048_576;


const BAD_ENUM: i32 = 99;


const CODE: i64 = 12_345;


const RATE: f64 = 2.5;


const HALF: f64 = 0.5;


const HALF_HASH: u64 = 1 << 63;


const LEFT_TO_RIGHT_MARK: &str = "a\u{200e}b";


const ZERO_WIDTH: &str = "a\u{200b}b";


const OVERRIDE: &str = "a\u{202e}b";


const LINE_BREAK: &str = "a\nb";


const ARRAY_TAG: u8 = 0x2a;


const KVLIST_TAG: u8 = 0x32;


const HUNDRED_THOUSAND: usize = 100_000;


const VALUES_TAG: u8 = 0x0a;


const VALUE_TAG: u8 = 0x12;


const SPAN_ATTRIBUTE_TAG: u8 = 0x4a;


const JSON_LIMIT: usize = 5;


const JSON_BIG: usize = 64;


const SPANS_TAG: u8 = 0x12;


const SCOPE_SPANS_TAG: u8 = 0x12;


const RESOURCE_SPANS_TAG: u8 = 0x0a;


fn trace_bytes(seed: u8) -> Vec<u8> {
    u128::from(seed).wrapping_mul(GOLDEN).to_be_bytes().to_vec()
}


fn span(trace: u8, id: u8) -> Span {
    Span {
        trace_id: trace_bytes(trace),
        span_id: vec![id; SPAN_LEN],
        name: "op".to_string(),
        kind: SpanKind::Server as i32,
        start_time_unix_nano: NOW - SECOND,
        end_time_unix_nano: NOW,
        ..Default::default()
    }
}


fn text(key: &str, value: &str) -> KeyValue {
    pair(key, AnyKind::StringValue(value.to_string()))
}


fn pair(key: &str, value: AnyKind) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue { value: Some(value) }),
        ..Default::default()
    }
}


fn texts(count: usize) -> Vec<KeyValue> {
    (0..count).map(|index| text(&format!("k{index}"), "v")).collect()
}


fn resource(attributes: Vec<KeyValue>, spans: Vec<Span>) -> ResourceSpans {
    ResourceSpans {
        resource: Some(Resource {
            attributes,
            ..Default::default()
        }),
        scope_spans: vec![ScopeSpans { spans, ..Default::default() }],
        ..Default::default()
    }
}


fn service(name: &str, spans: Vec<Span>) -> ResourceSpans {
    resource(vec![text("service.name", name)], spans)
}


fn encode(resources: Vec<ResourceSpans>) -> Vec<u8> {
    ExportTraceServiceRequest { resource_spans: resources }.encode_to_vec()
}


fn run_with(bytes: &[u8], limits: &Limits, sampling: &Sampling) -> Outcome {
    decode_traces(bytes, TENANT, limits, sampling, NOW)
}


fn run(bytes: &[u8], limits: &Limits) -> Outcome {
    run_with(bytes, limits, &Sampling::default())
}


fn one(candidate: Span) -> Outcome {
    run(&encode(vec![service("api", vec![candidate])]), &Limits::default())
}


fn dropped(outcome: &Outcome, reason: DropReason) -> Option<u64> {
    outcome.dropped.get(&reason).copied()
}


fn only_drop(outcome: &Outcome, reason: DropReason) {
    assert!(outcome.rows.is_empty());
    assert_eq!(dropped(outcome, reason), Some(1));
    assert_eq!(outcome.dropped.len(), 1);
    assert_eq!(outcome.sampled_out, 0);
    assert!(outcome.refusal.is_none());
}


fn with_attributes(attributes: Vec<KeyValue>) -> Span {
    Span { attributes, ..span(1, 1) }
}


fn limits_for(spans: usize) -> Limits {
    Limits {
        max_spans: spans,
        ..Limits::default()
    }
}


fn framed(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    prost::encoding::encode_varint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}


fn nested_request(wrap: fn(Vec<u8>) -> Vec<u8>, depth: usize) -> Vec<u8> {
    let deepest = (0..depth).fold(Vec::new(), |inner, _| wrap(inner));
    let attribute = framed(
        SPAN_ATTRIBUTE_TAG,
        &[text("k", "").encode_to_vec().as_slice(), &framed(VALUE_TAG, &deepest)].concat(),
    );
    let spans = framed(SPANS_TAG, &attribute);
    let scope = framed(SCOPE_SPANS_TAG, &spans);
    framed(RESOURCE_SPANS_TAG, &scope)
}


fn nested_array(inner: Vec<u8>) -> Vec<u8> {
    framed(ARRAY_TAG, &framed(VALUES_TAG, &inner))
}


fn nested_kvlist(inner: Vec<u8>) -> Vec<u8> {
    framed(KVLIST_TAG, &framed(VALUES_TAG, &framed(VALUE_TAG, &inner)))
}


#[test]
fn shallow_nesting_decodes_so_the_deep_refusals_come_from_the_depth() -> TestResult {
    [nested_array, nested_kvlist].iter().try_for_each(|wrap| -> TestResult {
        let outcome = run(&nested_request(*wrap, SMALL), &Limits::default());
        assert!(outcome.refusal.is_none());
        assert_eq!(dropped(&outcome, DropReason::BadId), Some(1));
        Ok(())
    })
}


#[test]
fn nested_kvlists_ten_thousand_deep_are_refused_by_the_decoder() -> TestResult {
    let outcome = run(&nested_request(nested_kvlist, DEPTH), &Limits::default());
    assert!(matches!(outcome.refusal, Some(Refusal::Malformed(_))));
    assert!(outcome.rows.is_empty());
    Ok(())
}


#[test]
fn a_hundred_thousand_attributes_on_one_span_drop_only_that_span() -> TestResult {
    let bytes = encode(vec![service(
        "api",
        vec![with_attributes(texts(HUNDRED_THOUSAND)), span(SEED_TWO, SEED_TWO)],
    )]);
    let outcome = run(&bytes, &Limits::default());
    assert_eq!(dropped(&outcome, DropReason::TooManyAttributes), Some(1));
    assert_eq!(outcome.rows.len(), 1);
    assert!(outcome.refusal.is_none());
    Ok(())
}


#[test]
fn oversized_request_is_refused_before_decoding() -> TestResult {
    let limits = Limits {
        max_request_bytes: SMALL,
        ..Limits::default()
    };
    let outcome = run(&[BAD_BYTE; THREE], &limits);
    assert!(matches!(outcome.refusal, Some(Refusal::TooLarge { bytes: THREE })));
    assert!(outcome.rows.is_empty());
    Ok(())
}


#[test]
fn request_at_the_size_limit_is_decoded() -> TestResult {
    let bytes = encode(vec![service("api", vec![span(1, 1)])]);
    let limits = Limits {
        max_request_bytes: bytes.len(),
        ..Limits::default()
    };
    assert_eq!(run(&bytes, &limits).rows.len(), 1);
    let smaller = Limits {
        max_request_bytes: bytes.len() - 1,
        ..Limits::default()
    };
    assert!(matches!(run(&bytes, &smaller).refusal, Some(Refusal::TooLarge { bytes: size }) if size == bytes.len()));
    Ok(())
}


#[test]
fn malformed_bytes_are_refused() -> TestResult {
    let outcome = run(&[BAD_BYTE; THREE], &Limits::default());
    assert!(matches!(outcome.refusal, Some(Refusal::Malformed(_))));
    Ok(())
}


#[test]
fn invalid_tenant_is_refused_before_anything_else() -> TestResult {
    let bytes = encode(vec![service("api", vec![span(1, 1)])]);
    let outcome = decode_traces(&bytes, "-x", &Limits::default(), &Sampling::default(), NOW);
    assert!(matches!(outcome.refusal, Some(Refusal::InvalidTenant(_))));
    assert!(outcome.tenant.is_empty());
    assert!(outcome.rows.is_empty());
    assert!(outcome.dropped.is_empty());
    Ok(())
}


#[test]
fn resource_span_count_is_capped_at_n_and_n_plus_one() -> TestResult {
    let limits = Limits {
        max_resource_spans: SMALL,
        ..Limits::default()
    };
    let two = encode(vec![service("a", Vec::new()), service("b", Vec::new())]);
    assert!(run(&two, &limits).refusal.is_none());
    let three = encode(vec![service("a", Vec::new()), service("b", Vec::new()), service("c", Vec::new())]);
    assert!(matches!(
        run(&three, &limits).refusal,
        Some(Refusal::TooManyResourceSpans { count: THREE })
    ));
    Ok(())
}


#[test]
fn span_count_is_capped_at_n_and_n_plus_one() -> TestResult {
    let two = encode(vec![service("a", vec![span(1, 1)]), service("b", vec![span(SEED_TWO, SEED_TWO)])]);
    assert_eq!(run(&two, &limits_for(SMALL)).rows.len(), SMALL);
    let three = encode(vec![
        service("a", vec![span(1, 1), span(SEED_TWO, SEED_TWO)]),
        service("b", vec![span(SEED_THREE, SEED_THREE)]),
    ]);
    let outcome = run(&three, &limits_for(SMALL));
    assert!(matches!(outcome.refusal, Some(Refusal::TooManySpans { count: THREE })));
    assert!(outcome.rows.is_empty());
    Ok(())
}


#[test]
fn total_attributes_count_resource_span_event_and_link() -> TestResult {
    let limits = Limits {
        max_total_attributes: FIVE,
        ..Limits::default()
    };
    let loaded = Span {
        attributes: texts(SMALL),
        events: vec![Event {
            attributes: texts(1),
            ..Default::default()
        }],
        links: vec![Link {
            attributes: texts(1),
            ..Default::default()
        }],
        ..span(1, 1)
    };
    let five = encode(vec![resource(texts(1), vec![loaded.clone()])]);
    assert!(run(&five, &limits).refusal.is_none());
    let six = encode(vec![resource(texts(SMALL), vec![loaded])]);
    assert!(matches!(run(&six, &limits).refusal, Some(Refusal::TooManyAttributes { count: SIX })));
    Ok(())
}


#[test]
fn a_million_empty_spans_are_refused_before_any_row() -> TestResult {
    let bytes = encode(vec![resource(Vec::new(), vec![Span::default(); MILLION])]);
    let outcome = run(&bytes, &Limits::default());
    assert!(matches!(outcome.refusal, Some(Refusal::TooManySpans { count: MILLION })));
    assert!(outcome.rows.is_empty());
    assert!(outcome.dropped.is_empty());
    Ok(())
}


#[test]
fn per_span_attribute_event_and_link_caps_drop_the_span() -> TestResult {
    let limits = Limits {
        max_attributes_per_span: SMALL,
        max_events_per_span: SMALL,
        max_links_per_span: SMALL,
        ..Limits::default()
    };
    let at_cap = Span {
        attributes: texts(SMALL),
        events: vec![Event::default(); SMALL],
        links: vec![Link::default(); SMALL],
        ..span(1, 1)
    };
    let kept = run(&encode(vec![service("api", vec![at_cap.clone()])]), &limits);
    assert_eq!(kept.rows.len(), 1);
    assert_eq!(
        kept.rows.first().map(|row| (row.event_count, row.link_count)),
        Some((COUNT_TWO, COUNT_TWO))
    );
    let over = |changed: Span| run(&encode(vec![service("api", vec![changed])]), &limits);
    only_drop(
        &over(Span {
            attributes: texts(THREE),
            ..at_cap.clone()
        }),
        DropReason::TooManyAttributes,
    );
    only_drop(
        &over(Span {
            events: vec![Event::default(); THREE],
            ..at_cap.clone()
        }),
        DropReason::TooManyEvents,
    );
    only_drop(
        &over(Span {
            links: vec![Link::default(); THREE],
            ..at_cap
        }),
        DropReason::TooManyLinks,
    );
    Ok(())
}


#[test]
fn text_byte_caps_apply_at_n_and_n_plus_one() -> TestResult {
    let limits = Limits {
        max_name_bytes: SMALL,
        max_attribute_key_bytes: SMALL,
        max_attribute_value_bytes: SMALL,
        max_status_message_bytes: SMALL,
        ..Limits::default()
    };
    let run_one = |changed: Span| run(&encode(vec![resource(Vec::new(), vec![changed])]), &limits);
    let at_cap = Span {
        name: "ab".to_string(),
        attributes: vec![text("ab", "ab")],
        status: Some(Status {
            code: StatusCode::Ok as i32,
            message: "ab".to_string(),
        }),
        ..span(1, 1)
    };
    assert_eq!(run_one(at_cap.clone()).rows.len(), 1);
    only_drop(
        &run_one(Span {
            name: "abc".to_string(),
            ..at_cap.clone()
        }),
        DropReason::TextTooLong,
    );
    only_drop(
        &run_one(Span {
            attributes: vec![text("abc", "ab")],
            ..at_cap.clone()
        }),
        DropReason::TextTooLong,
    );
    only_drop(
        &run_one(Span {
            attributes: vec![text("ab", "abc")],
            ..at_cap.clone()
        }),
        DropReason::TextTooLong,
    );
    only_drop(
        &run_one(Span {
            status: Some(Status {
                code: 0,
                message: "abc".to_string(),
            }),
            ..at_cap.clone()
        }),
        DropReason::TextTooLong,
    );
    let long_service = encode(vec![service("abc", vec![at_cap])]);
    let outcome = run(&long_service, &limits);
    assert_eq!(dropped(&outcome, DropReason::TextTooLong), Some(1));
    Ok(())
}


#[test]
fn a_one_mebibyte_attribute_value_drops_only_that_span() -> TestResult {
    let big = with_attributes(vec![text("k", &"x".repeat(MEBIBYTE))]);
    let outcome = run(&encode(vec![service("api", vec![big, span(SEED_TWO, SEED_TWO)])]), &Limits::default());
    assert_eq!(dropped(&outcome, DropReason::TextTooLong), Some(1));
    assert_eq!(outcome.rows.len(), 1);
    Ok(())
}


#[test]
fn number_and_bytes_values_are_bounded_after_rendering() -> TestResult {
    let limits = Limits {
        max_attribute_value_bytes: SMALL,
        ..Limits::default()
    };
    let run_one = |value: AnyKind| run(&encode(vec![service("api", vec![with_attributes(vec![pair("k", value)])])]), &limits);
    only_drop(&run_one(AnyKind::IntValue(CODE)), DropReason::TextTooLong);
    only_drop(&run_one(AnyKind::DoubleValue(RATE)), DropReason::TextTooLong);
    only_drop(&run_one(AnyKind::BoolValue(false)), DropReason::TextTooLong);
    only_drop(&run_one(AnyKind::BytesValue(vec![1, SMALL as u8, THREE as u8])), DropReason::TextTooLong);
    assert_eq!(run_one(AnyKind::BytesValue(vec![BAD_BYTE])).rows.len(), 1);
    Ok(())
}


#[test]
fn zero_and_wrong_length_ids_are_dropped() -> TestResult {
    let bad = |changed: Span| only_drop(&one(changed), DropReason::BadId);
    bad(Span {
        trace_id: vec![0; ID_LEN],
        ..span(1, 1)
    });
    bad(Span {
        trace_id: vec![1; SHORT_ID],
        ..span(1, 1)
    });
    bad(Span {
        trace_id: Vec::new(),
        ..span(1, 1)
    });
    bad(Span {
        span_id: vec![0; SPAN_LEN],
        ..span(1, 1)
    });
    bad(Span {
        span_id: vec![1; THREE],
        ..span(1, 1)
    });
    bad(Span {
        parent_span_id: vec![0; SPAN_LEN],
        ..span(1, 1)
    });
    bad(Span {
        parent_span_id: vec![1; THREE],
        ..span(1, 1)
    });
    Ok(())
}


#[test]
fn parent_ids_are_optional_and_kept_when_valid() -> TestResult {
    let root = one(span(1, 1));
    assert_eq!(root.rows.first().map(|row| row.parent_span_id), Some(None));
    let child = one(Span {
        parent_span_id: vec![SMALL as u8; SPAN_LEN],
        ..span(1, 1)
    });
    assert_eq!(child.rows.first().map(|row| row.parent_span_id), Some(Some([SMALL as u8; SPAN_LEN])));
    Ok(())
}


#[test]
fn end_before_start_is_dropped_and_equal_times_are_kept() -> TestResult {
    only_drop(
        &one(Span {
            start_time_unix_nano: NOW,
            end_time_unix_nano: NOW - 1,
            ..span(1, 1)
        }),
        DropReason::BadTime,
    );
    let instant = one(Span {
        start_time_unix_nano: NOW,
        end_time_unix_nano: NOW,
        ..span(1, 1)
    });
    assert_eq!(instant.rows.len(), 1);
    Ok(())
}


#[test]
fn future_skew_is_capped_at_n_and_n_plus_one() -> TestResult {
    let ahead = |nanos: u64| {
        one(Span {
            start_time_unix_nano: NOW,
            end_time_unix_nano: NOW + nanos,
            ..span(1, 1)
        })
    };
    assert_eq!(ahead(SKEW * SECOND).rows.len(), 1);
    only_drop(&ahead(SKEW * SECOND + 1), DropReason::FutureSkew);
    only_drop(
        &one(Span {
            start_time_unix_nano: u64::MAX,
            end_time_unix_nano: u64::MAX,
            ..span(1, 1)
        }),
        DropReason::FutureSkew,
    );
    only_drop(
        &one(Span {
            start_time_unix_nano: u64::MAX,
            end_time_unix_nano: 0,
            ..span(1, 1)
        }),
        DropReason::BadTime,
    );
    Ok(())
}


#[test]
fn kind_and_status_are_validated() -> TestResult {
    only_drop(
        &one(Span {
            kind: BAD_ENUM,
            ..span(1, 1)
        }),
        DropReason::BadKind,
    );
    only_drop(
        &one(Span {
            status: Some(Status {
                code: BAD_ENUM,
                message: String::new(),
            }),
            ..span(1, 1)
        }),
        DropReason::BadStatus,
    );
    let unset = one(span(1, 1));
    assert_eq!(
        unset.rows.first().map(|row| (row.status_code, row.kind)),
        Some((StatusCode::Unset, SpanKind::Server))
    );
    let failed = one(Span {
        status: Some(Status {
            code: StatusCode::Error as i32,
            message: "boom".to_string(),
        }),
        ..span(1, 1)
    });
    assert_eq!(
        failed.rows.first().map(|row| (row.status_code, row.status_message.as_str())),
        Some((StatusCode::Error, "boom"))
    );
    Ok(())
}


#[test]
fn forbidden_text_is_refused_in_every_text_field() -> TestResult {
    [LEFT_TO_RIGHT_MARK, ZERO_WIDTH, OVERRIDE, LINE_BREAK]
        .iter()
        .try_for_each(|bad| -> TestResult {
            only_drop(
                &one(Span {
                    name: bad.to_string(),
                    ..span(1, 1)
                }),
                DropReason::BadText,
            );
            only_drop(&one(with_attributes(vec![text(bad, "v")])), DropReason::BadText);
            only_drop(&one(with_attributes(vec![text("k", bad)])), DropReason::BadText);
            only_drop(
                &one(Span {
                    status: Some(Status {
                        code: 0,
                        message: bad.to_string(),
                    }),
                    ..span(1, 1)
                }),
                DropReason::BadText,
            );
            let outcome = run(&encode(vec![service(bad, vec![span(1, 1)])]), &Limits::default());
            only_drop(&outcome, DropReason::BadText);
            Ok(())
        })
}


#[test]
fn empty_attribute_key_is_refused() -> TestResult {
    only_drop(&one(with_attributes(vec![text("", "v")])), DropReason::BadText);
    Ok(())
}


#[test]
fn attributes_are_rendered_sorted_and_deterministic() -> TestResult {
    let outcome = one(with_attributes(vec![
        pair("z", AnyKind::BoolValue(true)),
        pair("m", AnyKind::IntValue(CODE)),
        pair("d", AnyKind::DoubleValue(RATE)),
        pair("b", AnyKind::BytesValue(vec![1, BAD_BYTE])),
        text("a", "first"),
        text("a", "last"),
    ]));
    let row = outcome.rows.first().ok_or("row")?;
    let expected = [("a", "last"), ("b", "01ff"), ("d", "2.5"), ("m", "12345"), ("z", "true")];
    let rendered: Vec<(&str, &str)> = row.attributes.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
    assert_eq!(rendered, expected);
    assert_eq!(to_hex(&[1, BAD_BYTE]), "01ff");
    Ok(())
}


#[test]
fn unsupported_values_drop_only_the_attribute() -> TestResult {
    let list = AnyKind::KvlistValue(KeyValueList { values: Vec::new() });
    let empty = KeyValue {
        key: "k".to_string(),
        value: Some(AnyValue { value: None }),
        ..Default::default()
    };
    let missing = KeyValue {
        key: "k".to_string(),
        value: None,
        ..Default::default()
    };
    let cases = vec![
        pair("k", list),
        pair("k", AnyKind::StringValueStrindex(1)),
        empty,
        missing,
        pair("k", array_of(vec![scalar(array_of(Vec::new()))])),
        pair("k", array_of(vec![AnyValue { value: None }])),
    ];
    cases.into_iter().try_for_each(|bad| -> TestResult {
        let outcome = one(with_attributes(vec![bad, text("keep", "me")]));
        assert_eq!(outcome.rows.len(), 1);
        assert_eq!(
            outcome.rows.first().map(|row| row.attributes.clone()),
            Some(vec![("keep".to_string(), "me".to_string())])
        );
        assert_eq!(dropped(&outcome, DropReason::UnsupportedValue), Some(1));
        assert_eq!(outcome.dropped.len(), 1);
        Ok(())
    })
}


fn array_of(values: Vec<AnyValue>) -> AnyKind {
    AnyKind::ArrayValue(ArrayValue { values })
}


fn scalar(value: AnyKind) -> AnyValue {
    AnyValue { value: Some(value) }
}


fn strings(items: &[&str]) -> AnyKind {
    array_of(items.iter().map(|item| scalar(AnyKind::StringValue((*item).to_string()))).collect())
}


fn render_with(value: AnyKind, limit: usize) -> Outcome {
    let limits = Limits {
        max_attribute_value_bytes: limit,
        ..Limits::default()
    };
    run(&encode(vec![service("api", vec![with_attributes(vec![pair("k", value)])])]), &limits)
}


fn rendered(outcome: &Outcome) -> Option<String> {
    outcome
        .rows
        .first()
        .and_then(|row| row.attributes.first())
        .map(|(_, value)| value.clone())
}


#[test]
fn arrays_of_scalars_render_as_json_text_within_the_cap() -> TestResult {
    let mixed = array_of(vec![
        scalar(AnyKind::StringValue("a".to_string())),
        scalar(AnyKind::IntValue(CODE)),
        scalar(AnyKind::BoolValue(true)),
    ]);
    let outcome = one(with_attributes(vec![pair("k", mixed), pair("empty", array_of(Vec::new()))]));
    let attributes = outcome.rows.first().map(|row| row.attributes.clone());
    assert_eq!(
        attributes,
        Some(vec![
            ("empty".to_string(), "[]".to_string()),
            ("k".to_string(), "[\"a\",\"12345\",\"true\"]".to_string())
        ])
    );
    let joined = render_with(strings(&["a,b"]), JSON_BIG);
    let split = render_with(strings(&["a", "b"]), JSON_BIG);
    let blank = render_with(strings(&["a", "", "b"]), JSON_BIG);
    assert_eq!(rendered(&joined).as_deref(), Some("[\"a,b\"]"));
    assert_eq!(rendered(&split).as_deref(), Some("[\"a\",\"b\"]"));
    assert_eq!(rendered(&blank).as_deref(), Some("[\"a\",\"\",\"b\"]"));
    assert_eq!(render_with(strings(&["a"]), JSON_LIMIT).rows.len(), 1);
    only_drop(&render_with(strings(&["a"]), JSON_LIMIT - 1), DropReason::TextTooLong);
    only_drop(&render_with(strings(&["ab", "c"]), JSON_LIMIT), DropReason::TextTooLong);
    only_drop(&render_with(strings(&["abc", "def"]), JSON_LIMIT), DropReason::TextTooLong);
    let forbidden = array_of(vec![scalar(AnyKind::StringValue(ZERO_WIDTH.to_string()))]);
    only_drop(&one(with_attributes(vec![pair("k", forbidden)])), DropReason::BadText);
    Ok(())
}


fn scopes_request(scopes: usize, spans_each: usize) -> Vec<u8> {
    let scope = framed(SCOPE_SPANS_TAG, &[SPANS_TAG, 0].repeat(spans_each));
    framed(RESOURCE_SPANS_TAG, &scope.repeat(scopes))
}


#[test]
fn scopes_and_spans_are_counted_on_the_wire_before_decoding() -> TestResult {
    let limits = limits_for(SMALL);
    assert!(run(&scopes_request(SMALL, 1), &limits).refusal.is_none());
    assert!(run(&scopes_request(1, SMALL), &limits).refusal.is_none());
    assert!(matches!(
        run(&scopes_request(THREE, 1), &limits).refusal,
        Some(Refusal::TooManySpans { count: THREE })
    ));
    assert!(matches!(
        run(&scopes_request(1, THREE), &limits).refusal,
        Some(Refusal::TooManySpans { count: THREE })
    ));
    let empty_resources = [RESOURCE_SPANS_TAG, 0].repeat(THREE);
    let few = Limits {
        max_resource_spans: SMALL,
        ..Limits::default()
    };
    assert!(matches!(
        run(&empty_resources, &few).refusal,
        Some(Refusal::TooManyResourceSpans { count: THREE })
    ));
    Ok(())
}


const VARINT_KEY: u8 = 0x38;


const FIXED64_KEY: u8 = 0x39;


const FIXED32_KEY: u8 = 0x3d;


const BYTES_KEY: u8 = 0x3a;


const START_GROUP_KEY: u8 = 0x3b;


const END_GROUP_KEY: u8 = 0x3c;


const FIXED32_LEN: usize = 4;


const CONTINUATION: u8 = 0x80;


const ALL_BITS: u8 = 0xff;


const LEN_PAST_END: u8 = 0x7f;


const VARINT_OVERLONG: usize = 10;


#[test]
fn other_fields_and_wire_types_are_skipped_by_the_scan() -> TestResult {
    let unknown_varint = vec![VARINT_KEY, 1];
    let unknown_fixed = [&[FIXED64_KEY][..], &[0; SPAN_LEN]].concat();
    let unknown_fixed32 = [&[FIXED32_KEY][..], &[0; FIXED32_LEN]].concat();
    let unknown_bytes = framed(BYTES_KEY, b"xyz");
    let group = vec![START_GROUP_KEY, END_GROUP_KEY];
    let bytes = [unknown_varint, unknown_fixed, unknown_fixed32, unknown_bytes, group, scopes_request(1, 1)].concat();
    let outcome = run(&bytes, &limits_for(1));
    assert!(outcome.refusal.is_none());
    Ok(())
}


#[test]
fn a_truncated_wire_is_malformed_at_every_level() -> TestResult {
    let good = scopes_request(1, 1);
    let overlong = [&[RESOURCE_SPANS_TAG][..], &[ALL_BITS].repeat(VARINT_OVERLONG)].concat();
    let cases: Vec<Vec<u8>> = vec![
        vec![RESOURCE_SPANS_TAG],
        vec![RESOURCE_SPANS_TAG, CONTINUATION],
        vec![RESOURCE_SPANS_TAG, LEN_PAST_END, SCOPE_SPANS_TAG],
        framed(RESOURCE_SPANS_TAG, &[SCOPE_SPANS_TAG]),
        framed(RESOURCE_SPANS_TAG, &[SCOPE_SPANS_TAG, LEN_PAST_END]),
        framed(RESOURCE_SPANS_TAG, &framed(SCOPE_SPANS_TAG, &[SPANS_TAG])),
        framed(RESOURCE_SPANS_TAG, &framed(SCOPE_SPANS_TAG, &[SPANS_TAG, LEN_PAST_END])),
        vec![CONTINUATION],
        overlong,
        good.iter().copied().take(good.len().saturating_sub(1)).collect(),
    ];
    cases.iter().try_for_each(|bytes| -> TestResult {
        let outcome = run(bytes, &Limits::default());
        assert!(matches!(outcome.refusal, Some(Refusal::Malformed(_))), "{bytes:?}");
        assert!(outcome.rows.is_empty());
        Ok(())
    })
}


#[test]
fn a_refused_tenant_leaves_the_outcome_tenant_empty() -> TestResult {
    let outcome = decode_traces(&scopes_request(1, 1), "-x", &Limits::default(), &Sampling::default(), NOW);
    assert!(outcome.tenant.is_empty());
    let accepted = run(&scopes_request(1, 1), &Limits::default());
    assert_eq!(accepted.tenant, TENANT);
    Ok(())
}


#[test]
fn service_name_comes_from_the_resource_or_defaults() -> TestResult {
    let named = run(&encode(vec![service("checkout", vec![span(1, 1)])]), &Limits::default());
    assert_eq!(named.rows.first().map(|row| row.service_name.as_str()), Some("checkout"));
    let fallbacks = [
        resource(Vec::new(), vec![span(1, 1)]),
        resource(vec![text("service.name", "")], vec![span(1, 1)]),
        resource(vec![pair("service.name", AnyKind::IntValue(1))], vec![span(1, 1)]),
        ResourceSpans {
            resource: None,
            scope_spans: vec![ScopeSpans {
                spans: vec![span(1, 1)],
                ..Default::default()
            }],
            ..Default::default()
        },
    ];
    fallbacks.iter().try_for_each(|fallback| -> TestResult {
        let outcome = run(&encode(vec![fallback.clone()]), &Limits::default());
        assert_eq!(outcome.rows.first().map(|row| row.service_name.as_str()), Some("unknown_service"));
        Ok(())
    })
}


#[test]
fn rows_carry_the_argument_tenant_never_the_payload() -> TestResult {
    let outcome = one(with_attributes(vec![text("tenant", "evil")]));
    let row = outcome.rows.first().ok_or("row")?;
    assert_eq!(row.tenant, TENANT);
    assert_eq!(outcome.tenant, TENANT);
    assert_eq!(row.attributes, vec![("tenant".to_string(), "evil".to_string())]);
    Ok(())
}


#[test]
fn nested_values_ten_thousand_deep_are_refused_by_the_decoder() -> TestResult {
    let bytes = nested_request(nested_array, DEPTH);
    let outcome = run(&bytes, &Limits::default());
    assert!(matches!(outcome.refusal, Some(Refusal::Malformed(_))));
    assert!(outcome.rows.is_empty());
    Ok(())
}


fn split_request(first: bool) -> Vec<u8> {
    let spans = (1..=TRACES).map(|seed| span(seed, if first { 1 } else { SMALL as u8 })).collect();
    encode(vec![service("api", spans)])
}


fn kept_traces(outcome: &Outcome) -> Vec<String> {
    outcome.rows.iter().map(|row| to_hex(&row.trace_id)).collect()
}


#[test]
fn sampling_decision_is_per_trace_whatever_the_request_split() -> TestResult {
    let sampling = Sampling {
        default_ratio: HALF,
        ..Sampling::default()
    };
    let first = run_with(&split_request(true), &Limits::default(), &sampling);
    let second = run_with(&split_request(false), &Limits::default(), &sampling);
    assert_eq!(kept_traces(&first), kept_traces(&second));
    let expected: Vec<String> = (1..=TRACES)
        .map(trace_bytes)
        .filter(|id| {
            id.get(..SPAN_LEN)
                .and_then(|head| head.try_into().ok())
                .map(u64::from_be_bytes)
                .is_some_and(|hash| hash < HALF_HASH)
        })
        .map(|id| to_hex(&id))
        .collect();
    assert_eq!(kept_traces(&first), expected);
    assert!(!expected.is_empty() && expected.len() < usize::from(TRACES));
    assert_eq!(first.sampled_out, u64::from(TRACES) - to_u64(expected.len()));
    assert_eq!(trace_hash(&[1; ID_LEN]), u64::from_be_bytes([1; SPAN_LEN]));
    Ok(())
}


fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}


#[test]
fn ratio_zero_keeps_nothing_and_ratio_one_keeps_everything() -> TestResult {
    let bytes = split_request(true);
    let none = Sampling {
        default_ratio: ZERO_F,
        ..Sampling::default()
    };
    let dropped_all = run_with(&bytes, &Limits::default(), &none);
    assert!(dropped_all.rows.is_empty());
    assert_eq!(dropped_all.sampled_out, u64::from(TRACES));
    assert!(dropped_all.dropped.is_empty());
    let all = run_with(&bytes, &Limits::default(), &Sampling::default());
    assert_eq!(all.rows.len(), usize::from(TRACES));
    assert_eq!(all.sampled_out, 0);
    Ok(())
}


#[test]
fn error_spans_use_the_error_ratio_and_services_override_the_default() -> TestResult {
    let failing = |trace: u8| Span {
        status: Some(Status {
            code: StatusCode::Error as i32,
            message: String::new(),
        }),
        ..span(trace, 1)
    };
    let spans: Vec<Span> = (1..=TRACES).map(failing).collect();
    let bytes = encode(vec![service("api", spans.clone()), service("batch", spans)]);
    let sampling = Sampling {
        default_ratio: ZERO_F,
        error_ratio: Some(ONE_F),
        ..Sampling::default()
    };
    let outcome = run_with(&bytes, &Limits::default(), &sampling);
    assert_eq!(outcome.rows.len(), usize::from(TRACES) * SMALL);
    let plain = encode(vec![service("api", (1..=TRACES).map(|seed| span(seed, 1)).collect())]);
    assert!(run_with(&plain, &Limits::default(), &sampling).rows.is_empty());
    let mut overridden = sampling.clone();
    overridden.services.insert("api".to_string(), ONE_F);
    assert_eq!(run_with(&plain, &Limits::default(), &overridden).rows.len(), usize::from(TRACES));
    Ok(())
}


#[test]
fn reasons_have_stable_names() -> TestResult {
    let names: Vec<String> = [
        DropReason::BadId,
        DropReason::BadTime,
        DropReason::FutureSkew,
        DropReason::BadKind,
        DropReason::BadStatus,
        DropReason::BadText,
        DropReason::TextTooLong,
        DropReason::UnsupportedValue,
        DropReason::TooManyAttributes,
        DropReason::TooManyEvents,
        DropReason::TooManyLinks,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(
        names,
        [
            "bad_id",
            "bad_time",
            "future_skew",
            "bad_kind",
            "bad_status",
            "bad_text",
            "text_too_long",
            "unsupported_value",
            "too_many_attributes",
            "too_many_events",
            "too_many_links"
        ]
    );
    Ok(())
}
