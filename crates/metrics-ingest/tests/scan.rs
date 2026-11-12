mod common;


use common::types::TestResult;
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::decode::decode_request;
use metrics_ingest::model::{Limits, Refusal, Totals};
use metrics_ingest::scan::scan_request;
use prost::encoding::encode_varint;


const RESOURCE_METRICS: u8 = 0x0a;


const RESOURCE: u8 = 0x0a;


const SCOPE_METRICS: u8 = 0x12;


const SCOPE: u8 = 0x0a;


const METRIC: u8 = 0x12;


const ATTRIBUTE: u8 = 0x0a;


const ENTITY_REFS: u8 = 0x1a;


const ID_KEYS: u8 = 0x1a;


const DESCRIPTION_KEYS: u8 = 0x22;


const SCOPE_ATTRIBUTES: u8 = 0x1a;


const METADATA: u8 = 0x62;


const GAUGE: u8 = 0x2a;


const SUM: u8 = 0x3a;


const HISTOGRAM: u8 = 0x4a;


const EXPONENTIAL: u8 = 0x52;


const SUMMARY: u8 = 0x5a;


const POINTS: u8 = 0x0a;


const NUMBER_ATTRIBUTES: u8 = 0x3a;


const NUMBER_EXEMPLARS: u8 = 0x2a;


const HISTOGRAM_EXEMPLARS: u8 = 0x42;


const EXPONENTIAL_ATTRIBUTES: u8 = 0x0a;


const QUANTILES: u8 = 0x32;


const EXEMPLAR_ATTRIBUTES: u8 = 0x3a;


const VALUE: u8 = 0x12;


const ARRAY: u8 = 0x2a;


const KVLIST: u8 = 0x32;


const ELEMENT: u8 = 0x0a;


const VARINT_FIELD: [u8; 2] = [0x08, 0x01];


const TWO: usize = 2;


const THREE: usize = 3;


const FOUR: usize = 4;


const SEVEN: usize = 7;


const THIRTEEN: usize = 13;


const DEEP: usize = 150;


const LENGTH_CONTINUATION: u8 = 0x80;


const LENGTH_FIVE: u8 = 0x05;


fn framed(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    encode_varint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}


fn join(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}


fn empty(tag: u8) -> Vec<u8> {
    vec![tag, 0]
}


fn attribute_with(value: &[u8]) -> Vec<u8> {
    framed(ATTRIBUTE, &framed(VALUE, value))
}


fn in_metrics(metrics: &[Vec<u8>]) -> Vec<u8> {
    let framed_metrics: Vec<Vec<u8>> = metrics.iter().map(|metric| framed(METRIC, metric)).collect();
    framed(RESOURCE_METRICS, &framed(SCOPE_METRICS, &join(&framed_metrics)))
}


fn in_resource(parts: &[Vec<u8>]) -> Vec<u8> {
    framed(RESOURCE_METRICS, &framed(RESOURCE, &join(parts)))
}


fn limited(change: fn(&mut Limits)) -> Limits {
    let mut limits = Limits::default();
    change(&mut limits);
    limits
}


fn totals_of(bytes: &[u8], limits: &Limits) -> Result<Totals, String> {
    scan_request(bytes, limits).map_err(|refused| format!("{refused:?}"))
}


fn refusal(bytes: &[u8], limits: &Limits) -> Option<Refusal> {
    scan_request(bytes, limits).err()
}


fn full_request() -> Vec<u8> {
    let nested_array = framed(ARRAY, &framed(ELEMENT, &[]));
    let array = framed(ARRAY, &join(&[empty(ELEMENT), framed(ELEMENT, &nested_array)]));
    let point_one = join(&[
        framed(NUMBER_ATTRIBUTES, &framed(VALUE, &array)),
        framed(NUMBER_EXEMPLARS, &empty(EXEMPLAR_ATTRIBUTES)),
        VARINT_FIELD.to_vec(),
    ]);
    let gauge = framed(GAUGE, &join(&[framed(POINTS, &point_one), empty(POINTS)]));
    let first = join(&[gauge, empty(METADATA), VARINT_FIELD.to_vec()]);
    let histogram = framed(HISTOGRAM, &framed(POINTS, &empty(HISTOGRAM_EXEMPLARS)));
    let exponential = framed(EXPONENTIAL, &framed(POINTS, &empty(EXPONENTIAL_ATTRIBUTES)));
    let summary = framed(SUMMARY, &framed(POINTS, &join(&[empty(QUANTILES), empty(QUANTILES)])));
    let resource = join(&[
        empty(ATTRIBUTE),
        framed(ENTITY_REFS, &join(&[empty(ID_KEYS), empty(ID_KEYS), empty(DESCRIPTION_KEYS)])),
    ]);
    let scope = framed(SCOPE, &empty(SCOPE_ATTRIBUTES));
    let metrics = join(&[
        framed(METRIC, &first),
        framed(METRIC, &histogram),
        framed(METRIC, &exponential),
        framed(METRIC, &summary),
        framed(METRIC, &[]),
        framed(METRIC, &empty(GAUGE)),
    ]);
    framed(
        RESOURCE_METRICS,
        &join(&[framed(RESOURCE, &resource), framed(SCOPE_METRICS, &join(&[scope, metrics]))]),
    )
}


#[test]
fn every_repeated_field_is_counted_on_the_wire() -> TestResult {
    let totals = totals_of(&full_request(), &Limits::default())?;
    assert_eq!(
        totals,
        Totals {
            resources: 1,
            scopes: 1,
            points: SEVEN,
            extras: FOUR,
            attributes: THIRTEEN,
        }
    );
    Ok(())
}


#[test]
fn sum_points_are_counted_and_unrelated_fields_ignored() -> TestResult {
    let sum = framed(SUM, &join(&[empty(POINTS), empty(POINTS), VARINT_FIELD.to_vec()]));
    let totals = totals_of(&in_metrics(&[sum]), &Limits::default())?;
    assert_eq!(totals.points, TWO);
    Ok(())
}


#[test]
fn each_total_is_refused_over_its_limit() -> TestResult {
    let two_resources = join(&[empty(RESOURCE_METRICS), empty(RESOURCE_METRICS)]);
    assert_eq!(
        refusal(&two_resources, &limited(|limits| limits.max_resources = 1)),
        Some(Refusal::TooManyResources { count: TWO })
    );
    let two_metrics = in_metrics(&[Vec::new(), Vec::new()]);
    assert_eq!(
        refusal(&two_metrics, &limited(|limits| limits.max_data_points = 1)),
        Some(Refusal::TooManyDataPoints { count: TWO })
    );
    assert_eq!(refusal(&two_metrics, &limited(|limits| limits.max_data_points = TWO)), None);
    let scopes = framed(
        RESOURCE_METRICS,
        &join(&[empty(SCOPE_METRICS), empty(SCOPE_METRICS), empty(SCOPE_METRICS)]),
    );
    assert_eq!(
        refusal(&scopes, &limited(|limits| limits.max_data_points = TWO)),
        Some(Refusal::TooManyDataPoints { count: THREE })
    );
    let three_exemplars = join(&[empty(NUMBER_EXEMPLARS), empty(NUMBER_EXEMPLARS), empty(NUMBER_EXEMPLARS)]);
    let exemplars = in_metrics(&[framed(GAUGE, &framed(POINTS, &three_exemplars))]);
    assert_eq!(
        refusal(&exemplars, &limited(|limits| limits.max_data_points = TWO)),
        Some(Refusal::TooManyDataPoints { count: THREE })
    );
    let attributes = in_resource(&[empty(ATTRIBUTE), empty(ATTRIBUTE), empty(ATTRIBUTE)]);
    assert_eq!(
        refusal(&attributes, &limited(|limits| limits.max_total_attributes = TWO)),
        Some(Refusal::TooManyAttributes { count: THREE })
    );
    Ok(())
}


#[test]
fn value_elements_count_toward_the_attribute_total() -> TestResult {
    let array = framed(ARRAY, &join(&[empty(ELEMENT), empty(ELEMENT), empty(ELEMENT)]));
    let request = in_resource(&[attribute_with(&array)]);
    assert_eq!(
        refusal(&request, &limited(|limits| limits.max_total_attributes = THREE)),
        Some(Refusal::TooManyAttributes { count: FOUR })
    );
    assert_eq!(refusal(&request, &limited(|limits| limits.max_total_attributes = FOUR)), None);
    Ok(())
}


#[test]
fn key_value_lists_are_walked_and_depth_is_bounded() -> TestResult {
    let entry = framed(ELEMENT, &framed(VALUE, &framed(ARRAY, &empty(ELEMENT))));
    let list = framed(KVLIST, &entry);
    assert_eq!(totals_of(&in_resource(&[attribute_with(&list)]), &Limits::default())?.attributes, THREE);
    let deep = (0..DEEP).fold(Vec::new(), |inner, _| framed(ARRAY, &framed(ELEMENT, &inner)));
    assert!(scan_request(&in_resource(&[attribute_with(&deep)]), &Limits::default()).is_ok());
    Ok(())
}


#[test]
fn an_over_limit_value_is_refused_at_every_attribute_owner() -> TestResult {
    let array = framed(ARRAY, &join(&[empty(ELEMENT), empty(ELEMENT)]));
    let attribute = |tag: u8| framed(tag, &framed(VALUE, &array));
    let exemplar = framed(NUMBER_EXEMPLARS, &attribute(EXEMPLAR_ATTRIBUTES));
    let point = |inner: Vec<u8>| in_metrics(&[framed(GAUGE, &framed(POINTS, &inner))]);
    let requests = [
        framed(RESOURCE_METRICS, &framed(SCOPE_METRICS, &framed(SCOPE, &attribute(SCOPE_ATTRIBUTES)))),
        in_metrics(&[attribute(METADATA)]),
        point(attribute(NUMBER_ATTRIBUTES)),
        point(exemplar),
    ];
    let limits = limited(|current| current.max_total_attributes = 1);
    requests.iter().for_each(|request| {
        assert!(matches!(refusal(request, &limits), Some(Refusal::TooManyAttributes { .. })));
    });
    Ok(())
}


#[test]
fn unrelated_fields_inside_values_are_skipped() -> TestResult {
    let array = framed(ARRAY, &join(&[empty(ELEMENT), VARINT_FIELD.to_vec(), empty(SCOPE_METRICS)]));
    let totals = totals_of(&in_resource(&[attribute_with(&array)]), &Limits::default())?;
    assert_eq!(totals.attributes, TWO);
    Ok(())
}


#[test]
fn malformed_wire_is_refused_at_every_level() -> TestResult {
    let limits = Limits::default();
    assert!(matches!(
        refusal(&[RESOURCE_METRICS, LENGTH_CONTINUATION], &limits),
        Some(Refusal::Malformed(_))
    ));
    assert!(matches!(
        refusal(&[RESOURCE_METRICS, LENGTH_FIVE, 0], &limits),
        Some(Refusal::Malformed(_))
    ));
    assert!(matches!(
        refusal(&in_resource(&[attribute_with(&[ARRAY])]), &limits),
        Some(Refusal::Malformed(_))
    ));
    let broken_array = framed(ARRAY, &[ELEMENT]);
    assert!(matches!(
        refusal(&in_resource(&[attribute_with(&broken_array)]), &limits),
        Some(Refusal::Malformed(_))
    ));
    let broken_entry = framed(KVLIST, &framed(ELEMENT, &[VALUE]));
    assert!(matches!(
        refusal(&in_resource(&[attribute_with(&broken_entry)]), &limits),
        Some(Refusal::Malformed(_))
    ));
    let broken_ref = framed(ENTITY_REFS, &[ID_KEYS]);
    assert!(matches!(refusal(&in_resource(&[broken_ref]), &limits), Some(Refusal::Malformed(_))));
    let second_key_broken = framed(ENTITY_REFS, &join(&[empty(ID_KEYS), vec![DESCRIPTION_KEYS]]));
    assert!(matches!(
        refusal(&in_resource(&[second_key_broken]), &limits),
        Some(Refusal::Malformed(_))
    ));
    Ok(())
}


#[test]
fn the_scan_refuses_before_prost_decodes() -> TestResult {
    let bytes = in_metrics(&[Vec::new(), Vec::new()]);
    let limits = limited(|current| current.max_data_points = 1);
    let outcome = decode_request(&bytes, "tenant-a", &limits, &mut CardinalityState::default());
    assert_eq!(outcome.refusal, Some(Refusal::TooManyDataPoints { count: TWO }));
    assert!(outcome.rows.is_empty());
    Ok(())
}
