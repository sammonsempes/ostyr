#[path = "common/types.rs"]
mod types;


use cloud_posture::error::ParseError;
use cloud_posture::limits::{Limits, CEILING_MAX_BYTES};
use cloud_posture::model::{Findings, Severity, Skipped, Status};
use cloud_posture::prowler::{checked_time, parse_prowler_ocsf};
use cloud_posture::text::{escaped_whole, shown, status_of, MAX_FINDING_UID_BYTES};
use core_pg::scope::tenant_of;
use serde_json::{json, Value};
use std::error::Error;
use std::io::Read;
use types::TestResult;


const TENANT: &str = "lab";


const ACCOUNT: &str = "123456789012";


const YEAR_10000: i64 = 253_402_300_800;


const YEAR_9999_END: i64 = 253_402_300_799;


const YEAR_MINUS_1: i64 = -62_167_219_201;


const YEAR_0_START: i64 = -62_167_219_200;


const SMALL_CAP: usize = 3;


const LOOK_ALIKES: usize = 2;


const FOREIGN: usize = 3;


const DISTINCT: usize = 4;


const BOTH: usize = 2;


const UNPARSABLE: usize = 4;


const FIXED_KEYS: usize = 2;


const FINDING_TIME: i64 = 1_794_646_103;


const UNMAPPED_CAP: usize = 8;


const TOO_MANY: usize = 4;


const FLOOD: usize = 10_000;


const REFUSED_FIELDS: usize = 4;


const OVER_CAP_BYTES: usize = 1_025;


const MEBIBYTE: usize = 1_048_576;


const TEXT_CAP: usize = 1_024;


const EMOJI_BYTES: usize = 4;


const SMALL_BYTES: u64 = 10;


const GIBIBYTE: u64 = 1_073_741_824;


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("broken pipe"))
    }
}


fn cloud_finding() -> Value {
    json!({
        "message": "bucket is public",
        "finding_info": {
            "uid": "prowler-aws-s3_bucket_public_access-123456789012-us-east-1-my-bucket",
            "title": "Check S3 bucket public access",
            "types": ["Effects/Data Exposure"]
        },
        "metadata": { "event_code": "s3_bucket_public_access" },
        "status_code": "FAIL",
        "status_detail": "S3 Bucket my-bucket has public access.",
        "severity": "Critical",
        "time": FINDING_TIME,
        "resources": [{
            "uid": "arn:aws:s3:::my-bucket",
            "type": "AwsS3Bucket",
            "name": "my-bucket",
            "labels": ["env:prod"],
            "data": { "details": "", "metadata": { "deep": { "er": ["a", "b", "c"] } } }
        }],
        "cloud": {
            "account": { "uid": ACCOUNT, "name": "prod" },
            "provider": "aws",
            "region": "us-east-1"
        },
        "unmapped": {
            "provider": "aws",
            "provider_uid": ACCOUNT,
            "categories": ["internet-exposed"],
            "depends_on": [],
            "related_to": [],
            "additional_urls": [],
            "compliance": { "CIS-1.4": ["2.1.5"], "ISO27001-2013": ["A.9.1.1", "A.9.4.1"] }
        }
    })
}


fn cluster_finding() -> Value {
    json!({
        "finding_info": {
            "uid": "prowler-kubernetes-apiserver_anonymous_requests-lab-cluster-namespace: default-kubernetes",
            "title": "Ensure that anonymous requests are disabled"
        },
        "metadata": { "event_code": "apiserver_anonymous_requests" },
        "status_code": "PASS",
        "status_detail": "API Server does not allow anonymous requests.",
        "severity": "High",
        "time": FINDING_TIME,
        "resources": [{ "uid": "kube-apiserver-node-1", "type": "KubernetesAPIServer", "namespace": "default" }],
        "unmapped": { "provider": "kubernetes", "provider_uid": "lab-cluster" }
    })
}


fn set(mut finding: Value, pointer: &str, value: Value) -> Result<Value, Box<dyn Error>> {
    *finding.pointer_mut(pointer).ok_or(pointer.to_owned())? = value;
    Ok(finding)
}


fn parse_with(findings: &[Value], account: &str, limits: &Limits) -> Result<Findings, Box<dyn Error>> {
    let bytes = serde_json::to_vec(findings)?;
    Ok(parse_prowler_ocsf(bytes.as_slice(), TENANT, account, limits)?)
}


fn parse(findings: &[Value]) -> Result<Findings, Box<dyn Error>> {
    parse_with(findings, ACCOUNT, &Limits::default())
}


fn skipped_of(findings: &[Value], limits: &Limits) -> Result<(usize, Skipped), Box<dyn Error>> {
    let parsed = parse_with(findings, ACCOUNT, limits)?;
    Ok((parsed.items.len(), parsed.skipped))
}


fn only_bad_field(skipped: &Skipped) -> bool {
    *skipped
        == Skipped {
            bad_field: 1,
            refused_by_status: skipped.refused_by_status.clone(),
            ..Skipped::default()
        }
}


#[test]
fn a_cloud_finding_and_a_cluster_finding_are_kept_with_their_identity() -> TestResult {
    let parsed = parse(&[cloud_finding()])?;
    assert_eq!(tenant_of(&parsed.tenant), TENANT);
    assert_eq!(parsed.account, ACCOUNT);
    assert_eq!(parsed.skipped, Skipped::default());
    let finding = parsed.items.first().ok_or("no finding")?;
    assert_eq!(finding.check_id, "s3_bucket_public_access");
    assert_eq!(finding.status, Status::Fail);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.provider, "aws");
    assert_eq!(finding.account, ACCOUNT);
    assert_eq!(finding.region, "us-east-1");
    assert_eq!(finding.resource_uid, "arn:aws:s3:::my-bucket");
    assert_eq!(finding.resource_type, "AwsS3Bucket");
    assert_eq!(finding.time_unix, FINDING_TIME);
    assert_eq!(finding.title, "Check S3 bucket public access");
    assert_eq!(finding.detail, "S3 Bucket my-bucket has public access.");
    let cluster = parse_with(&[cluster_finding()], "lab-cluster", &Limits::default())?;
    let found = cluster.items.first().ok_or("no cluster finding")?;
    assert_eq!(
        (found.provider.as_str(), found.account.as_str(), found.region.as_str()),
        ("kubernetes", "lab-cluster", "default")
    );
    assert_eq!(found.status, Status::Pass);
    assert!(found.uid.contains("namespace: default"));
    Ok(())
}


#[test]
fn every_status_and_severity_of_the_source_is_accepted_and_others_are_bad_field() -> TestResult {
    let statuses = [
        ("PASS", Status::Pass),
        ("FAIL", Status::Fail),
        ("MANUAL", Status::Manual),
        ("MUTED", Status::Muted),
    ];
    statuses.iter().try_for_each(|(text, expected)| {
        let parsed = parse(&[set(cloud_finding(), "/status_code", json!(text))?])?;
        assert_eq!(parsed.items.first().map(|found| found.status), Some(*expected));
        Ok::<(), Box<dyn Error>>(())
    })?;
    let severities = [
        ("Unknown", Severity::Unknown),
        ("Informational", Severity::Informational),
        ("Low", Severity::Low),
        ("Medium", Severity::Medium),
        ("High", Severity::High),
        ("Critical", Severity::Critical),
        ("Fatal", Severity::Fatal),
        ("Other", Severity::Other),
    ];
    severities.iter().try_for_each(|(text, expected)| {
        let parsed = parse(&[set(cloud_finding(), "/severity", json!(text))?])?;
        assert_eq!(parsed.items.first().map(|found| found.severity), Some(*expected));
        Ok::<(), Box<dyn Error>>(())
    })?;
    let unknown = [
        set(cloud_finding(), "/status_code", json!("WARN"))?,
        set(cloud_finding(), "/status_code", json!("pass"))?,
        set(cloud_finding(), "/severity", json!("critical"))?,
        set(cloud_finding(), "/severity", json!("Severe"))?,
    ];
    let parsed = parse(&unknown)?;
    assert!(parsed.items.is_empty());
    assert_eq!(parsed.skipped.bad_field, unknown.len());
    Ok(())
}


#[test]
fn refused_identities_are_bad_field_whatever_the_field() -> TestResult {
    let long = "a".repeat(OVER_CAP_BYTES);
    let hostile = [
        "bucket\u{3164}a",
        "-bucket",
        "bucкet",
        "",
        " bucket",
        "bucket\n",
        "bucket\u{202e}a",
        long.as_str(),
    ];
    let fields = [
        "/resources/0/uid",
        "/resources/0/type",
        "/metadata/event_code",
        "/cloud/region",
        "/unmapped/provider",
    ];
    fields.iter().try_for_each(|field| {
        hostile.iter().try_for_each(|value| {
            let (kept, skipped) = skipped_of(&[set(cloud_finding(), field, json!(value))?], &Limits::default())?;
            assert_eq!(kept, 0, "{field} {value:?}");
            assert!(only_bad_field(&skipped), "{field} {value:?} {skipped:?}");
            Ok::<(), Box<dyn Error>>(())
        })
    })?;
    Ok(())
}


#[test]
fn a_look_alike_resource_is_refused_and_never_a_second_resource() -> TestResult {
    let real = set(cloud_finding(), "/resources/0/uid", json!("arn:aws:s3:::bucket-a"))?;
    let hangul = set(cloud_finding(), "/resources/0/uid", json!("arn:aws:s3:::bucket-a\u{3164}"))?;
    let cyrillic = set(cloud_finding(), "/resources/0/uid", json!("arn:aws:s3:::buckеt-a"))?;
    let parsed = parse(&[real, hangul, cyrillic])?;
    assert_eq!(parsed.items.len(), 1);
    assert_eq!(parsed.skipped.bad_field, LOOK_ALIKES);
    assert_eq!(
        parsed.items.first().map(|found| found.resource_uid.as_str()),
        Some("arn:aws:s3:::bucket-a")
    );
    Ok(())
}


#[test]
fn missing_required_fields_are_bad_field() -> TestResult {
    let pointers = [
        "/finding_info/uid",
        "/metadata/event_code",
        "/status_code",
        "/severity",
        "/time",
        "/resources",
        "/cloud/region",
        "/cloud/account/uid",
    ];
    pointers.iter().try_for_each(|pointer| {
        let mut finding = cloud_finding();
        let (parent, key) = pointer.rsplit_once('/').ok_or("no slash")?;
        let holder = if parent.is_empty() {
            Some(&mut finding)
        } else {
            finding.pointer_mut(parent)
        };
        holder.and_then(Value::as_object_mut).ok_or("no parent")?.remove(key);
        let (kept, skipped) = skipped_of(&[finding], &Limits::default())?;
        assert_eq!(kept, 0, "{pointer}");
        assert!(only_bad_field(&skipped), "{pointer} {skipped:?}");
        Ok::<(), Box<dyn Error>>(())
    })?;
    let no_resource = set(cloud_finding(), "/resources", json!([]))?;
    assert!(only_bad_field(&skipped_of(&[no_resource], &Limits::default())?.1));
    let no_account = set(cluster_finding(), "/unmapped", json!({ "provider": "kubernetes" }))?;
    assert!(only_bad_field(&skipped_of(&[no_account], &Limits::default())?.1));
    Ok(())
}


#[test]
fn optional_texts_may_be_missing_and_the_first_resource_wins() -> TestResult {
    let mut bare = cloud_finding();
    let info = bare.pointer_mut("/finding_info").and_then(Value::as_object_mut).ok_or("no info")?;
    info.remove("title");
    bare.as_object_mut().ok_or("no object")?.remove("status_detail");
    let with_second = set(
        bare,
        "/resources",
        json!([{ "uid": "first", "type": "T" }, { "uid": "second\u{3164}", "type": "T" }]),
    )?;
    let parsed = parse(&[with_second])?;
    let found = parsed.items.first().ok_or("no finding")?;
    assert_eq!(
        (found.title.as_str(), found.detail.as_str(), found.resource_uid.as_str()),
        ("", "", "first")
    );
    Ok(())
}


#[test]
fn a_foreign_account_is_refused_and_counted_whatever_its_text() -> TestResult {
    let foreign = set(cloud_finding(), "/cloud/account/uid", json!("999999999999"))?;
    let look_alike = set(cloud_finding(), "/cloud/account/uid", json!("123456789012\u{3164}"))?;
    let cluster = set(cluster_finding(), "/unmapped/provider_uid", json!("other-cluster"))?;
    let parsed = parse(&[foreign, look_alike, cluster, cloud_finding()])?;
    assert_eq!(parsed.items.len(), 1);
    assert_eq!(parsed.skipped.foreign_account, FOREIGN);
    assert_eq!(parsed.skipped.bad_field, 0);
    Ok(())
}


#[test]
fn a_repeated_identity_counts_a_duplicate_and_keeps_the_worst_status() -> TestResult {
    let first = cloud_finding();
    let second = set(cloud_finding(), "/status_code", json!("PASS"))?;
    let other_region = set(cloud_finding(), "/cloud/region", json!("eu-west-1"))?;
    let other_resource = set(cloud_finding(), "/resources/0/uid", json!("arn:aws:s3:::other"))?;
    let other_check = set(cloud_finding(), "/metadata/event_code", json!("other_check"))?;
    let parsed = parse(&[first, second, other_region, other_resource, other_check])?;
    assert_eq!(parsed.items.len(), DISTINCT);
    assert_eq!(parsed.skipped.duplicate, 1);
    assert_eq!(parsed.items.first().map(|found| found.status), Some(Status::Fail));
    Ok(())
}


fn with_status(status: &str) -> Result<Value, Box<dyn Error>> {
    set(cloud_finding(), "/status_code", json!(status))
}


#[test]
fn the_same_finding_uid_twice_keeps_the_worst_status_in_either_order() -> TestResult {
    let order = ["FAIL", "MANUAL", "MUTED", "PASS"];
    order.iter().enumerate().try_for_each(|(rank, worse)| {
        order.iter().skip(rank).try_for_each(|better| {
            [(worse, better), (better, worse)].iter().try_for_each(|(one, two)| {
                let parsed = parse(&[with_status(one)?, with_status(two)?])?;
                let kept = parsed.items.first().map(|found| found.status);
                assert_eq!(kept, status_of(worse), "{one} {two}");
                assert_eq!(parsed.items.len(), 1);
                assert_eq!(parsed.skipped.duplicate, 1);
                Ok::<(), Box<dyn Error>>(())
            })
        })
    })
}


fn inline_policy(user_arn: &str, policy: &str, status: &str) -> Result<Value, Box<dyn Error>> {
    let uid = format!("prowler-aws-iam_inline_policy_no_administrative_privileges-{ACCOUNT}-us-east-1-{policy}");
    set(
        set(with_status(status)?, "/resources/0/uid", json!(user_arn))?,
        "/finding_info/uid",
        json!(uid),
    )
}


#[test]
fn a_pass_then_a_fail_on_one_user_arn_keeps_both_findings() -> TestResult {
    let arn = "arn:aws:iam::123456789012:user/alice";
    let parsed = parse(&[inline_policy(arn, "a-readonly", "PASS")?, inline_policy(arn, "z-admin", "FAIL")?])?;
    assert_eq!(
        parsed.items.iter().map(|found| found.status).collect::<Vec<_>>(),
        vec![Status::Pass, Status::Fail]
    );
    assert_eq!(parsed.skipped, Skipped::default());
    Ok(())
}


#[test]
fn two_access_keys_of_one_user_both_failing_are_both_kept() -> TestResult {
    let arn = "arn:aws:iam::123456789012:user/alice";
    let parsed = parse(&[
        inline_policy(arn, "alice-access-key-1", "FAIL")?,
        inline_policy(arn, "alice-access-key-2", "FAIL")?,
    ])?;
    assert_eq!(parsed.items.len(), BOTH);
    assert_eq!(parsed.skipped.duplicate, 0);
    Ok(())
}


#[test]
fn an_empty_or_over_cap_finding_uid_is_bad_field() -> TestResult {
    let over = "u".repeat(MAX_FINDING_UID_BYTES + 1);
    let empty = set(cloud_finding(), "/finding_info/uid", json!(""))?;
    let long = set(cloud_finding(), "/finding_info/uid", json!(over))?;
    let (kept, skipped) = skipped_of(&[empty, long], &Limits::default())?;
    assert_eq!(kept, 0);
    assert_eq!(skipped.bad_field, BOTH);
    Ok(())
}


#[test]
fn many_findings_differing_only_by_uid_are_all_kept() -> TestResult {
    let findings = (0..FLOOD)
        .map(|index| set(cloud_finding(), "/finding_info/uid", json!(format!("u-{index}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let parsed = parse(&findings)?;
    assert_eq!(parsed.items.len(), FLOOD);
    assert_eq!(parsed.skipped, Skipped::default());
    Ok(())
}


#[test]
fn a_literal_escape_in_a_title_is_stored_raw_and_shown_with_its_backslash_escaped() -> TestResult {
    let title = set(cloud_finding(), "/finding_info/title", json!("\\u{1b}[999 bytes cut]"))?;
    let parsed = parse(&[title])?;
    let found = parsed.items.first().ok_or("no finding")?;
    assert_eq!(found.title, "\\u{1b}[999 bytes cut]");
    assert_eq!(shown(&found.title, found.title_cut), "\\u{5c}u{1b}[999 bytes cut]");
    Ok(())
}


#[test]
fn unparsable_findings_are_counted_and_never_fail_the_document() -> TestResult {
    let parsed = parse(&[
        json!(true),
        json!("text"),
        json!([]),
        set(cloud_finding(), "/status_code", json!(false))?,
        cloud_finding(),
    ])?;
    assert_eq!(parsed.items.len(), 1);
    assert_eq!(parsed.skipped.unparsable, UNPARSABLE);
    Ok(())
}


#[test]
fn a_root_object_or_scalar_or_garbage_is_malformed() -> TestResult {
    let inputs: [&[u8]; TOO_MANY] = [br#"{"findings":[]}"#, b"true", b"[", b"[] []"];
    inputs.iter().try_for_each(|input| {
        let refused = parse_prowler_ocsf(*input, TENANT, ACCOUNT, &Limits::default());
        assert!(matches!(refused, Err(ParseError::Malformed { .. })), "{refused:?}");
        Ok::<(), Box<dyn Error>>(())
    })?;
    let message = parse_prowler_ocsf(&b"{}"[..], TENANT, ACCOUNT, &Limits::default())
        .err()
        .ok_or("accepted")?
        .to_string();
    assert!(message.contains("line 1 column"), "{message}");
    Ok(())
}


#[test]
fn the_document_is_bounded_in_bytes_and_in_findings() -> TestResult {
    let small = Limits {
        max_bytes: SMALL_BYTES,
        ..Limits::default()
    };
    let too_large = parse_prowler_ocsf(&b"[                  ]"[..], TENANT, ACCOUNT, &small);
    assert!(matches!(too_large, Err(ParseError::TooLarge { max: SMALL_BYTES })), "{too_large:?}");
    let exact = parse_prowler_ocsf(&b"[        ]"[..], TENANT, ACCOUNT, &small)?;
    assert!(exact.items.is_empty());
    let ceiling = Limits {
        max_bytes: u64::MAX,
        ..Limits::default()
    };
    assert!(parse_prowler_ocsf(&b"[]"[..], TENANT, ACCOUNT, &ceiling)?.items.is_empty());
    assert_eq!(CEILING_MAX_BYTES, GIBIBYTE);
    let few = Limits {
        max_findings: SMALL_CAP,
        ..Limits::default()
    };
    let findings = vec![json!({}); TOO_MANY];
    let refused = parse_with(&findings, ACCOUNT, &few);
    assert!(refused.is_err());
    let message = refused.err().ok_or("accepted")?.to_string();
    assert!(message.contains("4 findings, above the 3 limit"), "{message}");
    assert_eq!(
        parse_with(findings.get(..SMALL_CAP).ok_or("short")?, ACCOUNT, &few)?.skipped.bad_field,
        SMALL_CAP
    );
    Ok(())
}


#[test]
fn an_invalid_tenant_account_or_a_failing_reader_is_an_error_before_any_parse() -> TestResult {
    let tenant = parse_prowler_ocsf(&b"[]"[..], "-lab", ACCOUNT, &Limits::default());
    assert!(matches!(tenant, Err(ParseError::Tenant(_))), "{tenant:?}");
    let accounts = ["", "-x", "a\u{3164}", "a b"];
    accounts.iter().try_for_each(|account| {
        let refused = parse_prowler_ocsf(&b"[]"[..], TENANT, account, &Limits::default());
        assert!(matches!(refused, Err(ParseError::Account)), "{account:?} {refused:?}");
        Ok::<(), Box<dyn Error>>(())
    })?;
    let broken = parse_prowler_ocsf(FailingReader, TENANT, ACCOUNT, &Limits::default());
    assert!(matches!(broken, Err(ParseError::Read(_))), "{broken:?}");
    Ok(())
}


#[test]
fn a_finding_with_ten_thousand_resources_is_refused_alone() -> TestResult {
    let flood = set(cloud_finding(), "/resources", json!(vec![json!({ "uid": "r", "type": "T" }); FLOOD]))?;
    let parsed = parse(&[cloud_finding(), flood])?;
    assert_eq!(parsed.items.len(), 1);
    assert!(only_bad_field(&parsed.skipped));
    Ok(())
}


fn over_cap(count: usize) -> Vec<Value> {
    vec![json!("x"); count]
}


fn over_cap_map(count: usize) -> Value {
    Value::Object((0..count).map(|index| (format!("k{index}"), json!(1))).collect())
}


#[test]
fn every_collection_at_every_level_is_refused_one_over_its_cap_and_kept_at_it() -> TestResult {
    let limits = Limits {
        max_resources: SMALL_CAP,
        max_labels: SMALL_CAP,
        max_unmapped: UNMAPPED_CAP,
        max_list: SMALL_CAP,
        max_frameworks: SMALL_CAP,
        max_requirements: SMALL_CAP,
        ..Limits::default()
    };
    let resources = |count: usize| set(cloud_finding(), "/resources", json!(vec![json!({ "uid": "r", "type": "T" }); count]));
    let labels = |count: usize| set(cloud_finding(), "/resources/0/labels", json!(over_cap(count)));
    let types = |count: usize| set(cloud_finding(), "/finding_info/types", json!(over_cap(count)));
    let unmapped = |count: usize| {
        let mut map = over_cap_map(count - FIXED_KEYS);
        map.as_object_mut().ok_or("no map")?.insert("provider".to_owned(), json!("aws"));
        map.as_object_mut().ok_or("no map")?.insert("provider_uid".to_owned(), json!(ACCOUNT));
        set(cloud_finding(), "/unmapped", map)
    };
    let lists = ["categories", "depends_on", "related_to", "additional_urls"];
    let frameworks = |count: usize| {
        let map: serde_json::Map<String, Value> = (0..count).map(|index| (format!("f{index}"), json!(["r"]))).collect();
        set(cloud_finding(), "/unmapped/compliance", Value::Object(map))
    };
    let requirements = |count: usize| set(cloud_finding(), "/unmapped/compliance", json!({ "CIS": over_cap(count) }));
    let check = |at_cap: Value, over: Value, label: &str| -> TestResult {
        let (kept, skipped) = skipped_of(&[at_cap], &limits)?;
        assert_eq!((kept, &skipped), (1, &Skipped::default()), "{label} at the cap");
        let (kept_over, skipped_over) = skipped_of(&[over, cloud_finding()], &limits)?;
        assert_eq!(kept_over, 1, "{label} over the cap");
        assert!(only_bad_field(&skipped_over), "{label} {skipped_over:?}");
        Ok(())
    };
    check(resources(SMALL_CAP)?, resources(TOO_MANY)?, "resources")?;
    check(labels(SMALL_CAP)?, labels(TOO_MANY)?, "labels")?;
    check(types(SMALL_CAP)?, types(TOO_MANY)?, "types")?;
    check(unmapped(UNMAPPED_CAP)?, unmapped(UNMAPPED_CAP + 1)?, "unmapped")?;
    lists.iter().try_for_each(|list| {
        let pointer = format!("/unmapped/{list}");
        check(
            set(cloud_finding(), &pointer, json!(over_cap(SMALL_CAP)))?,
            set(cloud_finding(), &pointer, json!(over_cap(TOO_MANY)))?,
            list,
        )
    })?;
    check(frameworks(SMALL_CAP)?, frameworks(TOO_MANY)?, "frameworks")?;
    check(requirements(SMALL_CAP)?, requirements(TOO_MANY)?, "requirements")?;
    Ok(())
}


#[test]
fn collections_of_the_wrong_shape_are_unparsable() -> TestResult {
    let shapes = [
        set(cloud_finding(), "/resources", json!({ "a": 1 }))?,
        set(cloud_finding(), "/unmapped", json!([1]))?,
        set(cloud_finding(), "/unmapped/compliance", json!([1]))?,
        set(cloud_finding(), "/unmapped/compliance", json!({ "CIS": "x" }))?,
        set(cloud_finding(), "/resources/0/labels", json!({ "a": 1 }))?,
        set(cloud_finding(), "/finding_info/types", json!("x"))?,
    ];
    let parsed = parse(&shapes)?;
    assert!(parsed.items.is_empty());
    assert_eq!(parsed.skipped.unparsable, shapes.len());
    Ok(())
}


#[test]
fn a_time_outside_the_rfc_3339_years_is_refused() -> TestResult {
    let accepted = [YEAR_0_START, YEAR_9999_END, 0];
    accepted.iter().try_for_each(|seconds| {
        assert_eq!(checked_time(Some(*seconds)).ok(), Some(*seconds));
        Ok::<(), Box<dyn Error>>(())
    })?;
    let refused = [YEAR_10000, YEAR_MINUS_1, i64::MAX, i64::MIN];
    refused.iter().try_for_each(|seconds| {
        let parsed = parse(&[set(cloud_finding(), "/time", json!(seconds))?])?;
        assert!(parsed.items.is_empty(), "{seconds}");
        assert_eq!(parsed.skipped.bad_field, 1, "{seconds}");
        Ok::<(), Box<dyn Error>>(())
    })?;
    assert!(checked_time(None).is_err());
    Ok(())
}


#[test]
fn hostile_display_texts_are_stored_escaped_and_the_cut_is_visible() -> TestResult {
    let escape = "scan \u{1b}]0;evil\u{7}done\n\u{202e}";
    let huge = "T".repeat(MEBIBYTE);
    let finding = set(set(cloud_finding(), "/status_detail", json!(escape))?, "/finding_info/title", json!(huge))?;
    let parsed = parse(&[finding])?;
    let found = parsed.items.first().ok_or("no finding")?;
    assert_eq!(found.detail, escape);
    assert_eq!(shown(&found.detail, found.detail_cut), "scan \\u{1b}]0;evil\\u{7}done\\u{a}\\u{202e}");
    assert!(!shown(&found.detail, found.detail_cut).chars().any(|next| next.is_control()));
    assert_eq!((found.title.len(), found.title_cut), (TEXT_CAP, MEBIBYTE - TEXT_CAP));
    assert!(shown(&found.title, found.title_cut).ends_with("\\[1047552 bytes cut]"));
    let emoji = set(cloud_finding(), "/finding_info/title", json!("\u{1f600}".repeat(MEBIBYTE / EMOJI_BYTES)))?;
    let parsed_emoji = parse(&[emoji])?;
    let kept = parsed_emoji.items.first().ok_or("no emoji finding")?;
    assert_eq!((kept.title.len(), kept.title.chars().all(|next| next == '\u{1f600}')), (TEXT_CAP, true));
    assert_eq!(kept.title_cut, MEBIBYTE - TEXT_CAP);
    let uid = set(cloud_finding(), "/finding_info/uid", json!("a\u{3164}b\u{1b}c"))?;
    assert_eq!(
        parse(&[uid])?.items.first().map(|other| other.uid.clone()),
        Some("a\u{3164}b\u{1b}c".to_owned())
    );
    Ok(())
}


#[test]
fn the_stored_finding_uid_is_raw_and_shown_escaped_on_demand() -> TestResult {
    let uid = set(cloud_finding(), "/finding_info/uid", json!("a\\u{1b}"))?;
    let parsed = parse(&[uid])?;
    let found = parsed.items.first().ok_or("no finding")?;
    assert_eq!(found.uid, "a\\u{1b}");
    assert_eq!(escaped_whole(&found.uid), "a\\u{5c}u{1b}");
    Ok(())
}


#[test]
fn a_resource_uid_or_type_with_single_inner_spaces_is_kept_and_other_spacing_is_refused() -> TestResult {
    let azure = set(
        set(cloud_finding(), "/resources/0/uid", json!("Conditional Access Policy"))?,
        "/resources/0/type",
        json!("Policy Type"),
    )?;
    let parsed = parse(&[azure])?;
    assert_eq!(parsed.items.len(), 1);
    assert_eq!(parsed.skipped, Skipped::default());
    ["Conditional  Access", " Conditional", "Conditional ", " ", "a -b"]
        .iter()
        .try_for_each(|uid| {
            let (kept, skipped) = skipped_of(&[set(cloud_finding(), "/resources/0/uid", json!(uid))?], &Limits::default())?;
            assert_eq!(kept, 0, "{uid:?}");
            assert!(only_bad_field(&skipped), "{uid:?}");
            Ok::<(), Box<dyn Error>>(())
        })?;
    let (kept, _skipped) = skipped_of(
        &[
            set(cloud_finding(), "/metadata/event_code", json!("a b"))?,
            set(cloud_finding(), "/cloud/region", json!("a b"))?,
        ],
        &Limits::default(),
    )?;
    assert_eq!(kept, 0);
    Ok(())
}


#[test]
fn markup_in_a_subject_is_refused_and_its_fail_is_counted_by_status() -> TestResult {
    let svg = set(cloud_finding(), "/resources/0/uid", json!("User/<svg/onload=alert(1)>"))?;
    let manual = set(set(cloud_finding(), "/resources/0/uid", json!("a<b"))?, "/status_code", json!("MANUAL"))?;
    let unknown_status = set(set(cloud_finding(), "/resources/0/uid", json!("a<b"))?, "/status_code", json!("WEIRD"))?;
    let no_status = set(set(cloud_finding(), "/resources/0/uid", json!("a<b"))?, "/status_code", json!(null))?;
    let unparsable = json!({ "status_code": true });
    let parsed = parse(&[svg, manual, unknown_status, no_status, unparsable, cloud_finding()])?;
    assert_eq!(parsed.items.len(), 1);
    assert_eq!(parsed.skipped.bad_field, REFUSED_FIELDS);
    assert_eq!(parsed.skipped.unparsable, 1);
    assert_eq!(parsed.skipped.refused_by_status.get(&Status::Fail), Some(&1));
    assert_eq!(parsed.skipped.refused_by_status.get(&Status::Manual), Some(&1));
    assert_eq!(parsed.skipped.refused_by_status.len(), BOTH);
    Ok(())
}


#[test]
fn the_aws_iam_fixture_keeps_the_fail_behind_the_pass_of_one_user() -> TestResult {
    let parsed = parse_prowler_ocsf(
        std::fs::File::open("tests/fixtures/prowler-aws-iam-inline.json")?,
        TENANT,
        ACCOUNT,
        &Limits::default(),
    )?;
    assert_eq!(
        parsed.items.iter().map(|found| found.status).collect::<Vec<_>>(),
        vec![Status::Pass, Status::Fail]
    );
    assert_eq!(parsed.skipped, Skipped::default());
    Ok(())
}
