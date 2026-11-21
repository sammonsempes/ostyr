#[path = "common/types.rs"]
mod types;


use cloud_posture::error::StoreError;
use cloud_posture::model::{Admitted, Finding, Findings, Severity, Skipped, Status};
use cloud_posture::prowler::identity_of;
use cloud_posture::store::{
    admit, admit_all, check_run, check_size, document_of, finding_doc, finding_fits, parse_answer, replace_run, replace_run_limited, stats_doc,
    MAX_FINDINGS_PER_TENANT, MAX_RUN_DOC_BYTES, MAX_RUN_ID_BYTES, MAX_STORED_TEXT_BYTES, MAX_TIME_UNIX, MIGRATIONS, MIGRATION_NAMESPACE,
    MIN_TIME_UNIX, PROVIDER_PATTERN, REFERENCE_PATTERN, REFUSE_SQL, REPLACE_SQL, SPACED_PATTERN, STORE_DEADLINE,
};
use cloud_posture::text::{
    severity_of, severity_rank, severity_text, status_of, status_text, valid_provider, valid_reference, valid_spaced_reference, MAX_ACCOUNT_BYTES,
    MAX_CHECK_ID_BYTES, MAX_FINDING_UID_BYTES, MAX_PROVIDER_BYTES, MAX_REGION_BYTES, MAX_RESOURCE_TYPE_BYTES, MAX_RESOURCE_UID_BYTES,
};
use cloud_posture::types::RowFuture;
use core_pg::error::PgError;
use core_pg::migrate::{check_embedded, check_namespace};
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use regex::Regex;
use serde_json::Value;
use std::future::ready;
use std::sync::Mutex;
use types::TestResult;


#[derive(Clone)]
pub struct Call {
    pub tenant: String,
    pub sql: &'static str,
    pub params: Vec<String>,
}


pub struct Weakening {
    pub name: &'static str,
    pub apply: fn(&mut Finding),
}


const NOW: u64 = 1_700_000_000_000_000;


const TWO: usize = 2;


const THREE: usize = 3;


const FOUR: usize = 4;


const FIVE: usize = 5;


const SIX: usize = 6;


const SEVEN: usize = 7;


const OTHERS_AT_CAP: usize = 150_001;


const CAP: usize = 200_000;


const GIANT_RUN: usize = 26_000;


const STATS_PARAM: usize = 4;


const DOC_PARAM: usize = 2;


const FINISHED_PARAM: usize = 3;


const PARAM_COUNT: usize = 6;


const SHA256_HEX: usize = 64;


const INDEX_ROOM: usize = 16;


const MIN_DEADLINE_SECONDS: u64 = 120;


pub struct Double {
    pub calls: Mutex<Vec<Call>>,
    pub reply: Vec<Vec<String>>,
    pub fail: bool,
}


fn double(reply: Vec<Vec<String>>) -> Double {
    Double {
        calls: Mutex::new(Vec::new()),
        reply,
        fail: false,
    }
}


fn executor<'a>(fake: &'a Double) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> {
        let answer = if fake.fail {
            Err(PgError::InvalidTenant)
        } else {
            match fake.calls.lock() {
                Ok(mut calls) => {
                    calls.push(Call {
                        tenant: tenant_of(&scope).to_owned(),
                        sql,
                        params,
                    });
                    Ok(fake.reply.clone())
                }
                Err(_poisoned) => Err(PgError::InvalidTenant),
            }
        };
        Box::pin(ready(answer))
    }
}


fn calls_of(fake: &Double) -> Result<Vec<Call>, Box<dyn std::error::Error>> {
    Ok(fake.calls.lock().map_err(|_poisoned| "poisoned")?.clone())
}


fn stored_reply(written: &str) -> Vec<Vec<String>> {
    vec![vec!["stored".to_owned(), "0".to_owned(), written.to_owned()]]
}


fn finding(account: &str, uid: &str, resource_uid: &str, status: Status) -> Finding {
    Finding {
        uid: uid.to_owned(),
        check_id: "check_one".to_owned(),
        status,
        severity: Severity::High,
        provider: "aws".to_owned(),
        account: account.to_owned(),
        region: "eu-west-1".to_owned(),
        resource_uid: resource_uid.to_owned(),
        resource_type: "AwsResource".to_owned(),
        time_unix: 1,
        title: "title".to_owned(),
        title_cut: 0,
        detail: "detail".to_owned(),
        detail_cut: 0,
    }
}


fn run_of(tenant: &str, account: &str, items: Vec<Finding>) -> Result<Findings, Box<dyn std::error::Error>> {
    Ok(Findings {
        tenant: tenant_scope(tenant)?,
        account: account.to_owned(),
        items,
        skipped: Skipped::default(),
    })
}


fn param(call: &Call, index: usize) -> Result<&str, Box<dyn std::error::Error>> {
    Ok(call.params.get(index).ok_or("missing parameter")?.as_str())
}


fn only_call(fake: &Double) -> Result<Call, Box<dyn std::error::Error>> {
    let calls = calls_of(fake)?;
    assert_eq!(calls.len(), 1);
    Ok(calls.first().ok_or("no call")?.clone())
}


#[test]
fn migration_is_well_formed_and_pins_the_function() -> TestResult {
    check_namespace(MIGRATION_NAMESPACE)?;
    check_embedded(&MIGRATIONS)?;
    let sql = MIGRATIONS.first().ok_or("no migration")?.sql;
    assert!(sql.contains("PRIMARY KEY (tenant, account, identity)"));
    assert!(sql.contains("CHECK (octet_length(identity) = 32)"));
    assert!(sql.contains("CREATE INDEX cloud_posture_findings_page ON cloud_posture_findings (tenant, account, severity_rank DESC, identity);"));
    assert!(sql.contains("PRIMARY KEY (tenant, account),"));
    assert!(sql.contains("pg_advisory_xact_lock(hashtextextended('cloud_posture/' || tenant_name, 0))"));
    assert!(!sql.contains("hashtext(tenant_name)"));
    assert!(sql.contains("SET search_path = pg_catalog, public, pg_temp SET enable_seqscan = off SET enable_bitmapscan = off SET jit = off AS $$"));
    assert!(sql.contains("current_setting('server_encoding') <> 'UTF8'"));
    assert!(sql.contains("('Fatal', 7), ('Critical', 6), ('High', 5), ('Medium', 4), ('Low', 3), ('Informational', 2), ('Other', 1), ('Unknown', 0)"));
    assert!(sql.contains("CHECK (time_unix BETWEEN -62167219200 AND 253402300799)"));
    assert!(sql.contains("DELETE FROM cloud_posture_findings f WHERE f.tenant = tenant_name AND f.account = account_name;"));
    assert!(sql.contains("INTO other_findings FROM cloud_posture_findings f WHERE f.tenant = tenant_name AND f.account <> account_name;"));
    assert!(sql.contains("INTO other_runs FROM cloud_posture_runs r WHERE r.tenant = tenant_name AND r.account <> account_name;"));
    assert!(sql.contains("others := other_findings + other_runs;"));
    assert!(sql.contains("others + incoming + 1 > max_total"));
    assert!(sql.contains("posture_replace_run"));
    assert!(REPLACE_SQL.contains("posture_replace_run($1, $2, $3, $4::text::jsonb, $5::text::bigint, $6::text::jsonb, $7::text::bigint)"));
    [
        ("account", REFERENCE_PATTERN, MAX_ACCOUNT_BYTES),
        ("check_id", REFERENCE_PATTERN, MAX_CHECK_ID_BYTES),
        ("region", REFERENCE_PATTERN, MAX_REGION_BYTES),
        ("run_id", REFERENCE_PATTERN, MAX_RUN_ID_BYTES),
        ("resource_uid", SPACED_PATTERN, MAX_RESOURCE_UID_BYTES),
        ("resource_type", SPACED_PATTERN, MAX_RESOURCE_TYPE_BYTES),
        ("provider", PROVIDER_PATTERN, MAX_PROVIDER_BYTES),
    ]
    .iter()
    .try_for_each(|(column, pattern, cap)| {
        let line = format!("CHECK ({column} ~ '{pattern}' AND octet_length({column}) <= {cap} AND octet_length({column}) = char_length({column}))");
        if sql.contains(&line) {
            Ok(())
        } else {
            Err(format!("missing check: {line}"))
        }
    })?;
    Ok(())
}


fn edge_inputs() -> Vec<String> {
    let mut inputs: Vec<String> = [
        "a",
        "-a",
        "a-",
        "",
        "\u{ff21}",
        "a\u{3164}b",
        "a\u{1b}b",
        "abc\n",
        "a b",
        "Conditional Access Policy",
        "a -b",
        "a  b",
        "a ",
        " a",
        "a\tb",
        "<x>",
        "arn:aws:iam::1:root",
        "Group/Domain Admins",
        "x$#()*+,=@",
        "aws_2",
        "Aws",
    ]
    .iter()
    .map(|text| (*text).to_owned())
    .collect();
    [
        MAX_PROVIDER_BYTES,
        MAX_CHECK_ID_BYTES,
        MAX_RESOURCE_TYPE_BYTES,
        MAX_RESOURCE_UID_BYTES,
        MAX_ACCOUNT_BYTES,
    ]
    .iter()
    .for_each(|cap| {
        inputs.push("a".repeat(*cap));
        inputs.push("a".repeat(*cap + 1));
    });
    inputs
}


#[test]
fn every_check_regex_agrees_with_the_rust_grammar_on_edge_inputs() -> TestResult {
    let reference = Regex::new(REFERENCE_PATTERN)?;
    let spaced = Regex::new(SPACED_PATTERN)?;
    let provider = Regex::new(PROVIDER_PATTERN)?;
    edge_inputs().iter().try_for_each(|input| {
        [MAX_CHECK_ID_BYTES, MAX_ACCOUNT_BYTES, MAX_RUN_ID_BYTES].iter().try_for_each(|cap| {
            let sql_side = reference.is_match(input) && input.len() <= *cap;
            if sql_side == valid_reference(input, *cap) {
                Ok(())
            } else {
                Err(format!("reference grammar differs on {input:?} cap {cap}"))
            }
        })?;
        [MAX_RESOURCE_UID_BYTES, MAX_RESOURCE_TYPE_BYTES].iter().try_for_each(|cap| {
            let sql_side = spaced.is_match(input) && input.len() <= *cap;
            if sql_side == valid_spaced_reference(input, *cap) {
                Ok(())
            } else {
                Err(format!("spaced grammar differs on {input:?} cap {cap}"))
            }
        })?;
        let sql_side = provider.is_match(input) && input.len() <= MAX_PROVIDER_BYTES;
        if sql_side == valid_provider(input) {
            Ok(())
        } else {
            Err(format!("provider grammar differs on {input:?}"))
        }
    })?;
    assert!(!reference.is_match("abc\n"));
    assert!(!reference.is_match("-a"));
    assert!(!spaced.is_match("a -b"));
    Ok(())
}


#[test]
fn text_maps_are_the_inverse_of_the_parser_and_the_rank_is_explicit() -> TestResult {
    [Status::Pass, Status::Fail, Status::Manual, Status::Muted]
        .iter()
        .for_each(|status| assert_eq!(status_of(status_text(*status)), Some(*status)));
    let ranked = [
        (Severity::Fatal, SEVEN),
        (Severity::Critical, SIX),
        (Severity::High, FIVE),
        (Severity::Medium, FOUR),
        (Severity::Low, THREE),
        (Severity::Informational, TWO),
        (Severity::Other, 1),
        (Severity::Unknown, 0),
    ];
    ranked.iter().for_each(|(severity, rank)| {
        assert_eq!(severity_of(severity_text(*severity)), Some(*severity));
        assert_eq!(usize::from(severity_rank(*severity)), *rank);
    });
    Ok(())
}


fn weakened() -> Vec<Weakening> {
    vec![
        Weakening {
            name: "account",
            apply: |item| item.account = "other".to_owned(),
        },
        Weakening {
            name: "check id",
            apply: |item| item.check_id = "-bad".to_owned(),
        },
        Weakening {
            name: "provider",
            apply: |item| item.provider = "AWS".to_owned(),
        },
        Weakening {
            name: "region",
            apply: |item| item.region = "eu west".to_owned(),
        },
        Weakening {
            name: "resource uid",
            apply: |item| item.resource_uid = "a  b".to_owned(),
        },
        Weakening {
            name: "resource type",
            apply: |item| item.resource_type = "<x>".to_owned(),
        },
        Weakening {
            name: "empty uid",
            apply: |item| item.uid = String::new(),
        },
        Weakening {
            name: "long uid",
            apply: |item| item.uid = "u".repeat(MAX_FINDING_UID_BYTES + 1),
        },
        Weakening {
            name: "uid NUL",
            apply: |item| item.uid = "a\0b".to_owned(),
        },
        Weakening {
            name: "title NUL",
            apply: |item| item.title = "a\0b".to_owned(),
        },
        Weakening {
            name: "detail NUL",
            apply: |item| item.detail = "a\0b".to_owned(),
        },
        Weakening {
            name: "long title",
            apply: |item| item.title = "t".repeat(MAX_STORED_TEXT_BYTES + 1),
        },
        Weakening {
            name: "long detail",
            apply: |item| item.detail = "d".repeat(MAX_STORED_TEXT_BYTES + 1),
        },
        Weakening {
            name: "time below",
            apply: |item| item.time_unix = MIN_TIME_UNIX - 1,
        },
        Weakening {
            name: "time above",
            apply: |item| item.time_unix = MAX_TIME_UNIX + 1,
        },
        Weakening {
            name: "title cut",
            apply: |item| item.title_cut = usize::MAX,
        },
        Weakening {
            name: "detail cut",
            apply: |item| item.detail_cut = usize::MAX,
        },
    ]
}


#[test]
fn a_finding_that_does_not_fit_is_refused_alone() -> TestResult {
    let good = finding("acc", "uid", "res", Status::Fail);
    assert!(finding_fits(&good, "acc"));
    let edges = Finding {
        uid: "u".repeat(MAX_FINDING_UID_BYTES),
        title: "t".repeat(MAX_STORED_TEXT_BYTES),
        detail: "d".repeat(MAX_STORED_TEXT_BYTES),
        time_unix: MIN_TIME_UNIX,
        ..good.clone()
    };
    assert!(finding_fits(&edges, "acc"));
    assert!(finding_fits(
        &Finding {
            time_unix: MAX_TIME_UNIX,
            ..good.clone()
        },
        "acc"
    ));
    weakened().iter().for_each(|weakening| {
        let mut item = good.clone();
        (weakening.apply)(&mut item);
        assert!(!finding_fits(&item, "acc"), "{} must be refused", weakening.name);
    });
    Ok(())
}


#[test]
fn identity_keeps_two_findings_of_one_uid_and_merges_a_true_repeat_keeping_the_worst() -> TestResult {
    let items = vec![
        finding("acc", "same", "res-one", Status::Pass),
        finding("acc", "same", "res-two", Status::Pass),
        finding("acc", "same", "res-one", Status::Fail),
        finding("acc", "same", "res-two", Status::Manual),
        finding("acc", "same", "res-two", Status::Pass),
    ];
    let admitted = admit_all("acc", &items);
    assert_eq!(admitted.kept.len(), TWO);
    assert_eq!(admitted.duplicate, THREE);
    assert_eq!(
        admitted.kept.iter().map(|item| item.status).collect::<Vec<_>>(),
        vec![Status::Fail, Status::Manual]
    );
    assert_ne!(identity_of(items.first().ok_or("no item")?), identity_of(items.get(1).ok_or("no item")?));
    Ok(())
}


#[test]
fn a_refused_finding_is_counted_by_status() -> TestResult {
    let foreign = finding("other", "uid", "res", Status::Muted);
    let nul = Finding {
        detail: "x\0".to_owned(),
        ..finding("acc", "uid", "res", Status::Fail)
    };
    let mut admitted = Admitted::default();
    admit(&mut admitted, "acc", &foreign);
    admit(&mut admitted, "acc", &nul);
    admit(&mut admitted, "acc", &nul);
    assert!(admitted.kept.is_empty());
    assert_eq!(admitted.refused.get(&Status::Muted), Some(&1));
    assert_eq!(admitted.refused.get(&Status::Fail), Some(&TWO));
    let counters = stats_doc(&Skipped::default(), &admitted);
    assert_eq!(counters.get("store_refused"), Some(&Value::from(THREE)));
    Ok(())
}


#[test]
fn the_document_is_an_array_the_identity_is_recomputed_and_the_limit_is_exact() -> TestResult {
    assert_eq!(document_of(&[], TWO)?, "[]");
    let item = finding("acc", "uid", "res", Status::Fail);
    let document = document_of(&[&item, &item], MAX_RUN_DOC_BYTES)?;
    let parsed: Value = serde_json::from_str(&document)?;
    let rows = parsed.as_array().ok_or("not an array")?;
    assert_eq!(rows.len(), TWO);
    let doc = finding_doc(&item);
    assert_eq!(
        doc.get("identity").and_then(Value::as_str),
        Some(format!("{:x}", identity_of(&item)).as_str())
    );
    assert_eq!(doc.get("identity").and_then(Value::as_str).map(str::len), Some(SHA256_HEX));
    assert_eq!(doc.get("severity_rank"), Some(&Value::from(FIVE)));
    assert_eq!(doc.get("status"), Some(&Value::from("FAIL")));
    let one = finding_doc(&item).to_string();
    assert!(document_of(&[&item], one.len() + TWO).is_ok());
    assert!(matches!(document_of(&[&item], one.len() + 1), Err(StoreError::RunTooLarge { .. })));
    assert!(matches!(
        document_of(&[&item, &item], one.len() * TWO),
        Err(StoreError::RunTooLarge { .. })
    ));
    Ok(())
}


#[tokio::test]
async fn checks_before_any_io_refuse_tenant_account_run_id_and_size() -> TestResult {
    let scope = tenant_scope("a")?;
    let fake = double(stored_reply("0"));
    let exec = executor(&fake);
    let one = vec![finding("acc", "uid", "res", Status::Fail)];
    let foreign = run_of("b", "acc", one.clone())?;
    assert!(matches!(
        refused(replace_run(&exec, &scope, &foreign, "run", NOW).await)?,
        StoreError::TenantMismatch
    ));
    let bad_account = run_of("a", "-acc", one.clone())?;
    assert!(matches!(
        refused(replace_run(&exec, &scope, &bad_account, "run", NOW).await)?,
        StoreError::BadAccount
    ));
    let good = run_of("a", "acc", one.clone())?;
    assert!(matches!(
        refused(replace_run(&exec, &scope, &good, "-run", NOW).await)?,
        StoreError::BadRunId
    ));
    let long_run = "r".repeat(MAX_RUN_ID_BYTES + 1);
    assert!(matches!(
        refused(replace_run(&exec, &scope, &good, &long_run, NOW).await)?,
        StoreError::BadRunId
    ));
    assert!(matches!(
        refused(replace_run(&exec, &scope, &good, "run", u64::MAX).await)?,
        StoreError::BadTime
    ));
    assert!(check_run(&scope, &good, "run").is_ok());
    assert!(check_size(&good).is_ok());
    assert!(calls_of(&fake)?.is_empty());
    Ok(())
}


fn refused<Value: std::fmt::Debug>(result: Result<Value, StoreError>) -> Result<StoreError, Box<dyn std::error::Error>> {
    match result {
        Err(error) => Ok(error),
        Ok(value) => Err(format!("expected a refusal, got {value:?}").into()),
    }
}


#[tokio::test]
async fn a_run_is_sent_once_under_the_scope_with_the_recomputed_identity_and_the_counters() -> TestResult {
    let scope = tenant_scope("a")?;
    let fake = double(stored_reply("2"));
    let exec = executor(&fake);
    let mut found = run_of(
        "a",
        "acc",
        vec![
            finding("acc", "u1", "res-1", Status::Fail),
            finding("acc", "u2", "res-2", Status::Pass),
            finding("acc", "u3", "res-3", Status::Fail),
            Finding {
                detail: "bad\0detail".to_owned(),
                ..finding("acc", "u4", "res-4", Status::Fail)
            },
            finding("other", "u5", "res-5", Status::Muted),
            finding("acc", "u1", "res-1", Status::Pass),
        ],
    )?;
    found.skipped.unparsable = 1;
    found.skipped.bad_field = TWO;
    found.skipped.foreign_account = THREE;
    found.skipped.refused_by_status.insert(Status::Fail, 1);
    found.skipped.refused_by_status.insert(Status::Manual, 1);
    let outcome = replace_run(&exec, &scope, &found, "run-1", NOW).await?;
    assert_eq!((outcome.stored, outcome.store_refused, outcome.duplicate), (TWO, TWO, 1));
    let call = only_call(&fake)?;
    assert_eq!(call.tenant, "a");
    assert_eq!(call.sql, REPLACE_SQL);
    assert_eq!(call.params.len(), PARAM_COUNT);
    assert_eq!(param(&call, 0)?, "acc");
    assert_eq!(param(&call, 1)?, "run-1");
    assert_eq!(param(&call, FINISHED_PARAM)?, NOW.to_string());
    assert_eq!(param(&call, PARAM_COUNT - 1)?, MAX_FINDINGS_PER_TENANT.to_string());
    let rows: Value = serde_json::from_str(param(&call, DOC_PARAM)?)?;
    let items = rows.as_array().ok_or("not an array")?;
    assert_eq!(items.len(), THREE);
    let first = items.first().ok_or("no row")?;
    let expected = format!("{:x}", identity_of(found.items.first().ok_or("no item")?));
    assert_eq!(first.get("identity").and_then(Value::as_str), Some(expected.as_str()));
    assert_eq!(first.get("status"), Some(&Value::from("FAIL")));
    assert!(!param(&call, DOC_PARAM)?.contains("bad"));
    let stats: Value = serde_json::from_str(param(&call, STATS_PARAM)?)?;
    let keys = [
        "unparsable",
        "bad_field",
        "duplicate",
        "foreign_account",
        "refused_pass",
        "refused_muted",
        "refused_manual",
        "refused_fail",
        "store_refused",
    ];
    let counts = keys.map(|key| stats.get(key).and_then(Value::as_u64).and_then(|number| usize::try_from(number).ok()));
    assert_eq!(
        counts,
        [Some(1), Some(TWO), Some(1), Some(THREE), Some(0), Some(1), Some(1), Some(TWO), Some(TWO)]
    );
    Ok(())
}


#[tokio::test]
async fn a_clean_run_reports_no_refusal() -> TestResult {
    let scope = tenant_scope("a")?;
    let fake = double(stored_reply("1"));
    let exec = executor(&fake);
    let found = run_of("a", "acc", vec![finding("acc", "u1", "res-1", Status::Fail)])?;
    let outcome = replace_run(&exec, &scope, &found, "run", NOW).await?;
    assert_eq!((outcome.stored, outcome.store_refused, outcome.duplicate), (1, 0, 0));
    Ok(())
}


#[tokio::test]
async fn the_cap_refusal_is_an_error_with_the_counts() -> TestResult {
    let scope = tenant_scope("a")?;
    let fake = double(vec![vec!["refused_cap".to_owned(), "150001".to_owned(), "0".to_owned()]]);
    let exec = executor(&fake);
    let found = run_of("a", "acc", vec![finding("acc", "u1", "res-1", Status::Fail)])?;
    let error = refused(replace_run(&exec, &scope, &found, "run", NOW).await)?;
    assert!(matches!(
        error,
        StoreError::TenantCap {
            cap: MAX_FINDINGS_PER_TENANT,
            items: 1,
            others: OTHERS_AT_CAP
        }
    ));
    assert!(error.to_string().contains("150001"));
    Ok(())
}


#[tokio::test]
async fn a_failing_store_and_bad_answers_are_errors() -> TestResult {
    let scope = tenant_scope("a")?;
    let found = run_of("a", "acc", Vec::new())?;
    let failing = Double {
        fail: true,
        ..double(Vec::new())
    };
    let exec = executor(&failing);
    assert!(matches!(
        refused(replace_run(&exec, &scope, &found, "run", NOW).await)?,
        StoreError::Pg(_)
    ));
    let answers: Vec<Vec<Vec<String>>> = vec![
        Vec::new(),
        vec![vec!["stored".to_owned()]],
        vec![vec!["other".to_owned(), "0".to_owned(), "0".to_owned()]],
        vec![vec!["stored".to_owned(), "x".to_owned(), "0".to_owned()]],
        vec![vec!["stored".to_owned(), "0".to_owned(), "x".to_owned()]],
    ];
    answers.iter().try_for_each(|answer| {
        assert!(matches!(parse_answer(answer), Err(StoreError::BadAnswer)));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert_eq!(parse_answer(&stored_reply("4"))?, (true, 0, FOUR));
    Ok(())
}


#[tokio::test]
async fn a_run_too_large_to_send_writes_only_the_refusal_marker() -> TestResult {
    let scope = tenant_scope("a")?;
    let fake = double(stored_reply("0"));
    let exec = executor(&fake);
    let found = run_of("a", "acc", vec![finding("acc", "u1", "res-1", Status::Fail)])?;
    assert!(matches!(
        refused(replace_run_limited(&exec, &scope, &found, "run", NOW, 1).await)?,
        StoreError::RunTooLarge { .. }
    ));
    let big: Vec<Finding> = (0..GIANT_RUN)
        .map(|index| Finding {
            uid: format!("{index}{}", "u".repeat(MAX_FINDING_UID_BYTES - INDEX_ROOM)),
            title: "t".repeat(MAX_STORED_TEXT_BYTES),
            detail: "d".repeat(MAX_STORED_TEXT_BYTES),
            resource_uid: format!("res{index}{}", "r".repeat(MAX_RESOURCE_UID_BYTES - INDEX_ROOM)),
            ..finding("acc", "u", "r", Status::Fail)
        })
        .collect();
    let giant = run_of("a", "acc", big)?;
    assert!(matches!(
        refused(replace_run(&exec, &scope, &giant, "run", NOW).await)?,
        StoreError::RunTooLarge { .. }
    ));
    let crowd = run_of("a", "acc", vec![finding("acc", "uid", "res", Status::Fail); MAX_FINDINGS_PER_TENANT + 1])?;
    assert!(matches!(
        refused(replace_run(&exec, &scope, &crowd, "run", NOW).await)?,
        StoreError::RunTooLarge { .. }
    ));
    let calls = calls_of(&fake)?;
    assert_eq!(calls.len(), THREE);
    calls.iter().try_for_each(|call| {
        assert_eq!(call.tenant, "a");
        assert_eq!(call.sql, REFUSE_SQL);
        assert_eq!(call.params.len(), FOUR);
        assert!(!call.sql.contains("posture_replace_run"));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let sizes: Vec<&str> = calls.iter().map(|call| param(call, TWO)).collect::<Result<_, _>>()?;
    assert_eq!(sizes, vec!["1", &GIANT_RUN.to_string(), &(MAX_FINDINGS_PER_TENANT + 1).to_string()]);
    let first = calls.first().ok_or("no call")?;
    assert_eq!(param(first, 0)?, "acc");
    assert_eq!(param(first, 1)?, NOW.to_string());
    assert_eq!(param(first, THREE)?, MAX_FINDINGS_PER_TENANT.to_string());
    Ok(())
}


#[tokio::test]
async fn a_failing_marker_is_logged_and_the_refusal_stays_the_answer() -> TestResult {
    let scope = tenant_scope("a")?;
    let failing = Double {
        fail: true,
        ..double(Vec::new())
    };
    let exec = executor(&failing);
    let found = run_of("a", "acc", vec![finding("acc", "u1", "res-1", Status::Fail)])?;
    assert!(matches!(
        refused(replace_run_limited(&exec, &scope, &found, "run", NOW, 1).await)?,
        StoreError::RunTooLarge { .. }
    ));
    Ok(())
}


#[test]
fn the_second_migration_writes_the_marker_under_the_tenant_lock() -> TestResult {
    check_embedded(&MIGRATIONS)?;
    let sql = MIGRATIONS.get(1).ok_or("no second migration")?.sql;
    assert_eq!(MIGRATIONS.get(1).ok_or("none")?.version, "posture_0002");
    assert!(sql.contains("pg_advisory_xact_lock(hashtextextended('cloud_posture/' || tenant_name, 0))"));
    assert!(sql.contains("SET search_path = pg_catalog, public, pg_temp SET enable_seqscan = off SET enable_bitmapscan = off SET jit = off AS $$"));
    assert!(sql.contains("UPDATE cloud_posture_runs r SET refused_micros = finished, refused_items = claimed WHERE r.tenant = tenant_name AND r.account = account_name;"));
    assert!(sql.contains("IF NOT FOUND AND others + 1 <= max_total THEN"));
    assert!(!sql.contains("DELETE"));
    assert!(!sql.contains("INSERT INTO cloud_posture_findings"));
    assert!(REFUSE_SQL.contains("posture_refuse_run($1, $2, $3::text::bigint, $4::text::bigint, $5::text::bigint)"));
    Ok(())
}


#[test]
fn the_third_migration_pins_the_page_plan_and_keeps_the_newest_refusal() -> TestResult {
    check_embedded(&MIGRATIONS)?;
    let migration = MIGRATIONS.get(TWO).ok_or("no third migration")?;
    assert_eq!(migration.version, "posture_0003");
    let sql = migration.sql;
    assert!(sql.contains("GENERATED ALWAYS AS (int4send(32767 - severity_rank::integer) || identity) STORED;"));
    assert!(sql.contains("CREATE INDEX cloud_posture_findings_page_key ON cloud_posture_findings (tenant, account, page_key);"));
    assert!(sql.contains("DROP INDEX cloud_posture_findings_page;"));
    assert!(sql.contains("LANGUAGE sql STABLE SET search_path = pg_catalog, public, pg_temp SET enable_seqscan = off SET enable_bitmapscan = off SET enable_sort = off SET jit = off"));
    assert_eq!(
        sql.matches("pg_advisory_xact_lock(hashtextextended('cloud_posture/' || tenant_name, 0::bigint))")
            .count(),
        TWO
    );
    assert!(!sql.contains(", 0))"));
    assert_eq!(sql.matches("refused_micros = greatest(r.refused_micros, finished)").count(), TWO);
    assert_eq!(
        sql.matches("CASE WHEN r.refused_micros IS NULL OR finished > r.refused_micros THEN")
            .count(),
        TWO
    );
    assert!(sql.contains("refused_micros = CASE WHEN cloud_posture_runs.refused_micros > EXCLUDED.finished_micros THEN cloud_posture_runs.refused_micros ELSE NULL END;"));
    assert!(sql.contains(
        "refused_items = CASE WHEN cloud_posture_runs.refused_micros > EXCLUDED.finished_micros THEN cloud_posture_runs.refused_items ELSE 0 END,"
    ));
    Ok(())
}


#[test]
fn constants_and_messages() -> TestResult {
    assert!(STORE_DEADLINE.as_secs() >= MIN_DEADLINE_SECONDS);
    assert_eq!(MAX_FINDINGS_PER_TENANT, CAP);
    [
        StoreError::TenantMismatch,
        StoreError::BadAccount,
        StoreError::BadRunId,
        StoreError::BadTime,
        StoreError::BadAnswer,
        StoreError::BadLimit { max: 1 },
        StoreError::BadCursor,
        StoreError::RunChanged,
        StoreError::StoredValue,
        StoreError::RunTooLarge {
            items: 1,
            max_items: TWO,
            max_bytes: THREE,
        },
        StoreError::TenantCap {
            cap: 1,
            items: TWO,
            others: THREE,
        },
        StoreError::from(PgError::InvalidTenant),
    ]
    .iter()
    .for_each(|error| assert!(!error.to_string().is_empty()));
    Ok(())
}
