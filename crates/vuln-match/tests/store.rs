#[path = "common/store/types.rs"]
mod store_types;
#[path = "common/types.rs"]
mod types;


use alerts::types::RowFuture;
use core_pg::error::PgError;
use core_pg::migrate::{check_embedded, check_namespace};
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use serde_json::Value;
use std::cmp::Reverse;
use std::future::ready;
use std::sync::Mutex;
use store_types::Call;
use types::TestResult;
use vuln_match::error::StoreError;
use vuln_match::limits::{
    LAST_SEEN_GRANULARITY_MICROS, MAX_CURSOR_BYTES, MAX_FIELD_BYTES, MAX_FINDINGS_PER_SCAN, MAX_OPEN_FINDINGS_PER_TENANT, MAX_PAGE_LIMIT,
    MAX_RESOLVED_FINDINGS_PER_TENANT,
};
use vuln_match::model::{AssetFinding, Criticality, Finding, ScoredFinding, StoredFinding};
use vuln_match::priority::priority_of;
use vuln_match::store::{
    cursor_of, finding_doc, is_field, open_findings, parse_cursor, record_scan, record_scan_capped, stored_of, FIRST_SQL, MIGRATIONS,
    MIGRATION_NAMESPACE, NEXT_SQL, SCAN_SQL,
};


const TWO: usize = 2;


const THREE: usize = 3;


const UPDATED: u64 = 2;


const RESOLVED: u64 = 3;


const FOUR: u32 = 4;


const FIVE: u32 = 5;


const SEVEN: u64 = 7;


const EIGHT: u64 = 8;


const KEY_FIELDS: usize = 4;


const ANSWER_COLUMNS: usize = 5;


const CURSOR_PARTS: usize = 5;


const NOW: u64 = 1_700_000_000_000_000;


const PARAM_ASSET: usize = 0;


const PARAM_DOCS: usize = 1;


const PARAM_CAP: usize = 2;


const PARAM_NOW: usize = 3;


const PARAM_RESOLVED_CAP: usize = 4;


const PARAM_GRANULARITY: usize = 5;


const SMALL_RESOLVED_CAP: u64 = 6;


const ROW_COUNT: usize = 1_200;


const PRIORITY_SPREAD: usize = 7;


const PRIORITY_BASE: u32 = 1_000;


const SMALL_CAP: u64 = 5;


const OVER_SCORE: f64 = 11.0;


const BIG_EPSS: f64 = 2.0;


const GOOD_CVSS: f64 = 7.5;


const GOOD_EPSS: f64 = 0.25;


const MAX_U32_PRIORITY: u32 = 4_294_967_295;


const FIELD_COLUMNS: usize = 12;


const COL_FIXED: usize = 5;


const COL_CVSS: usize = 6;


const ALIAS_FLOOD: usize = 101;


const HUGE_NAME: usize = 1_000_000;


const DOC_COLUMN_PRIORITY: usize = 9;


const SMALL_PAGE: usize = 3;


#[derive(Default)]
pub struct Double {
    pub calls: Mutex<Vec<Call>>,
    pub scan_reply: Vec<Vec<String>>,
    pub pages: Vec<Vec<String>>,
    pub fail: bool,
}


pub fn row(priority: u32, asset: &str, ecosystem: &str, package: &str, record: &str) -> Vec<String> {
    [
        asset.to_owned(),
        ecosystem.to_owned(),
        package.to_owned(),
        record.to_owned(),
        "1.0".to_owned(),
        String::new(),
        "7.5".to_owned(),
        "0.25".to_owned(),
        "false".to_owned(),
        priority.to_string(),
        "10".to_owned(),
        "20".to_owned(),
    ]
    .to_vec()
}


pub fn key_of(item: &[String]) -> (Reverse<u32>, Vec<String>) {
    let priority = item.get(DOC_COLUMN_PRIORITY).and_then(|text| text.parse::<u32>().ok()).unwrap_or(0);
    (Reverse(priority), item.iter().take(KEY_FIELDS).cloned().collect())
}


pub fn model_pages(double: &Double, sql: &'static str, params: &[String]) -> Vec<Vec<String>> {
    let limit: usize = params.last().and_then(|text| text.parse().ok()).unwrap_or(0);
    let after: Option<(Reverse<u32>, Vec<String>)> = (sql == NEXT_SQL).then(|| {
        let priority = params.first().and_then(|text| text.parse::<u32>().ok()).unwrap_or(0);
        (Reverse(priority), params.iter().skip(1).take(KEY_FIELDS).cloned().collect())
    });
    double
        .pages
        .iter()
        .filter(|item| after.as_ref().is_none_or(|cursor| key_of(item) > *cursor))
        .take(limit)
        .cloned()
        .collect()
}


pub fn executor<'a>(double: &'a Double) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> {
        let answer = if double.fail {
            Err(PgError::InvalidTenant)
        } else {
            let tenant = tenant_of(&scope).to_owned();
            let reply = if sql == SCAN_SQL {
                double.scan_reply.clone()
            } else {
                model_pages(double, sql, &params)
            };
            match double.calls.lock() {
                Ok(mut calls) => {
                    calls.push((tenant, sql, params));
                    Ok(reply)
                }
                Err(_poisoned) => Err(PgError::InvalidTenant),
            }
        };
        Box::pin(ready(answer))
    }
}


pub fn calls_of(double: &Double) -> Result<Vec<Call>, Box<dyn std::error::Error>> {
    Ok(double.calls.lock().map_err(|_poisoned| "poisoned")?.clone())
}


pub fn finding(asset: &str, package: &str, record: &str) -> AssetFinding {
    AssetFinding {
        asset: asset.to_owned(),
        scored: ScoredFinding {
            finding: Finding {
                package: package.to_owned(),
                installed_version: "1.0-1".to_owned(),
                ecosystem: "Debian:12".to_owned(),
                record_id: record.to_owned(),
                cve_aliases: vec!["CVE-2024-1234".to_owned()],
                fixed_version: Some("1.2".to_owned()),
            },
            cvss: GOOD_CVSS,
            epss: GOOD_EPSS,
            kev: false,
            criticality: Criticality::High,
        },
    }
}


pub fn outcome_reply(values: [&str; ANSWER_COLUMNS]) -> Vec<Vec<String>> {
    vec![values.iter().map(|text| (*text).to_owned()).collect()]
}


#[test]
fn migration_is_well_formed_and_resolves_absent_rows_per_tenant() -> TestResult {
    check_namespace(MIGRATION_NAMESPACE)?;
    check_embedded(&MIGRATIONS)?;
    let sql = MIGRATIONS.first().ok_or("no migration")?.sql;
    assert!(sql.contains("pg_advisory_xact_lock(hashtextextended('vuln_scan_store/' || tenant_name, 0))"));
    assert!(!sql.contains("hashtext(tenant_name)"));
    assert!(sql.contains("SET search_path = pg_catalog, public SET enable_nestloop = off"));
    assert!(sql.contains("DELETE FROM vuln_findings WHERE ctid = ANY (ARRAY("));
    assert!(sql.contains("IF NOT EXISTS (SELECT 1 FROM vuln_finding_rows WHERE tenant = tenant_name) THEN"));
    assert!(sql.contains("m.changed OR m.was_seen <= now_micros - granularity"));
    assert!(sql.contains("SELECT max_open - open_total INTO room"));
    assert!(sql.contains("LIMIT greatest(room + (SELECT count(*) FROM resolved), 0)"));
    assert!(sql.contains("ORDER BY resolved_micros, asset, ecosystem, package, record_id LIMIT excess"));
    assert!(sql.contains("UPDATE vuln_findings f SET resolved_micros = now_micros"));
    assert!(sql.contains("AND NOT EXISTS (SELECT 1 FROM incoming i"));
    assert!(sql.contains("WHERE tenant = tenant_name"));
    assert!(sql.contains("FROM vuln_findings WHERE tenant = tenant_name"));
    assert!(sql.contains("UPDATE vuln_finding_rows SET open_total = open_total + n_inserted + n_reopened - n_resolved"));
    assert!(sql.contains("UPDATE vuln_finding_rows SET resolved_total = resolved_total - n_evicted WHERE tenant = tenant_name"));
    Ok(())
}


#[test]
fn every_read_statement_binds_the_tenant() -> TestResult {
    assert!(FIRST_SQL.contains("WHERE tenant = $1 AND resolved_micros IS NULL"));
    assert!(NEXT_SQL.contains("WHERE tenant = $1 AND resolved_micros IS NULL"));
    assert!(SCAN_SQL.contains("vuln_scan_store($1, $2"));
    Ok(())
}


#[test]
fn field_grammar() -> TestResult {
    assert!(is_field("openssl"));
    assert!(is_field(&"a".repeat(MAX_FIELD_BYTES)));
    assert!(!is_field(""));
    assert!(!is_field(&"a".repeat(MAX_FIELD_BYTES + 1)));
    assert!(!is_field("with space"));
    assert!(!is_field("-rf"));
    assert!(is_field("a-b"));
    assert!(!is_field("esc\u{1b}[0m"));
    assert!(!is_field("\u{e9}"));
    Ok(())
}


#[test]
fn doc_of_a_good_finding() -> TestResult {
    let item = finding("h1", "openssl", "DSA-1");
    let doc = finding_doc("h1", &item).ok_or("refused")?;
    assert_eq!(doc.get("package").and_then(Value::as_str), Some("openssl"));
    assert_eq!(doc.get("fixed_version").and_then(Value::as_str), Some("1.2"));
    assert_eq!(doc.get("priority").and_then(Value::as_u64), Some(u64::from(priority_of(&item.scored))));
    let mut unfixed = item;
    unfixed.scored.finding.fixed_version = None;
    let unfixed_doc = finding_doc("h1", &unfixed).ok_or("refused")?;
    assert_eq!(unfixed_doc.get("fixed_version"), Some(&Value::Null));
    Ok(())
}


#[test]
fn doc_refuses_each_bad_input_alone() -> TestResult {
    let good = finding("h1", "openssl", "DSA-1");
    assert!(finding_doc("h2", &good).is_none());
    let mut huge = good.clone();
    huge.scored.finding.package = "p".repeat(HUGE_NAME);
    assert!(finding_doc("h1", &huge).is_none());
    let mut escape = good.clone();
    escape.scored.finding.installed_version = "1.0\u{1b}[31m".to_owned();
    assert!(finding_doc("h1", &escape).is_none());
    let mut bad_fixed = good.clone();
    bad_fixed.scored.finding.fixed_version = Some("1 2".to_owned());
    assert!(finding_doc("h1", &bad_fixed).is_none());
    let mut nan = good.clone();
    nan.scored.cvss = f64::NAN;
    assert!(finding_doc("h1", &nan).is_none());
    let mut over = good.clone();
    over.scored.cvss = OVER_SCORE;
    assert!(finding_doc("h1", &over).is_none());
    let mut epss = good.clone();
    epss.scored.epss = BIG_EPSS;
    assert!(finding_doc("h1", &epss).is_none());
    let mut negative = good.clone();
    negative.scored.epss = -GOOD_EPSS;
    assert!(finding_doc("h1", &negative).is_none());
    let mut alias = good.clone();
    alias.scored.finding.cve_aliases = vec!["GHSA-aaaa".to_owned()];
    assert!(finding_doc("h1", &alias).is_none());
    let mut many = good;
    many.scored.finding.cve_aliases = vec!["CVE-2024-1234".to_owned(); ALIAS_FLOOD];
    assert!(finding_doc("h1", &many).is_none());
    Ok(())
}


#[tokio::test]
async fn scan_sends_tenant_asset_docs_cap_and_time() -> TestResult {
    let double = Double {
        scan_reply: outcome_reply(["1", "2", "3", "0", "0"]),
        ..Double::default()
    };
    let exec = executor(&double);
    let scope = tenant_scope("acme")?;
    let findings = vec![finding("h1", "a", "R1"), finding("h1", "b", "R2"), finding("h2", "c", "R3")];
    let outcome = record_scan(&exec, &scope, "h1", &findings, NOW).await?;
    assert_eq!(
        (
            outcome.inserted,
            outcome.updated,
            outcome.resolved,
            outcome.refused_no_room,
            outcome.refused
        ),
        (1, UPDATED, RESOLVED, 0, 1)
    );
    let calls = calls_of(&double)?;
    let (tenant, sql, params) = calls.first().ok_or("no call")?;
    assert_eq!((tenant.as_str(), *sql), ("acme", SCAN_SQL));
    assert_eq!(params.get(PARAM_ASSET).map(String::as_str), Some("h1"));
    let docs: Vec<Value> = serde_json::from_str(params.get(PARAM_DOCS).ok_or("docs")?)?;
    assert_eq!(docs.len(), TWO);
    assert_eq!(params.get(PARAM_CAP), Some(&MAX_OPEN_FINDINGS_PER_TENANT.to_string()));
    assert_eq!(params.get(PARAM_NOW), Some(&NOW.to_string()));
    assert_eq!(params.get(PARAM_RESOLVED_CAP), Some(&MAX_RESOLVED_FINDINGS_PER_TENANT.to_string()));
    assert_eq!(params.get(PARAM_GRANULARITY), Some(&LAST_SEEN_GRANULARITY_MICROS.to_string()));
    Ok(())
}


#[tokio::test]
async fn empty_scan_is_sent_to_resolve_everything() -> TestResult {
    let double = Double {
        scan_reply: outcome_reply(["0", "0", "4", "0", "0"]),
        ..Double::default()
    };
    let exec = executor(&double);
    let outcome = record_scan(&exec, &tenant_scope("acme")?, "h1", &[], NOW).await?;
    assert_eq!(outcome.resolved, u64::from(FOUR));
    let calls = calls_of(&double)?;
    assert_eq!(calls.first().and_then(|call| call.2.get(PARAM_DOCS)).map(String::as_str), Some("[]"));
    Ok(())
}


#[tokio::test]
async fn no_room_is_reported_with_an_injected_cap() -> TestResult {
    let double = Double {
        scan_reply: outcome_reply(["0", "1", "0", "7", "8"]),
        ..Double::default()
    };
    let exec = executor(&double);
    let outcome = record_scan_capped(&exec, &tenant_scope("acme")?, "h1", &[], NOW, SMALL_CAP, SMALL_RESOLVED_CAP).await?;
    assert_eq!((outcome.refused_no_room, outcome.evicted_resolved), (SEVEN, EIGHT));
    let calls = calls_of(&double)?;
    assert_eq!(calls.first().and_then(|call| call.2.get(PARAM_CAP)), Some(&SMALL_CAP.to_string()));
    assert_eq!(
        calls.first().and_then(|call| call.2.get(PARAM_RESOLVED_CAP)),
        Some(&SMALL_RESOLVED_CAP.to_string())
    );
    Ok(())
}


#[tokio::test]
async fn bounds_are_refused_before_any_io() -> TestResult {
    let double = Double::default();
    let exec = executor(&double);
    let scope = tenant_scope("acme")?;
    let one = finding("h1", "a", "R1");
    let many = vec![one.clone(); MAX_FINDINGS_PER_SCAN + 1];
    assert!(matches!(
        record_scan(&exec, &scope, "h1", &many, NOW).await,
        Err(StoreError::TooManyFindings { max: MAX_FINDINGS_PER_SCAN })
    ));
    assert!(matches!(
        record_scan(&exec, &scope, "bad asset", std::slice::from_ref(&one), NOW).await,
        Err(StoreError::BadAsset)
    ));
    assert!(matches!(
        record_scan_capped(&exec, &scope, "h1", std::slice::from_ref(&one), NOW, 0, 1).await,
        Err(StoreError::BadCap { .. })
    ));
    assert!(matches!(
        record_scan_capped(&exec, &scope, "h1", std::slice::from_ref(&one), NOW, MAX_OPEN_FINDINGS_PER_TENANT + 1, 1).await,
        Err(StoreError::BadCap { .. })
    ));
    assert!(matches!(
        record_scan_capped(&exec, &scope, "h1", std::slice::from_ref(&one), NOW, 1, 0).await,
        Err(StoreError::BadCap { .. })
    ));
    assert!(matches!(
        record_scan_capped(
            &exec,
            &scope,
            "h1",
            std::slice::from_ref(&one),
            NOW,
            1,
            MAX_RESOLVED_FINDINGS_PER_TENANT + 1
        )
        .await,
        Err(StoreError::BadCap { .. })
    ));
    assert!(matches!(
        record_scan(&exec, &scope, "h1", std::slice::from_ref(&one), u64::MAX).await,
        Err(StoreError::BadTime)
    ));
    assert!(calls_of(&double)?.is_empty());
    let exact = vec![one; MAX_FINDINGS_PER_SCAN];
    assert!(record_scan(&exec, &scope, "h1", &exact, NOW).await.is_err());
    assert_eq!(calls_of(&double)?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn database_and_answer_errors_keep_no_text() -> TestResult {
    let failing = Double {
        fail: true,
        ..Double::default()
    };
    let exec = executor(&failing);
    let scope = tenant_scope("acme")?;
    assert!(matches!(record_scan(&exec, &scope, "h1", &[], NOW).await, Err(StoreError::Pg(_))));
    for reply in [Vec::new(), outcome_reply(["x", "0", "0", "0", "0"]), vec![vec!["1".to_owned()]]] {
        let double = Double {
            scan_reply: reply,
            ..Double::default()
        };
        let reply_exec = executor(&double);
        let error = record_scan(&reply_exec, &scope, "h1", &[], NOW).await.err().ok_or("accepted")?;
        assert!(matches!(error, StoreError::BadAnswer));
        assert!(!format!("{error:?}{error}").contains("acme"));
    }
    Ok(())
}


#[test]
fn cursor_round_trip_and_refusals() -> TestResult {
    let long = "~".repeat(MAX_FIELD_BYTES);
    let stored = stored_of(&row(MAX_U32_PRIORITY, &long, &long, &long, &long))?;
    let cursor = cursor_of(&stored);
    assert_eq!(cursor.len(), MAX_CURSOR_BYTES);
    assert_eq!(parse_cursor(&cursor)?.len(), CURSOR_PARTS);
    assert_eq!(parse_cursor("7 h1 Debian:12 pkg R1")?, ["7", "h1", "Debian:12", "pkg", "R1"]);
    let every_byte: String = (b'!'..=b'~').map(char::from).collect();
    let wide = stored_of(&row(1, &every_byte, "e", "p", "r"))?;
    assert_eq!(parse_cursor(&cursor_of(&wide))?.get(1), Some(&every_byte));
    let refused = [
        "",
        "7 h1 e p",
        "7 h1 e p r extra",
        "x h1 e p r",
        "07 h1 e p r",
        "-1 h1 e p r",
        "4294967296 h1 e p r",
        "7  e p r",
        &format!("7 {}", "a".repeat(MAX_CURSOR_BYTES)),
        "7 h1 e p r\u{1b}",
        &format!("7 {long} {long} {long} {long}x"),
    ];
    refused
        .iter()
        .for_each(|text| assert!(matches!(parse_cursor(text), Err(StoreError::BadCursor)), "{text:?}"));
    Ok(())
}


#[test]
fn stored_row_errors() -> TestResult {
    let good = row(FIVE, "h1", "e", "p", "r");
    assert_eq!(stored_of(&good)?.fixed_version, None);
    let mut fixed = good.clone();
    fixed.get_mut(COL_FIXED).ok_or("column")?.clone_from(&"2.0".to_owned());
    assert_eq!(stored_of(&fixed)?.fixed_version.as_deref(), Some("2.0"));
    assert!(matches!(
        stored_of(&good.iter().take(FIELD_COLUMNS - 1).cloned().collect::<Vec<_>>()),
        Err(StoreError::BadAnswer)
    ));
    (COL_CVSS..FIELD_COLUMNS).try_for_each(|index| {
        let mut broken = good.clone();
        broken.get_mut(index).ok_or("column")?.clone_from(&"x".to_owned());
        assert!(matches!(stored_of(&broken), Err(StoreError::BadAnswer)), "column {index}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}


pub fn sorted_rows() -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = (0..ROW_COUNT)
        .map(|index| {
            let spread = u32::try_from(index % PRIORITY_SPREAD).unwrap_or(0);
            row(
                PRIORITY_BASE - spread,
                &format!("h{}", index % SMALL_PAGE),
                "Debian:12",
                &format!("pkg{index}"),
                "R1",
            )
        })
        .collect();
    rows.sort_by_key(|item| key_of(item));
    rows
}


#[tokio::test]
async fn pages_walk_every_open_row_once_in_priority_order() -> TestResult {
    let all = sorted_rows();
    let double = Double {
        pages: all.clone(),
        ..Double::default()
    };
    let exec = executor(&double);
    let scope = tenant_scope("acme")?;
    let mut seen: Vec<StoredFinding> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    while pages == 0 || (cursor.is_some() && pages < ROW_COUNT) {
        let page = open_findings(&exec, &scope, cursor.as_deref(), MAX_PAGE_LIMIT).await?;
        assert!(page.findings.len() <= MAX_PAGE_LIMIT);
        seen.extend(page.findings);
        cursor = page.next;
        pages += 1;
    }
    assert_eq!(pages, THREE);
    let expected: Vec<StoredFinding> = all.iter().map(|item| stored_of(item)).collect::<Result<_, _>>()?;
    assert_eq!(seen, expected);
    assert!(seen
        .windows(TWO)
        .all(|pair| pair.first().zip(pair.get(1)).is_some_and(|(left, right)| left.priority >= right.priority)));
    let calls = calls_of(&double)?;
    assert_eq!(calls.first().map(|call| call.1), Some(FIRST_SQL));
    assert_eq!(calls.get(1).map(|call| call.1), Some(NEXT_SQL));
    assert!(calls.iter().all(|call| call.0 == "acme"));
    assert_eq!(calls.first().and_then(|call| call.2.last()), Some(&(MAX_PAGE_LIMIT + 1).to_string()));
    Ok(())
}


#[tokio::test]
async fn last_page_has_no_cursor_and_limits_are_checked() -> TestResult {
    let double = Double {
        pages: vec![row(FIVE, "h1", "e", "p", "r"), row(FOUR, "h1", "e", "p", "s")],
        ..Double::default()
    };
    let exec = executor(&double);
    let scope = tenant_scope("acme")?;
    let page = open_findings(&exec, &scope, None, SMALL_PAGE).await?;
    assert_eq!((page.findings.len(), page.next), (TWO, None));
    let exact = open_findings(&exec, &scope, None, TWO).await?;
    assert_eq!(exact.next, None);
    let first = open_findings(&exec, &scope, None, 1).await?;
    assert_eq!(first.next.as_deref(), Some("5 h1 e p r"));
    let before = calls_of(&double)?.len();
    assert!(matches!(open_findings(&exec, &scope, None, 0).await, Err(StoreError::BadLimit { .. })));
    assert!(matches!(
        open_findings(&exec, &scope, None, MAX_PAGE_LIMIT + 1).await,
        Err(StoreError::BadLimit { .. })
    ));
    assert!(matches!(
        open_findings(&exec, &scope, Some("garbage"), 1).await,
        Err(StoreError::BadCursor)
    ));
    assert_eq!(calls_of(&double)?.len(), before);
    Ok(())
}


#[tokio::test]
async fn read_errors() -> TestResult {
    let scope = tenant_scope("acme")?;
    let failing = Double {
        fail: true,
        ..Double::default()
    };
    assert!(matches!(
        open_findings(&executor(&failing), &scope, None, 1).await,
        Err(StoreError::Pg(_))
    ));
    let broken = Double {
        pages: vec![vec!["only".to_owned()]],
        ..Double::default()
    };
    assert!(matches!(
        open_findings(&executor(&broken), &scope, None, 1).await,
        Err(StoreError::BadAnswer)
    ));
    Ok(())
}
