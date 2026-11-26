#![cfg(unix)]


#[path = "common/site.rs"]
mod site;
#[path = "common/types.rs"]
mod types;


use core_pg::error::PgError;
use core_pg::scope::TenantScope;
use grc::error::StoreError;
use grc::round::{
    changed_controls, fault_class, gather_indicators, gather_indicators_bounded, refusal_class, run_round, run_round_with, store_outcome_unknown,
    Gathered, RoundFault, RoundSummary, MAX_DIRECTORY_ENTRIES, MAX_INDICATOR_FILES,
};
use grc::service::{load_declarations, Declarations};
use grc::store::{digest_hex, GET_SQL, LIST_FRAMEWORK_SQL, STORE_SQL};
use grc::types::{ClockFn, RowFuture};
use site::{write_site, Site};
use std::fs;
use std::future::ready;
use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use tempfile::{tempdir, TempDir};
use time::Duration;
use time::OffsetDateTime;
use tracing::Dispatch;
use types::TestResult;


const NOW_SECONDS: i64 = 1_795_687_200;


const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH.saturating_add(Duration::seconds(NOW_SECONDS));


const LISTED_ID: &str = "3";


const FILE_CAP_EXCESS: usize = 2;


const BODY_PARAMETER: usize = 4;


const PG_PORT: u16 = 5432;


const FILES_READ: usize = 5;


const HOSTILE_FILES: usize = 6;


fn indicator(tenant: &str, name: &str) -> String {
    format!(r#"{{"tenant":"{tenant}","name":"{name}","value":1,"observed_at":"2026-11-26T09:00:00Z","source":"test"}}"#)
}


fn put(site: &Site, file: &str, text: &str) -> TestResult {
    fs::write(site.indicators.join(file), text)?;
    Ok(())
}


fn fresh() -> Result<(TempDir, Site), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let site = write_site(dir.path(), PG_PORT, "", "[builtin:nis2]")?;
    Ok((dir, site))
}


#[derive(Clone)]
enum StoreReply {
    Rows(Vec<Vec<String>>),
    Fails(fn() -> PgError),
}


#[derive(Default)]
struct Script {
    previous: Mutex<Option<String>>,
    stored: Mutex<Vec<String>>,
    list: Option<Result<Vec<Vec<String>>, ()>>,
    get: Option<Vec<Vec<String>>>,
    store: Option<StoreReply>,
}


fn answer(script: &Script, sql: &'static str, params: Vec<String>) -> Result<Vec<Vec<String>>, PgError> {
    let failure = || PgError::InvalidTenant;
    if sql == LIST_FRAMEWORK_SQL {
        match script.list.clone() {
            Some(Ok(rows)) => Ok(rows),
            Some(Err(())) => Err(failure()),
            None => script
                .previous
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .map_or(Ok(Vec::new()), |body| Ok(vec![meta_row(body)])),
        }
    } else if sql == GET_SQL {
        match script.get.clone() {
            Some(rows) => Ok(rows),
            None => Ok(script
                .previous
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .map(|body| vec!["nis2".to_owned(), "1".to_owned(), "2026-11-26".to_owned(), digest_hex(body), body.clone()])
                .collect()),
        }
    } else if sql == STORE_SQL {
        let body = params.get(BODY_PARAMETER).cloned().ok_or_else(failure)?;
        script.stored.lock().unwrap_or_else(PoisonError::into_inner).push(body);
        match script.store.clone() {
            Some(StoreReply::Rows(rows)) => Ok(rows),
            Some(StoreReply::Fails(make)) => Err(make()),
            None => Ok(vec![vec!["stored".to_owned(), "7".to_owned()]]),
        }
    } else {
        Err(failure())
    }
}


fn meta_row(body: &str) -> Vec<String> {
    [LISTED_ID, "nis2", "1", "2026-11-26", &digest_hex(body), &body.len().to_string(), "5"]
        .map(str::to_owned)
        .to_vec()
}


async fn round_over(script: &Script, declarations: &Declarations, gathered: &Gathered) -> RoundSummary {
    let exec = |_scope: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> { Box::pin(ready(answer(script, sql, params))) };
    run_round_with(&exec, declarations, gathered, NOW).await
}


fn declarations(site: &Site) -> Result<Declarations, Box<dyn std::error::Error>> {
    Ok(load_declarations(&site.settings_file)?)
}


#[test]
fn indicator_files_are_read_each_refused_alone_and_named_by_count() -> TestResult {
    let (_dir, site) = fresh()?;
    put(
        &site,
        "a.json",
        &format!(
            "[{}, {}]",
            indicator("acme", "vuln.kev_mean_days_to_fix"),
            indicator("globex", "assets.owned_ratio")
        ),
    )?;
    put(&site, "b.json", &format!("[{}]", indicator("acme", "assets.owned_ratio")))?;
    put(&site, "dup1.json", &format!("[{}]", indicator("acme", "patch.on_time_ratio")))?;
    put(&site, "dup2.json", &format!("[{}]", indicator("acme", "patch.on_time_ratio")))?;
    put(&site, "bad.json", "not json")?;
    put(&site, "notes.txt", "ignored")?;
    let gathered = gather_indicators(&site.indicators, "acme");
    let names: Vec<&str> = gathered.values.iter().map(|value| value.name.as_str()).collect();
    assert_eq!(names, vec!["vuln.kev_mean_days_to_fix", "assets.owned_ratio"]);
    assert_eq!(
        (gathered.files, gathered.refused_files, gathered.foreign, gathered.duplicated),
        (FILES_READ, 1, 1, 1)
    );
    assert!(!gathered.unreadable_directory);
    Ok(())
}


#[test]
fn hostile_indicator_files_are_refused_alone_and_the_others_still_count() -> TestResult {
    let (_dir, site) = fresh()?;
    put(&site, "good.json", &format!("[{}]", indicator("acme", "assets.owned_ratio")))?;
    put(
        &site,
        "duplicate-key.json",
        r#"[{"tenant":"acme","tenant":"acme","name":"x","value":1,"observed_at":"2026-11-26T09:00:00Z","source":"t"}]"#,
    )?;
    put(
        &site,
        "nan.json",
        r#"[{"tenant":"acme","name":"x","value":NaN,"observed_at":"2026-11-26T09:00:00Z","source":"t"}]"#,
    )?;
    put(
        &site,
        "huge.json",
        r#"[{"tenant":"acme","name":"x","value":1e999,"observed_at":"2026-11-26T09:00:00Z","source":"t"}]"#,
    )?;
    let big = fs::File::create(site.indicators.join("big.json"))?;
    big.set_len(grc::inputs::MAX_INPUT_BYTES + 1)?;
    let status = std::process::Command::new("mkfifo").arg(site.indicators.join("fifo.json")).status()?;
    assert!(status.success());
    std::os::unix::fs::symlink("/dev/zero", site.indicators.join("zero.json"))?;
    let gathered = gather_indicators(&site.indicators, "acme");
    assert_eq!(gathered.values.len(), 1);
    assert_eq!(gathered.refused_files, HOSTILE_FILES);
    Ok(())
}


#[test]
fn files_beyond_the_cap_are_counted_and_a_missing_directory_is_named() -> TestResult {
    let (_dir, site) = fresh()?;
    (0..MAX_INDICATOR_FILES + FILE_CAP_EXCESS).try_for_each(|index| put(&site, &format!("f{index:02}.json"), "[]"))?;
    let gathered = gather_indicators(&site.indicators, "acme");
    assert_eq!((gathered.files, gathered.beyond_cap), (MAX_INDICATOR_FILES, FILE_CAP_EXCESS));
    let absent = gather_indicators(&site.dir.join("absent"), "acme");
    assert!(absent.unreadable_directory);
    assert!(absent.values.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_first_round_stores_and_a_second_over_the_same_evidence_counts_no_change() -> TestResult {
    let (_dir, site) = fresh()?;
    let loaded = declarations(&site)?;
    let script = Script::default();
    let first = round_over(&script, &loaded, &Gathered::default()).await;
    assert_eq!((first.stored, first.failed, first.cap_reached), (1, 0, 0));
    assert_eq!(first.changed, 1);
    assert!(first.no_evidence > 0);
    let body = script
        .stored
        .lock()
        .map_err(|_poisoned| "poisoned")?
        .first()
        .cloned()
        .ok_or("nothing stored")?;
    *script.previous.lock().map_err(|_poisoned| "poisoned")? = Some(body);
    let second = round_over(&script, &loaded, &Gathered::default()).await;
    assert_eq!((second.stored, second.changed), (1, 0));
    *script.previous.lock().map_err(|_poisoned| "poisoned")? = Some(r#"{"controls":[{"id":"art21-2-a","evidence_digest":"old"}]}"#.to_owned());
    let third = round_over(&script, &loaded, &Gathered::default()).await;
    assert_eq!(third.changed, 1);
    Ok(())
}


#[tokio::test]
async fn an_unreadable_previous_report_counts_every_control_as_changed_and_the_store_still_runs() -> TestResult {
    let (_dir, site) = fresh()?;
    let loaded = declarations(&site)?;
    let listing_fails = Script {
        list: Some(Err(())),
        ..Script::default()
    };
    assert_eq!(round_over(&listing_fails, &loaded, &Gathered::default()).await.stored, 1);
    let meta = meta_row("{}");
    let empty_get = Script {
        list: Some(Ok(vec![meta.clone()])),
        get: Some(Vec::new()),
        ..Script::default()
    };
    assert_eq!(round_over(&empty_get, &loaded, &Gathered::default()).await.stored, 1);
    let bad_body = Script {
        list: Some(Ok(vec![meta])),
        get: Some(vec![vec![
            "nis2".to_owned(),
            "1".to_owned(),
            "2026-11-26".to_owned(),
            digest_hex("{}"),
            "{}".to_owned(),
        ]]),
        ..Script::default()
    };
    assert_eq!(round_over(&bad_body, &loaded, &Gathered::default()).await.stored, 1);
    Ok(())
}


#[tokio::test]
async fn already_stored_the_cap_a_store_fault_and_a_foreign_record_are_each_counted_by_name() -> TestResult {
    let (_dir, site) = fresh()?;
    let loaded = declarations(&site)?;
    let already = Script {
        store: Some(StoreReply::Rows(vec![vec!["already_stored".to_owned(), "7".to_owned()]])),
        ..Script::default()
    };
    let summary = round_over(&already, &loaded, &Gathered::default()).await;
    assert_eq!((summary.already_stored, summary.stored), (1, 0));
    let capped = Script {
        store: Some(StoreReply::Rows(vec![vec!["refused".to_owned(), "0".to_owned()]])),
        ..Script::default()
    };
    let capped_summary = round_over(&capped, &loaded, &Gathered::default()).await;
    assert_eq!((capped_summary.cap_reached, capped_summary.failed, capped_summary.stored), (1, 0, 0));
    let failing = Script {
        store: Some(StoreReply::Fails(server_error)),
        ..Script::default()
    };
    let failed_summary = round_over(&failing, &loaded, &Gathered::default()).await;
    assert_eq!((failed_summary.failed, failed_summary.unknown), (1, 0));
    let mut foreign = loaded.clone();
    foreign.manual.iter_mut().for_each(|record| record.tenant = "globex".to_owned());
    let foreign_summary = round_over(&Script::default(), &foreign, &Gathered::default()).await;
    assert_eq!((foreign_summary.failed, foreign_summary.stored), (1, 0));
    Ok(())
}


#[test]
fn every_fault_has_a_fixed_class() -> TestResult {
    assert_eq!(fault_class(&RoundFault::Report(grc::error::GrcError::Duplicate)), "report");
    assert_eq!(
        fault_class(&RoundFault::Store(grc::error::StoreError::CapReached { max: 1 })),
        "cap_reached"
    );
    assert_eq!(fault_class(&RoundFault::Store(grc::error::StoreError::BadRow)), "unknown");
    assert_eq!(fault_class(&RoundFault::Store(grc::error::StoreError::Busy)), "store");
    assert_eq!(fault_class(&RoundFault::Store(StoreError::Store(server_error()))), "store");
    Ok(())
}


fn server_error() -> PgError {
    PgError::Server {
        code: "57014".to_owned(),
        class: "query_canceled",
    }
}


fn client_deadline() -> PgError {
    PgError::ClientDeadline { seconds: 1 }
}


#[test]
fn only_a_statement_that_may_have_committed_is_unknown() -> TestResult {
    assert!(store_outcome_unknown(&StoreError::Store(client_deadline())));
    assert!(store_outcome_unknown(&StoreError::Store(PgError::InvalidTenant)));
    assert!(store_outcome_unknown(&StoreError::BadRow));
    assert!(!store_outcome_unknown(&StoreError::Store(server_error())));
    assert!(!store_outcome_unknown(&StoreError::Store(PgError::StatementTimeout { seconds: 1 })));
    assert!(!store_outcome_unknown(&StoreError::Store(PgError::ConnectTimeout { seconds: 1 })));
    assert!(!store_outcome_unknown(&StoreError::TooLarge { bytes: BIGGER, max: 1 }));
    assert!(!store_outcome_unknown(&StoreError::TenantMismatch));
    Ok(())
}


#[tokio::test]
async fn a_lost_reply_and_a_bad_answer_are_counted_unknown_never_as_a_failure_or_a_store() -> TestResult {
    let (_dir, site) = fresh()?;
    let loaded = declarations(&site)?;
    let lost = Script {
        store: Some(StoreReply::Fails(client_deadline)),
        ..Script::default()
    };
    let lost_summary = round_over(&lost, &loaded, &Gathered::default()).await;
    assert_eq!((lost_summary.unknown, lost_summary.failed, lost_summary.stored), (1, 0, 0));
    let garbled = Script {
        store: Some(StoreReply::Rows(vec![vec!["stored".to_owned()]])),
        ..Script::default()
    };
    let garbled_summary = round_over(&garbled, &loaded, &Gathered::default()).await;
    assert_eq!((garbled_summary.unknown, garbled_summary.failed, garbled_summary.stored), (1, 0, 0));
    let timed_out = Script {
        store: Some(StoreReply::Fails(|| PgError::StatementTimeout { seconds: 1 })),
        ..Script::default()
    };
    let timed_out_summary = round_over(&timed_out, &loaded, &Gathered::default()).await;
    assert_eq!((timed_out_summary.unknown, timed_out_summary.failed), (0, 1));
    Ok(())
}


#[test]
fn a_changed_digest_is_counted_and_an_absent_one_on_both_sides_is_not() -> TestResult {
    let (_dir, site) = fresh()?;
    let loaded = declarations(&site)?;
    let framework = loaded.frameworks.first().ok_or("none")?;
    let report = grc::round::report_of("acme", framework, (&[], &loaded.manual), NOW)?;
    assert_eq!(changed_controls(&report, &std::collections::BTreeMap::new()), 1);
    Ok(())
}


fn clock() -> OffsetDateTime {
    NOW
}


#[tokio::test]
async fn an_unreachable_database_makes_the_round_unavailable_not_failed() -> TestResult {
    let (_dir, site) = fresh()?;
    let listener = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    listener.bind(&std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)).into())?;
    let port = listener.local_addr()?.as_socket().ok_or("no port")?.port();
    fs::write(&site.pg_file, site::pg_text(&site.dir, port, "127.0.0.1"))?;
    let loaded = declarations(&site)?;
    let clock_fn: &ClockFn = &clock;
    let summary = run_round(&loaded, clock_fn).await;
    assert!(summary.unavailable);
    assert_eq!(summary.failed, 0);
    Ok(())
}


const BIGGER: usize = 2;


const DECOYS: usize = MAX_DIRECTORY_ENTRIES + 100;


const SMALL_SCAN: usize = 3;


const SMALL_SCAN_FILES: usize = 5;


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


struct Sink(Arc<Mutex<Vec<u8>>>);


impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn captured<Output>(work: impl FnOnce() -> Output) -> Result<(Output, String), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || Sink(Arc::clone(&writer)))
        .with_ansi(false)
        .finish();
    let value = tracing::subscriber::with_default(subscriber, work);
    let bytes = buffer.lock().map_err(|_poisoned| "poisoned")?.clone();
    Ok((value, String::from_utf8(bytes)?))
}


#[test]
fn decoy_entries_never_hide_a_producer_file_and_a_crowded_directory_is_named_by_its_count() -> TestResult {
    let (_dir, site) = fresh()?;
    (0..DECOYS).try_for_each(|index| put(&site, &format!("decoy{index}.txt"), "x"))?;
    put(&site, "real.json", &format!("[{}]", indicator("acme", "assets.owned_ratio")))?;
    let (gathered, log) = captured(|| gather_indicators(&site.indicators, "acme"))?;
    assert_eq!(gathered.values.len(), 1);
    assert_eq!((gathered.entries, gathered.scan_cut), (DECOYS + 1, false));
    assert!(log.contains(&format!("entries={}", DECOYS + 1)), "{log}");
    assert!(log.contains("scan_cut=false"), "{log}");
    Ok(())
}


#[test]
fn a_scan_cut_by_its_bound_is_a_named_warning_never_a_silent_slice() -> TestResult {
    let (_dir, site) = fresh()?;
    (0..SMALL_SCAN_FILES).try_for_each(|index| put(&site, &format!("f{index}.json"), "[]"))?;
    let (gathered, log) = captured(|| gather_indicators_bounded(&site.indicators, "acme", SMALL_SCAN))?;
    assert_eq!((gathered.entries, gathered.scan_cut), (SMALL_SCAN, true));
    assert!(log.contains("scan_cut=true"), "{log}");
    assert!(log.contains(&format!("entries={SMALL_SCAN}")), "{log}");
    let (quiet, quiet_log) = captured(|| gather_indicators_bounded(&site.indicators, "acme", MAX_DIRECTORY_ENTRIES))?;
    assert_eq!((quiet.entries, quiet.scan_cut), (SMALL_SCAN_FILES, false));
    assert!(!quiet_log.contains("entry bound"), "{quiet_log}");
    Ok(())
}


#[test]
fn a_hostile_file_name_cannot_forge_a_log_line_and_the_refusal_is_a_fixed_class() -> TestResult {
    let (_dir, site) = fresh()?;
    let hostile = "x\nINFO forged line\u{1b}[31m.json";
    put(&site, hostile, "not json")?;
    let (gathered, log) = captured(|| gather_indicators(&site.indicators, "acme"))?;
    assert_eq!(gathered.refused_files, 1);
    assert_eq!(log.lines().count(), 1, "{log:?}");
    assert!(!log.contains('\u{1b}'), "{log:?}");
    assert!(log.contains("class=\"malformed JSON\""), "{log:?}");
    assert!(log.contains("\\n"), "{log:?}");
    Ok(())
}


#[test]
fn every_refusal_has_a_fixed_class_that_holds_no_file_text() -> TestResult {
    let marker = "SECRET-MARKER";
    let invalid = grc::error::GrcError::Invalid {
        file: marker.to_owned(),
        reason: marker.to_owned(),
    };
    assert_eq!(refusal_class(&invalid), "invalid content");
    assert_eq!(refusal_class(&grc::error::GrcError::Duplicate), "refused");
    let json = grc::error::GrcError::Json {
        file: marker.to_owned(),
        category: serde_json::error::Category::Syntax,
        line: 1,
        column: 1,
    };
    assert_eq!(refusal_class(&json), "malformed JSON");
    let unreadable = grc::inputs::load_indicators(std::path::Path::new("/nonexistent-SECRET-MARKER.json"))
        .err()
        .ok_or("must refuse")?;
    assert_eq!(refusal_class(&unreadable), "unreadable, not a regular file, or too large");
    Ok(())
}
