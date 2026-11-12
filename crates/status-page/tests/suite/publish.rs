use crate::harness::{state_with, TENANT};
use crate::types::TestResult;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use status_page::app::{run_app_with, AppFile};
use status_page::error::{StatusPageError, StoreError};
use status_page::model::{ComponentConfig, IncidentInput, IncidentUpdateInput, PageConfig, PageSettings, Snapshot};
use status_page::publish::{
    error_class, fetch, first_publish, fit_page, omission_changed, omission_reason, publisher, render_class, tick, MAX_RENDERS_PER_TICK,
    READ_DEADLINE,
};
use status_page::settings::validate_settings;
use status_page::store_model::PublishedRead;
use status_page::types::IncidentReadFn;
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::{sleep, Instant};


const OTHER_TENANT: &str = "globex";


const SERVICE: &str = "svc-web";


const SECRET_NOTE: &str = "SECRET-INTERNAL-NOTE 10.0.0.5";


const OTHER_TITLE: &str = "GLOBEX-ONLY-TITLE";


const INTERVAL: u64 = 60;


const FAST_INTERVAL: u64 = 5;


const TOO_FAST_INTERVAL: u64 = 4;


const TOO_SLOW_INTERVAL: u64 = 3601;


const TWO_READS: usize = 2;


const SLOW_READ_SECONDS: u64 = 20;


const SKIPPED_BY_SLOW_READ: u64 = 4;


const PAGE: &str = "id: main
tenant: acme
title: Acme status
components:
  - name: Website
    service: svc-web
";


const BAD_TENANT_PAGE: &str = "id: main
tenant: bad tenant
title: Acme status
components:
  - name: Website
    service: svc-web
";


#[derive(Default)]
struct Fake {
    incidents: Vec<IncidentInput>,
    fail: bool,
    leak: bool,
    never: bool,
    delay_seconds: u64,
    hidden: usize,
    hidden_ongoing: usize,
    seen: Vec<String>,
}


fn lock_error<Guard>(_poisoned: PoisonError<Guard>) -> StoreError {
    StoreError::BadRow { column: "lock" }
}


fn incident(tenant: &str, title: &str) -> IncidentInput {
    IncidentInput {
        tenant: tenant.to_owned(),
        service: SERVICE.to_owned(),
        published: true,
        public_title: title.to_owned(),
        started_at: 0,
        resolved_at: None,
        updates: Vec::new(),
        omitted_updates: 0,
        internal_note: SECRET_NOTE.to_owned(),
        assignee: "alice".to_owned(),
        asset_ids: vec!["asset-1".to_owned()],
        addresses: vec!["10.0.0.5".to_owned()],
    }
}


fn config() -> PageConfig {
    PageConfig {
        id: "main".to_owned(),
        tenant: TENANT.to_owned(),
        title: "Acme status".to_owned(),
        checks: Vec::new(),
        components: vec![ComponentConfig {
            name: "Website".to_owned(),
            service: SERVICE.to_owned(),
            objective_ppm: None,
            rule: None,
        }],
    }
}


fn answer(shared: &Arc<Mutex<Fake>>, scope: &TenantScope) -> Result<(Vec<IncidentInput>, Fake), StoreError> {
    let mut fake = shared.lock().map_err(lock_error)?;
    fake.seen.push(tenant_of(scope).to_owned());
    let rows = fake
        .incidents
        .iter()
        .filter(|row| fake.leak || row.tenant == tenant_of(scope))
        .cloned()
        .collect();
    Ok((
        rows,
        Fake {
            fail: fake.fail,
            never: fake.never,
            delay_seconds: fake.delay_seconds,
            hidden: fake.hidden,
            hidden_ongoing: fake.hidden_ongoing,
            ..Fake::default()
        },
    ))
}


fn reader(shared: &Arc<Mutex<Fake>>) -> IncidentReadFn {
    let outer = Arc::clone(shared);
    Box::new(move |scope| {
        let inner = Arc::clone(&outer);
        Box::pin(async move {
            let (rows, flags) = answer(&inner, &scope)?;
            sleep(Duration::from_secs(flags.delay_seconds)).await;
            if flags.never {
                std::future::pending::<()>().await;
            }
            if flags.fail {
                Err(StoreError::BadRow { column: "down" })
            } else {
                let ongoing = rows.iter().filter(|row| row.resolved_at.is_none()).count();
                Ok(PublishedRead {
                    total: rows.len() + flags.hidden,
                    ongoing: ongoing + flags.hidden_ongoing,
                    incidents: rows,
                })
            }
        })
    })
}


fn shared_with(incidents: Vec<IncidentInput>) -> Arc<Mutex<Fake>> {
    Arc::new(Mutex::new(Fake {
        incidents,
        ..Fake::default()
    }))
}


fn change(shared: &Arc<Mutex<Fake>>, edit: impl FnOnce(&mut Fake)) -> TestResult {
    let mut fake = shared.lock().map_err(|_poisoned| "lock")?;
    edit(&mut fake);
    Ok(())
}


fn listen() -> tracing::subscriber::DefaultGuard {
    tracing::subscriber::set_default(tracing_subscriber::fmt().with_writer(std::io::sink).finish())
}


fn served(state: &status_page::model::PageState) -> Result<Arc<Snapshot>, &'static str> {
    state.snapshot.load_full().ok_or("nothing served")
}


fn interval_settings(seconds: u64) -> PageSettings {
    PageSettings {
        publish_interval_seconds: seconds,
        ..PageSettings::default()
    }
}


#[tokio::test(start_paused = true)]
async fn two_ticks_publish_two_snapshots_and_the_etag_follows_the_content() -> TestResult {
    let (state, _clock) = state_with(PageSettings::default());
    let shared = shared_with(vec![incident(TENANT, "Website down")]);
    let read = reader(&shared);
    let scope = tenant_scope(TENANT)?;
    first_publish(&config(), &state, &read, &scope).await?;
    let first = served(&state)?;
    assert!(first.json.contains("Website down"));
    publisher(&config(), &state, &read, &scope, 1).await;
    assert_eq!(served(&state)?.etag, first.etag);
    change(&shared, |fake| fake.incidents.push(incident(TENANT, "Mail slow")))?;
    publisher(&config(), &state, &read, &scope, 1).await;
    let third = served(&state)?;
    assert_ne!(third.etag, first.etag);
    assert!(third.json.contains("Mail slow") && third.html.contains("Mail slow"));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_failing_read_keeps_the_old_snapshot_and_the_next_tick_recovers() -> TestResult {
    let _listener = listen();
    let (state, _clock) = state_with(PageSettings::default());
    let shared = shared_with(vec![incident(TENANT, "Website down")]);
    let read = reader(&shared);
    let scope = tenant_scope(TENANT)?;
    first_publish(&config(), &state, &read, &scope).await?;
    let before = served(&state)?;
    change(&shared, |fake| {
        fake.fail = true;
        fake.incidents.clear();
    })?;
    publisher(&config(), &state, &read, &scope, 1).await;
    assert_eq!(*served(&state)?, *before);
    change(&shared, |fake| {
        fake.fail = false;
        fake.incidents.push(incident(TENANT, "Back again"));
    })?;
    publisher(&config(), &state, &read, &scope, 1).await;
    assert!(served(&state)?.json.contains("Back again"));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_failed_first_read_serves_a_page_without_incidents_and_unknown_components() -> TestResult {
    let _listener = listen();
    let (state, _clock) = state_with(PageSettings::default());
    let shared = shared_with(vec![incident(TENANT, "Website down")]);
    change(&shared, |fake| fake.fail = true)?;
    first_publish(&config(), &state, &reader(&shared), &tenant_scope(TENANT)?).await?;
    let page = served(&state)?;
    assert!(!page.json.contains("Website down"));
    assert!(page.json.contains("unknown") && !page.json.contains("operational"));
    assert!(page.html.contains("Website"));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn another_tenants_incidents_never_appear_and_every_read_is_scoped() -> TestResult {
    let (state, _clock) = state_with(PageSettings::default());
    let shared = shared_with(vec![incident(OTHER_TENANT, OTHER_TITLE), incident(TENANT, "Mine")]);
    let read = reader(&shared);
    let scope = tenant_scope(TENANT)?;
    first_publish(&config(), &state, &read, &scope).await?;
    publisher(&config(), &state, &read, &scope, 1).await;
    let page = served(&state)?;
    assert!(page.json.contains("Mine"));
    assert!(!page.json.contains(OTHER_TITLE) && !page.html.contains(OTHER_TITLE));
    let seen = shared.lock().map_err(|_poisoned| "lock")?.seen.clone();
    assert_eq!(seen.len(), TWO_READS);
    assert!(seen.iter().all(|tenant| tenant == TENANT));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_reader_that_leaks_another_tenant_cannot_change_the_page() -> TestResult {
    let (state, _clock) = state_with(PageSettings::default());
    let shared = shared_with(vec![incident(TENANT, "Mine")]);
    let read = reader(&shared);
    let scope = tenant_scope(TENANT)?;
    first_publish(&config(), &state, &read, &scope).await?;
    let before = served(&state)?;
    change(&shared, |fake| {
        fake.leak = true;
        fake.incidents.push(incident(OTHER_TENANT, OTHER_TITLE));
    })?;
    tick(&config(), &state, &read, &scope).await;
    assert_eq!(*served(&state)?, *before);
    assert!(!before.json.contains(OTHER_TITLE));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn internal_notes_never_reach_the_outputs_and_titles_are_escaped() -> TestResult {
    let (state, _clock) = state_with(PageSettings::default());
    let shared = shared_with(vec![incident(TENANT, "<script>alert(1)</script>")]);
    first_publish(&config(), &state, &reader(&shared), &tenant_scope(TENANT)?).await?;
    let page = served(&state)?;
    [&page.json, &page.html].iter().for_each(|text| {
        assert!(!text.contains("SECRET") && !text.contains("10.0.0.5") && !text.contains("alice") && !text.contains("asset-1"));
    });
    assert!(!page.html.contains("<script>"));
    assert!(page.html.contains("&lt;script&gt;"));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_reload_of_the_interval_applies_at_the_next_tick() -> TestResult {
    let (state, _clock) = state_with(interval_settings(INTERVAL));
    let shared = shared_with(Vec::new());
    let read = reader(&shared);
    let scope = tenant_scope(TENANT)?;
    let started = Instant::now();
    publisher(&config(), &state, &read, &scope, 1).await;
    assert_eq!(started.elapsed(), Duration::from_secs(INTERVAL));
    state.settings.store(Arc::new(interval_settings(FAST_INTERVAL)));
    let restarted = Instant::now();
    publisher(&config(), &state, &read, &scope, 1).await;
    assert_eq!(restarted.elapsed(), Duration::from_secs(FAST_INTERVAL));
    assert_eq!(state.publish_skipped.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn ticks_covered_by_a_slow_read_are_counted_and_the_read_never_overlaps() -> TestResult {
    let (state, _clock) = state_with(interval_settings(FAST_INTERVAL));
    let shared = shared_with(vec![incident(TENANT, "Slow")]);
    change(&shared, |fake| fake.delay_seconds = SLOW_READ_SECONDS)?;
    let started = Instant::now();
    publisher(&config(), &state, &reader(&shared), &tenant_scope(TENANT)?, 1).await;
    assert_eq!(started.elapsed(), Duration::from_secs(FAST_INTERVAL + SLOW_READ_SECONDS));
    assert_eq!(state.publish_skipped.load(Ordering::SeqCst), SKIPPED_BY_SLOW_READ);
    assert_eq!(shared.lock().map_err(|_poisoned| "lock")?.seen.len(), 1);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_read_that_never_answers_hits_the_deadline_and_keeps_the_page() -> TestResult {
    let _listener = listen();
    let (state, _clock) = state_with(PageSettings::default());
    let shared = shared_with(vec![incident(TENANT, "Kept")]);
    let read = reader(&shared);
    let scope = tenant_scope(TENANT)?;
    first_publish(&config(), &state, &read, &scope).await?;
    let before = served(&state)?;
    change(&shared, |fake| fake.never = true)?;
    let started = Instant::now();
    tick(&config(), &state, &read, &scope).await;
    assert_eq!(started.elapsed(), READ_DEADLINE);
    assert_eq!(*served(&state)?, *before);
    let refused = fetch(&read, &scope, Duration::from_secs(1)).await;
    assert!(matches!(refused, Err(StoreError::ReadTimeout)));
    Ok(())
}


#[test]
fn error_classes_are_fixed_labels() -> TestResult {
    let config_error = core_config::load::load_file::<PageSettings>(Path::new("/nonexistent/settings.yaml"))
        .err()
        .ok_or("loaded")?;
    assert_eq!(error_class(&StoreError::ReadTimeout), "timeout");
    assert_eq!(error_class(&StoreError::Pg(PgError::InvalidTenant)), "database");
    assert_eq!(error_class(&StoreError::Config(config_error)), "config");
    assert_eq!(error_class(&StoreError::Conflict), "rows");
    Ok(())
}


#[test]
fn the_publish_interval_is_bounded() -> TestResult {
    assert!(validate_settings(&interval_settings(FAST_INTERVAL)).is_ok());
    assert!(validate_settings(&interval_settings(TOO_SLOW_INTERVAL - 1)).is_ok());
    assert!(validate_settings(&interval_settings(TOO_FAST_INTERVAL)).is_err());
    assert!(validate_settings(&interval_settings(TOO_SLOW_INTERVAL)).is_err());
    assert_eq!(PageSettings::default().publish_interval_seconds, INTERVAL);
    Ok(())
}


const BIG_MESSAGE_BYTES: usize = 2000;


const BIG_UPDATES: i64 = 100;


const BIG_RESOLVED: i64 = 10;


const MANY_UNRESOLVED: i64 = 20;


const FEW_UNRESOLVED: i64 = 3;


fn big_incident(title: &str, started_at: i64, resolved: bool) -> IncidentInput {
    let mut base = incident(TENANT, title);
    base.started_at = started_at;
    base.resolved_at = resolved.then_some(started_at + 1);
    base.updates = (0..BIG_UPDATES)
        .map(|at| IncidentUpdateInput {
            at,
            message: "m".repeat(BIG_MESSAGE_BYTES),
            internal_note: SECRET_NOTE.to_owned(),
        })
        .collect();
    base
}


fn resolved_set() -> Vec<IncidentInput> {
    (0..BIG_RESOLVED)
        .map(|number| big_incident(&format!("resolved-{number:02}"), number, true))
        .collect()
}


#[tokio::test(start_paused = true)]
async fn an_oversized_read_is_fitted_unresolved_first_with_a_visible_count_on_a_running_server_and_a_fresh_start() -> TestResult {
    let _listener = listen();
    let (state, _clock) = state_with(PageSettings::default());
    let mut rows = resolved_set();
    rows.push(big_incident("unresolved-old", -1, false));
    let shared = shared_with(rows);
    let read = reader(&shared);
    let scope = tenant_scope(TENANT)?;
    first_publish(&config(), &state, &read, &scope).await?;
    let fresh = served(&state)?;
    assert!(fresh.json.contains("unresolved-old") && fresh.json.contains("resolved-09"));
    assert!(!fresh.json.contains("resolved-00"));
    assert!(fresh.json.contains("\"omitted_incidents\":") && fresh.html.contains("older incidents not shown"));
    change(&shared, |fake| {
        fake.incidents.push(big_incident("unresolved-new", BIG_RESOLVED + 1, false))
    })?;
    publisher(&config(), &state, &read, &scope, 1).await;
    let running = served(&state)?;
    assert_ne!(running.etag, fresh.etag);
    assert!(running.json.contains("unresolved-new") && running.json.contains("unresolved-old"));
    assert!(running.html.contains("older incidents not shown"));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn unresolved_incidents_are_never_dropped_before_resolved_ones() -> TestResult {
    let (state, _clock) = state_with(PageSettings::default());
    let mut rows = resolved_set();
    rows.extend((0..FEW_UNRESOLVED).map(|number| big_incident(&format!("open-{number:02}"), -number - 1, false)));
    let shared = shared_with(rows);
    first_publish(&config(), &state, &reader(&shared), &tenant_scope(TENANT)?).await?;
    let page = served(&state)?;
    assert!((0..FEW_UNRESOLVED).all(|number| page.json.contains(&format!("open-{number:02}"))));
    assert!(!page.json.contains("resolved-00") && page.json.contains("resolved-09"));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn when_nothing_fits_the_empty_page_states_the_count() -> TestResult {
    let _listener = listen();
    let (state, _clock) = state_with(PageSettings::default());
    let rows = (0..MANY_UNRESOLVED)
        .map(|number| big_incident(&format!("open-{number:02}"), number, false))
        .collect();
    let shared = shared_with(rows);
    first_publish(&config(), &state, &reader(&shared), &tenant_scope(TENANT)?).await?;
    let page = served(&state)?;
    assert!(!page.json.contains("open-") && page.json.contains("\"omitted_incidents\":20"));
    Ok(())
}


const HIDDEN_RESOLVED: usize = 250;


const OMITTED: usize = 5;


const RENDERS: u32 = 8;


const HIDDEN_ONGOING: usize = 7;


#[tokio::test(start_paused = true)]
async fn rows_beyond_the_read_limit_are_counted_in_the_omitted_totals() -> TestResult {
    let _listener = listen();
    let (state, _clock) = state_with(PageSettings::default());
    let shared = shared_with(vec![incident(TENANT, "Website down"), big_incident("resolved-old", 1, true)]);
    change(&shared, |fake| fake.hidden = HIDDEN_RESOLVED)?;
    first_publish(&config(), &state, &reader(&shared), &tenant_scope(TENANT)?).await?;
    let page = served(&state)?;
    assert!(page.json.contains("Website down") && page.json.contains("\"omitted_incidents\":250"));
    assert!(!page.json.contains("omitted_ongoing") && page.html.contains("250 older incidents not shown."));
    change(&shared, |fake| fake.hidden_ongoing = HIDDEN_ONGOING)?;
    tick(&config(), &state, &reader(&shared), &tenant_scope(TENANT)?).await;
    let ongoing = served(&state)?;
    assert!(ongoing.json.contains("\"omitted_ongoing\":7"));
    assert!(ongoing.html.contains("250 incidents not shown, 7 of them ongoing."));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_fit_counts_ongoing_incidents_it_had_to_drop() -> TestResult {
    let _listener = listen();
    let (state, _clock) = state_with(PageSettings::default());
    let rows: Vec<IncidentInput> = (0..MANY_UNRESOLVED)
        .map(|number| big_incident(&format!("open-{number:02}"), number, false))
        .collect();
    let shared = shared_with(rows);
    change(&shared, |fake| {
        fake.hidden = HIDDEN_ONGOING;
        fake.hidden_ongoing = HIDDEN_ONGOING;
    })?;
    first_publish(&config(), &state, &reader(&shared), &tenant_scope(TENANT)?).await?;
    let page = served(&state)?;
    assert!(page.html.contains("27 incidents not shown, 27 of them ongoing."));
    assert!(page.json.contains("\"omitted_incidents\":27") && page.json.contains("\"omitted_ongoing\":27"));
    Ok(())
}


#[test]
fn the_oversize_is_reported_once_per_change_and_the_renders_per_tick_are_bounded() -> TestResult {
    let (state, _clock) = state_with(PageSettings::default());
    let none = (0, 0);
    let some = (OMITTED, 1);
    let more_ongoing = (OMITTED, 1 + 1);
    let more = (OMITTED + 1, 1 + 1);
    assert!(!omission_changed(&state, none));
    assert!(omission_changed(&state, some));
    assert!(!omission_changed(&state, some));
    assert!(omission_changed(&state, more_ongoing));
    assert!(omission_changed(&state, more));
    assert!(!omission_changed(&state, none));
    assert!(omission_changed(&state, more_ongoing));
    assert_eq!(MAX_RENDERS_PER_TICK, RENDERS);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_render_error_never_stops_the_first_publish_and_keeps_the_page_afterwards() -> TestResult {
    let _listener = listen();
    let (state, _clock) = state_with(PageSettings::default());
    let shared = shared_with(vec![incident(TENANT, &"t".repeat(BIG_MESSAGE_BYTES + BIG_MESSAGE_BYTES))]);
    let read = reader(&shared);
    let scope = tenant_scope(TENANT)?;
    first_publish(&config(), &state, &read, &scope).await?;
    let page = served(&state)?;
    assert!(!page.json.contains("tttt") && page.json.contains("unknown"));
    change(&shared, |fake| {
        fake.incidents.clear();
        fake.incidents.push(incident(TENANT, "Good"));
    })?;
    tick(&config(), &state, &read, &scope).await;
    let good = served(&state)?;
    assert!(good.json.contains("Good"));
    change(&shared, |fake| {
        fake.incidents.clear();
        fake.incidents.push(incident(TENANT, &"t".repeat(BIG_MESSAGE_BYTES + BIG_MESSAGE_BYTES)));
    })?;
    tick(&config(), &state, &read, &scope).await;
    assert_eq!(*served(&state)?, *good);
    assert_eq!(render_class(&StatusPageError::TenantMismatch), "tenant");
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_page_config_that_cannot_render_still_fails_the_first_publish() -> TestResult {
    let (state, _clock) = state_with(PageSettings::default());
    let shared = shared_with(Vec::new());
    let mut broken = config();
    broken.title = "t".repeat(BIG_MESSAGE_BYTES + BIG_MESSAGE_BYTES);
    let refused = first_publish(&broken, &state, &reader(&shared), &tenant_scope(TENANT)?).await;
    assert!(refused.is_err());
    assert!(state.snapshot.load_full().is_none());
    Ok(())
}


fn files(dir: &Path, page: &str, with_pg: bool) -> Result<AppFile, std::io::Error> {
    fs::write(dir.join("page.yaml"), page)?;
    fs::write(dir.join("settings.yaml"), "burst: 30\n")?;
    Ok(AppFile {
        page_file: dir.join("page.yaml"),
        settings_file: dir.join("settings.yaml"),
        audit_file: dir.join("audit.log"),
        pg_file: with_pg.then(|| dir.join("pg.yaml")),
    })
}


#[tokio::test]
async fn the_server_serves_the_store_page_before_accepting_and_stops_the_publisher() -> TestResult {
    let dir = tempdir()?;
    let file = files(dir.path(), PAGE, true)?;
    let shared = shared_with(vec![incident(TENANT, "From the store"), incident(OTHER_TENANT, OTHER_TITLE)]);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = oneshot::channel::<()>();
    let running = tokio::spawn(run_app_with(
        file,
        listener,
        Box::pin(async {
            stopped.await.inspect_err(|error| tracing::warn!(%error, "stop signal dropped")).ok();
        }),
        Some(reader(&shared)),
    ));
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(b"GET /status.json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    let text = String::from_utf8(bytes)?;
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("From the store") && !text.contains(OTHER_TITLE) && !text.contains("Sample incident"));
    assert!(text.contains("unknown") && !text.contains("operational"));
    stop.send(()).map_err(|()| "server gone")?;
    running.await??;
    Ok(())
}


#[tokio::test]
async fn pg_file_and_the_reader_must_come_together_and_the_tenant_must_be_valid() -> TestResult {
    let dir = tempdir()?;
    let shared = shared_with(Vec::new());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let without_reader = run_app_with(files(dir.path(), PAGE, true)?, listener, Box::pin(std::future::ready(())), None).await;
    assert!(matches!(without_reader, Err(StatusPageError::ReaderMismatch)));
    let other = TcpListener::bind("127.0.0.1:0").await?;
    let without_file = run_app_with(
        files(dir.path(), PAGE, false)?,
        other,
        Box::pin(std::future::ready(())),
        Some(reader(&shared)),
    )
    .await;
    assert!(matches!(without_file, Err(StatusPageError::ReaderMismatch)));
    let third = TcpListener::bind("127.0.0.1:0").await?;
    let bad = run_app_with(
        files(dir.path(), BAD_TENANT_PAGE, true)?,
        third,
        Box::pin(std::future::ready(())),
        Some(reader(&shared)),
    )
    .await;
    assert!(matches!(bad, Err(StatusPageError::Pg(_))));
    assert!(shared.lock().map_err(|_poisoned| "lock")?.seen.is_empty());
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn an_incident_on_a_service_no_component_declares_is_counted_not_dropped_silently() -> TestResult {
    let _listener = listen();
    let (state, _clock) = state_with(PageSettings::default());
    let mut other = incident(TENANT, "Undeclared outage");
    other.service = "svc-unlisted".to_owned();
    let shared = shared_with(vec![incident(TENANT, "Website down"), other]);
    first_publish(&config(), &state, &reader(&shared), &tenant_scope(TENANT)?).await?;
    let page = served(&state)?;
    assert!(page.json.contains("Website down") && !page.json.contains("Undeclared outage") && !page.json.contains("svc-unlisted"));
    assert!(page.json.contains("\"omitted_incidents\":1") && page.json.contains("\"omitted_ongoing\":1"));
    assert!(page.json.contains("\"omitted_undeclared\":1"));
    assert!(page.html.contains("1 of them on services this page does not list."));
    Ok(())
}


#[test]
fn the_omission_reason_names_size_the_read_limit_or_undeclared_services() -> TestResult {
    assert_eq!(omission_reason(true, 1), "size");
    assert_eq!(omission_reason(false, 1), "read_limit");
    assert_eq!(omission_reason(false, 0), "undeclared");
    let read_limit = PublishedRead {
        incidents: vec![incident(TENANT, "One")],
        total: HIDDEN_RESOLVED,
        ongoing: 1,
    };
    let (_first, omitted) = fit_page(&config(), &read_limit)?;
    assert_eq!((omitted.all, omitted.undeclared, omitted.reason), (HIDDEN_RESOLVED - 1, 0, "read_limit"));
    let sized = PublishedRead {
        incidents: resolved_set(),
        total: resolved_set().len(),
        ongoing: 0,
    };
    let (_second, cut) = fit_page(&config(), &sized)?;
    assert!(cut.all > 0 && cut.reason == "size");
    let mut other = incident(TENANT, "Other");
    other.service = "svc-unlisted".to_owned();
    let hidden = PublishedRead {
        incidents: vec![other],
        total: 1,
        ongoing: 1,
    };
    let (_third, unlisted) = fit_page(&config(), &hidden)?;
    assert_eq!(
        (unlisted.all, unlisted.ongoing, unlisted.undeclared, unlisted.reason),
        (1, 1, 1, "undeclared")
    );
    Ok(())
}
