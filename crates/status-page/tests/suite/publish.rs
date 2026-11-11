use crate::harness::{state_with, TENANT};
use crate::types::TestResult;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use status_page::app::{run_app_with, AppFile};
use status_page::error::{StatusPageError, StoreError};
use status_page::model::{ComponentConfig, IncidentInput, PageConfig, PageSettings, Snapshot};
use status_page::publish::{error_class, fetch, first_publish, publisher, tick, READ_DEADLINE};
use status_page::settings::validate_settings;
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
                Ok(rows)
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
