use crate::fixture::{call, fixture_with_permits, login, semaphores_of, ANALYST};
use crate::types::{Captured, TestError, TestResult};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use platform::error::PlatformError;
use platform::merge::{module_of, module_parts};
use platform::model::Module;
use platform::permits::{
    connection_demand, counted, module_cap, module_name, module_permits, module_semaphores, note_refusal, permits_of, refusal_counter,
    refusal_status, start_permits, LARGE_CAP, PLATFORM_PG_BUDGET, SMALL_CAP,
};
use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use strum::VariantArray;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::ServiceExt;
use tracing::dispatcher::DefaultGuard;
use tracing::Dispatch;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


const ALL_MODULES: &str =
    "alerts, cases, cmdb, risk, hunts, certificates, oncall, dhcp, compliance, vulnerabilities, remote_shell, posture, status, grc, attack_paths, playbooks";


const FLOODED_PATH: &str = "/grc/reports";


const ALERTS_PATH: &str = "/alerts";


const LOG_REFUSALS: u64 = 9;


const POWERS_OF_TWO_UNDER_LIMIT: usize = 4;


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


struct Sink(Arc<Mutex<Vec<u8>>>);


impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_poisoned| std::io::Error::other("poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


async fn status_of(router: &Router, path: &str, token: &str) -> Result<StatusCode, TestError> {
    Ok(call(router, "GET", path, Some(token), Body::empty()).await?.status())
}


fn hold_all(semaphore: &Arc<Semaphore>, module: Module) -> Result<OwnedSemaphorePermit, TestError> {
    Ok(Arc::clone(semaphore).try_acquire_many_owned(u32::try_from(module_cap(module))?)?)
}


fn all_modules() -> Vec<Module> {
    Module::VARIANTS.to_vec()
}


#[test]
fn the_budget_covers_every_cap_the_cancel_connection_and_the_late_close() -> TestResult {
    assert!(
        connection_demand() <= PLATFORM_PG_BUDGET,
        "{} > {PLATFORM_PG_BUDGET}",
        connection_demand()
    );
    assert_eq!(connection_demand(), PLATFORM_PG_BUDGET);
    Ok(())
}


#[test]
fn every_module_has_exactly_one_row_with_a_cap_and_a_name_that_parses_back() -> TestResult {
    let names = Module::VARIANTS.iter().map(|module| module_name(*module)).collect::<Vec<_>>();
    assert_eq!(names.join(", "), ALL_MODULES);
    for module in all_modules() {
        assert!(module_cap(module) > 0, "{module:?}");
        assert_eq!(module_of(module_name(module)), Some(module));
    }
    assert_eq!(module_cap(Module::Alerts), LARGE_CAP);
    assert_eq!(module_cap(Module::Cases), LARGE_CAP);
    assert_eq!(module_cap(Module::Grc), SMALL_CAP);
    Ok(())
}


#[test]
fn each_module_gets_its_own_semaphore_of_its_own_cap() -> TestResult {
    let permits = module_semaphores(&all_modules());
    for (module, semaphore) in &permits {
        assert_eq!(semaphore.available_permits(), module_cap(*module), "{module:?}");
        let others = permits
            .iter()
            .filter(|(other, held)| other != module && Arc::ptr_eq(held, semaphore))
            .count();
        assert_eq!(others, 0, "{module:?} shares a semaphore");
    }
    assert_eq!(module_permits(Module::Cmdb).available_permits(), module_cap(Module::Cmdb));
    assert_eq!(start_permits().available_permits(), 1);
    Ok(())
}


#[test]
fn a_selected_module_without_a_semaphore_is_a_named_error() -> TestResult {
    let permits = module_semaphores(&[Module::Alerts]);
    assert!(permits_of(&permits, Module::Alerts).is_ok());
    assert_eq!(permits_of(&permits, Module::Grc).err(), Some(PlatformError::MissingPermits));
    let missing = platform::permits::module_semaphores(&[]);
    let dir = tempfile::tempdir()?;
    let pg_file = dir.path().join("pg.yaml");
    std::fs::write(
        &pg_file,
        "host: 127.0.0.1\nport: 1\ndatabase: ostyr\nuser: ostyr\npassword_file: /run/pg.pass\nca_file: /run/ca.pem\n",
    )?;
    let module_file = dir.path().join("platform.yaml");
    std::fs::write(&module_file, crate::fixture::module_text("alerts", &pg_file))?;
    let (opened, _pg) = alerts::settings::open_pg_engine_as(&module_file, core_api::server::new_listener(), platform::merge::ACTOR)?;
    let parts = module_parts(&[Module::Alerts], &Arc::new(opened), &missing, None, None);
    assert_eq!(parts.err(), Some(PlatformError::MissingPermits));
    Ok(())
}


#[tokio::test]
async fn a_flooded_module_leaves_the_alerts_reads_reaching_their_backend() -> TestResult {
    let permits = semaphores_of(ALL_MODULES)?;
    let fx = fixture_with_permits(ALL_MODULES, &permits)?;
    let token = login(&fx.router, ANALYST).await?;
    let grc = permits_of(&permits, Module::Grc)?;
    let held = hold_all(grc, Module::Grc)?;
    assert_eq!(status_of(&fx.router, FLOODED_PATH, &token).await?, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(status_of(&fx.router, ALERTS_PATH, &token).await?, StatusCode::INTERNAL_SERVER_ERROR);
    drop(held);
    assert_eq!(status_of(&fx.router, FLOODED_PATH, &token).await?, StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}


#[tokio::test]
async fn every_module_but_alerts_flooded_at_once_still_leaves_alerts_served() -> TestResult {
    let permits = semaphores_of(ALL_MODULES)?;
    let fx = fixture_with_permits(ALL_MODULES, &permits)?;
    let token = login(&fx.router, ANALYST).await?;
    let held: Vec<_> = permits
        .iter()
        .filter(|(module, _semaphore)| *module != Module::Alerts)
        .map(|(module, semaphore)| hold_all(semaphore, *module))
        .collect::<Result<_, _>>()?;
    assert_eq!(status_of(&fx.router, FLOODED_PATH, &token).await?, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(status_of(&fx.router, "/cases", &token).await?, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(status_of(&fx.router, ALERTS_PATH, &token).await?, StatusCode::INTERNAL_SERVER_ERROR);
    drop(held);
    Ok(())
}


#[test]
fn the_refusal_status_is_the_module_reply() -> TestResult {
    assert_eq!(refusal_status(Module::Risk), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refusal_status(Module::Alerts), StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}


fn capture() -> (DefaultGuard, Captured) {
    LazyLock::force(&ANCHOR);
    let buffer: Captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .json()
            .with_writer(BoxMakeWriter::new(move || Sink(Arc::clone(&writer))))
            .finish(),
    );
    (tracing::dispatcher::set_default(&dispatch), buffer)
}


fn text_of(buffer: &Captured) -> Result<String, TestError> {
    Ok(String::from_utf8(buffer.lock().map_err(|_poisoned| "poisoned")?.clone())?)
}


#[test]
fn the_warning_fires_at_the_first_refusal_and_each_power_of_two_with_fixed_fields() -> TestResult {
    let (guard, buffer) = capture();
    let counter = refusal_counter(Module::Grc);
    let counts: Vec<u64> = (0..LOG_REFUSALS).map(|_| note_refusal(&counter)).collect();
    drop(guard);
    assert_eq!(counts, (1..=LOG_REFUSALS).collect::<Vec<_>>());
    assert_eq!(counter.refusals.load(Ordering::Relaxed), LOG_REFUSALS);
    let text = text_of(&buffer)?;
    assert_eq!(text.lines().count(), POWERS_OF_TWO_UNDER_LIMIT, "{text}");
    assert!(text.lines().all(|line| line.contains("platform module connection cap reached")));
    assert!(text.lines().all(|line| line.contains("\"module\":\"grc\"") && line.contains("\"cap\":4")));
    Ok(())
}


async fn warnings_for(module: Module, path: &str) -> Result<usize, TestError> {
    let router: Router = counted(
        Router::new()
            .route("/429", get(|| async { StatusCode::TOO_MANY_REQUESTS }))
            .route("/503", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
            .route("/200", get(|| async { StatusCode::OK })),
        module,
    );
    let (guard, buffer) = capture();
    let response = router.oneshot(Request::builder().uri(path).body(Body::empty())?).await?;
    drop(guard);
    assert_eq!(response.status().as_u16().to_string(), path.trim_start_matches('/'));
    Ok(text_of(&buffer)?.lines().count())
}


#[tokio::test]
async fn the_layer_counts_only_the_module_refusal_status() -> TestResult {
    assert_eq!(warnings_for(Module::Grc, "/429").await?, 1);
    assert_eq!(warnings_for(Module::Grc, "/503").await?, 0);
    assert_eq!(warnings_for(Module::Grc, "/200").await?, 0);
    assert_eq!(warnings_for(Module::Risk, "/503").await?, 1);
    assert_eq!(warnings_for(Module::Risk, "/429").await?, 0);
    Ok(())
}


#[test]
fn the_detached_read_pool_is_not_smaller_than_the_pg_demand() -> TestResult {
    assert!(usize::from(core_api::state::MAX_DETACHED_READS) >= connection_demand());
    assert_eq!(
        core_api::state::MAX_DETACHED_READS_PER_SOURCE.cmp(&core_api::config::MAX_CONNECTIONS_PER_SOURCE),
        std::cmp::Ordering::Less
    );
    Ok(())
}
