mod types;


use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use hunt_packs::model::{Baseline, Cost, HuntPack, Source};
use hunt_packs::run::{HuntOutcome, RunError};
use hunt_packs::schedule::{due_runs, RunWindow, ScheduleError};
use hunt_packs::store::{last_done, record_done, Param, FINDING_CONFLICT, FINDING_INSERTED, FINDING_SQL, GET_SQL, SET_SQL};
use hunt_packs::tick::{
    check_limits, tick, Hooks, PackStatus, RunRecord, TickError, TickLimits, DEFAULT_MAX_RUNS_PER_TICK, MAX_CLOCK_SKEW, MAX_RUNS_PER_TICK_CEILING,
    MAX_TENANTS_CEILING,
};
use hunt_packs::types::RunFn;
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::{ready, Ready};
use std::io::Write;
use std::rc::Rc;
use std::sync::{Arc, LazyLock, Mutex};
use tracing::Dispatch;
use types::{Calls, Log, Store, TestResult};


const HOUR: i64 = 3_600;


const BOUND_MATCHES: u64 = 11;


const MIDNIGHT: i64 = 1_641_600_000;


const H2: i64 = MIDNIGHT + 2 * HOUR;


const H3: i64 = MIDNIGHT + 3 * HOUR;


const H4: i64 = MIDNIGHT + 4 * HOUR;


const H5: i64 = MIDNIGHT + 5 * HOUR;


const SLACK: i64 = 10;


const YEAR_9999: i64 = 253_402_300_799;


const TWO: usize = 2;


const EVEN: i64 = 2;


const THREE: usize = 3;


const FOUR: usize = 4;


fn pack(id: &str, source: Source) -> HuntPack {
    HuntPack {
        id: id.to_owned(),
        title: "T".to_owned(),
        hypothesis: "H".to_owned(),
        technique: "T1059".to_owned(),
        source,
        query: "SELECT 1".to_owned(),
        schedule_seconds: HOUR as u64,
        window_seconds: HOUR as u64,
        cost: Cost {
            max_rows: 1,
            max_seconds: 1,
            max_bytes_read: Some(1),
        },
        baseline: Baseline { max_matches: 0 },
        tests: Vec::new(),
    }
}


fn never(_end: i64) -> bool {
    false
}


fn at_four(end: i64) -> bool {
    end == H4
}


fn always(_end: i64) -> bool {
    true
}


fn recorder(log: &Log, fails: fn(i64) -> bool) -> impl FnMut(&HuntPack, &str, i64) -> Result<HuntOutcome, RunError> {
    let shared = Rc::clone(log);
    move |pack, tenant, end| {
        shared.borrow_mut().push((tenant.to_owned(), pack.id.clone(), end));
        if fails(end) {
            Err(RunError::Malformed)
        } else {
            Ok(HuntOutcome {
                matches: 1,
                finding: (end / HOUR) % EVEN == 0,
                bound: None,
            })
        }
    }
}


fn future_due(_pack: &HuntPack, _last: Option<i64>, now: i64, _grace: i64, _max: u32) -> Result<Vec<RunWindow>, ScheduleError> {
    Ok(vec![RunWindow { start: now, end: now + 1 }])
}


fn broken_due(_pack: &HuntPack, _last: Option<i64>, _now: i64, _grace: i64, _max: u32) -> Result<Vec<RunWindow>, ScheduleError> {
    Err(ScheduleError::OutOfRange)
}


fn hooks<'a>(run: &'a mut RunFn<'a>) -> Hooks<'a> {
    Hooks { run, due: due_runs }
}


fn answer(store: &Store, scope: &TenantScope, sql: &'static str, params: &[Param]) -> Result<Vec<i64>, PgError> {
    let tenant = tenant_of(scope).to_owned();
    let mut map = store.borrow_mut();
    match (sql, params) {
        (GET_SQL, [Param::Text(pack)]) => Ok(map.get(&(tenant, pack.clone())).copied().into_iter().collect()),
        (SET_SQL, [Param::Text(pack), Param::Int(end)]) => {
            let stored = map.entry((tenant, pack.clone())).or_insert(*end);
            *stored = (*stored).max(*end);
            Ok(vec![*stored])
        }
        (FINDING_SQL, [Param::Text(pack), _, Param::Int(end), Param::Int(matches), _]) => {
            let key = (tenant, format!("{pack}@{end}"));
            let fresh = !map.contains_key(&key);
            let held = *map.entry(key).or_insert(*matches);
            Ok(match (fresh, held == *matches) {
                (true, _) => vec![FINDING_INSERTED],
                (false, true) => Vec::new(),
                (false, false) => vec![FINDING_CONFLICT],
            })
        }
        _ => Err(PgError::InvalidTenant),
    }
}


fn fake(store: &Store, calls: &Calls) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<Result<Vec<i64>, PgError>> {
    fake_failing(store, calls, "")
}


fn fake_failing(
    store: &Store,
    calls: &Calls,
    failing: &'static str,
) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<Result<Vec<i64>, PgError>> {
    let shared = Rc::clone(store);
    let counter = Rc::clone(calls);
    move |scope, sql, params| {
        *counter.borrow_mut() += 1;
        ready(if sql == failing {
            Err(PgError::LegacyRecords)
        } else {
            answer(&shared, scope, sql, &params)
        })
    }
}


fn fresh() -> (Store, Calls, Log) {
    (
        Rc::new(RefCell::new(HashMap::new())),
        Rc::new(RefCell::new(0)),
        Rc::new(RefCell::new(Vec::new())),
    )
}


fn tenants(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}


fn stored(store: &Store, tenant: &str, pack_id: &str) -> Option<i64> {
    store.borrow().get(&(tenant.to_owned(), pack_id.to_owned())).copied()
}


fn call(tenant: &str, pack_id: &str, end: i64) -> (String, String, i64) {
    (tenant.to_owned(), pack_id.to_owned(), end)
}


#[tokio::test]
async fn first_tick_runs_and_records_only_the_latest_window() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    let packs = [pack("p", Source::Clickhouse)];
    let report = tick(
        &tenants(&["a"]),
        &packs,
        H5 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    let first = report.packs.first().ok_or("no entry")?;
    assert_eq!(first.status, PackStatus::Done);
    assert_eq!(first.runs, vec![RunRecord { end: H5, finding: false }]);
    assert_eq!(first.last_end, Some(H5));
    assert_eq!(stored(&store, "a", "p"), Some(H5));
    assert_eq!(*log.borrow(), vec![call("a", "p", H5)]);
    Ok(())
}


#[tokio::test]
async fn a_catch_up_runs_every_window_oldest_first() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    record_done(&mut exec, "a", "p", H2).await?;
    let packs = [pack("p", Source::Clickhouse)];
    let report = tick(
        &tenants(&["a"]),
        &packs,
        H5 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    let ends: Vec<i64> = report.packs.iter().flat_map(|entry| entry.runs.iter().map(|item| item.end)).collect();
    assert_eq!(ends, vec![H3, H4, H5]);
    assert_eq!(*log.borrow(), vec![call("a", "p", H3), call("a", "p", H4), call("a", "p", H5)]);
    assert_eq!(last_done(&mut exec, "a", "p").await?, Some(H5));
    Ok(())
}


#[tokio::test]
async fn a_failed_window_is_not_recorded_and_is_retried() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut failing = recorder(&log, at_four);
    record_done(&mut exec, "a", "p", H2).await?;
    let packs = [pack("p", Source::Clickhouse)];
    let limits = TickLimits::default();
    let report = tick(&tenants(&["a"]), &packs, H5 + SLACK, &limits, &mut exec, &mut hooks(&mut failing)).await?;
    let first = report.packs.first().ok_or("no entry")?;
    assert!(matches!(first.status, PackStatus::RunFailed(_)));
    assert_eq!(first.runs.len(), 1);
    assert_eq!(first.attempted, TWO);
    assert_eq!(*log.borrow(), vec![call("a", "p", H3), call("a", "p", H4)]);
    assert_eq!(stored(&store, "a", "p"), Some(H3));
    log.borrow_mut().clear();
    let mut healthy = recorder(&log, never);
    let again = tick(&tenants(&["a"]), &packs, H5 + SLACK, &limits, &mut exec, &mut hooks(&mut healthy)).await?;
    let ends: Vec<i64> = again.packs.iter().flat_map(|entry| entry.runs.iter().map(|item| item.end)).collect();
    assert_eq!(ends, vec![H4, H5]);
    assert_eq!(*log.borrow(), vec![call("a", "p", H4), call("a", "p", H5)]);
    Ok(())
}


#[tokio::test]
async fn a_runner_that_always_fails_moves_no_state() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, always);
    record_done(&mut exec, "a", "p", H2).await?;
    let packs = [pack("p", Source::Clickhouse)];
    tick(
        &tenants(&["a"]),
        &packs,
        H5 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    assert_eq!(*log.borrow(), vec![call("a", "p", H3)]);
    assert_eq!(stored(&store, "a", "p"), Some(H2));
    Ok(())
}


#[tokio::test]
async fn a_poisoned_state_runs_nothing_for_that_pack_only() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    record_done(&mut exec, "a", "p", YEAR_9999).await?;
    let packs = [pack("p", Source::Clickhouse), pack("q", Source::Clickhouse)];
    let report = tick(
        &tenants(&["a", "b"]),
        &packs,
        H5 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    let poisoned = report.packs.first().ok_or("no entry")?;
    assert_eq!(poisoned.status, PackStatus::StateInFuture);
    assert!(poisoned.runs.is_empty());
    assert_eq!(*log.borrow(), vec![call("a", "q", H5), call("b", "p", H5), call("b", "q", H5)]);
    assert_eq!(stored(&store, "a", "p"), Some(YEAR_9999));
    assert_eq!(stored(&store, "a", "q"), Some(H5));
    assert_eq!(stored(&store, "b", "p"), Some(H5));
    Ok(())
}


#[tokio::test]
async fn a_state_inside_the_clock_skew_is_accepted() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    record_done(&mut exec, "a", "p", H5).await?;
    let packs = [pack("p", Source::Clickhouse)];
    let report = tick(
        &tenants(&["a"]),
        &packs,
        H5 - MAX_CLOCK_SKEW,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    assert_eq!(report.packs.first().ok_or("no entry")?.status, PackStatus::Done);
    assert!(log.borrow().is_empty());
    Ok(())
}


#[tokio::test]
async fn a_state_one_second_past_the_clock_skew_is_in_the_future() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    record_done(&mut exec, "a", "p", H5).await?;
    let packs = [pack("p", Source::Clickhouse)];
    let report = tick(
        &tenants(&["a"]),
        &packs,
        H5 - MAX_CLOCK_SKEW - 1,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    assert_eq!(report.packs.first().ok_or("no entry")?.status, PackStatus::StateInFuture);
    assert!(log.borrow().is_empty());
    assert_eq!(stored(&store, "a", "p"), Some(H5));
    Ok(())
}


#[tokio::test]
async fn a_clock_going_backwards_records_nothing_backwards() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    let packs = [pack("p", Source::Clickhouse)];
    let limits = TickLimits::default();
    tick(&tenants(&["a"]), &packs, H5 + SLACK, &limits, &mut exec, &mut hooks(&mut run)).await?;
    log.borrow_mut().clear();
    let back = tick(&tenants(&["a"]), &packs, H4 + SLACK, &limits, &mut exec, &mut hooks(&mut run)).await?;
    assert!(back.packs.iter().all(|entry| entry.runs.is_empty()));
    assert!(log.borrow().is_empty());
    assert_eq!(stored(&store, "a", "p"), Some(H5));
    Ok(())
}


#[tokio::test]
async fn an_end_after_now_is_refused_and_nothing_is_recorded() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    let packs = [pack("p", Source::Clickhouse)];
    let mut future = Hooks {
        run: &mut run,
        due: future_due,
    };
    let report = tick(&tenants(&["a"]), &packs, H5, &TickLimits::default(), &mut exec, &mut future).await?;
    let first = report.packs.first().ok_or("no entry")?;
    assert_eq!(first.status, PackStatus::FutureEnd);
    assert_eq!(first.attempted, 0);
    assert!(log.borrow().is_empty());
    assert_eq!(stored(&store, "a", "p"), None);
    Ok(())
}


#[tokio::test]
async fn a_schedule_error_stops_the_pack() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    let packs = [pack("p", Source::Clickhouse)];
    let mut broken = Hooks {
        run: &mut run,
        due: broken_due,
    };
    let report = tick(&tenants(&["a"]), &packs, H5, &TickLimits::default(), &mut exec, &mut broken).await?;
    assert!(matches!(report.packs.first().ok_or("no entry")?.status, PackStatus::ScheduleFailed(_)));
    assert!(log.borrow().is_empty());
    Ok(())
}


#[tokio::test]
async fn the_per_tick_cap_defers_the_rest() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    record_done(&mut exec, "a", "p", H2).await?;
    let packs = [pack("p", Source::Clickhouse), pack("q", Source::Clickhouse)];
    let limits = TickLimits {
        max_runs_per_tick: TWO,
        ..TickLimits::default()
    };
    let before = *calls.borrow();
    let report = tick(&tenants(&["a"]), &packs, H5 + SLACK, &limits, &mut exec, &mut hooks(&mut run)).await?;
    let first = report.packs.first().ok_or("no entry")?;
    let second = report.packs.get(1).ok_or("no second entry")?;
    assert_eq!(first.status, PackStatus::Deferred);
    assert_eq!(first.runs.len(), TWO);
    assert_eq!(second.status, PackStatus::Deferred);
    assert_eq!(second.attempted, 0);
    assert_eq!(report.deferred, TWO);
    assert_eq!(*log.borrow(), vec![call("a", "p", H3), call("a", "p", H4)]);
    assert_eq!(stored(&store, "a", "p"), Some(H4));
    assert_eq!(stored(&store, "a", "q"), None);
    assert_eq!(*calls.borrow() - before, 1 + TWO + 1);
    Ok(())
}


#[tokio::test]
async fn packs_run_in_id_order_and_osquery_is_skipped() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    let packs = [pack("b", Source::Clickhouse), pack("o", Source::Osquery), pack("a", Source::Clickhouse)];
    let report = tick(&tenants(&["t"]), &packs, H5, &TickLimits::default(), &mut exec, &mut hooks(&mut run)).await?;
    let ids: Vec<&str> = report.packs.iter().map(|entry| entry.pack_id.as_str()).collect();
    assert_eq!(ids, vec!["a", "b"]);
    assert_eq!(report.skipped_osquery, 1);
    assert_eq!(*log.borrow(), vec![call("t", "a", H5), call("t", "b", H5)]);
    assert_eq!(stored(&store, "t", "o"), None);
    Ok(())
}


#[tokio::test]
async fn two_tenants_are_isolated() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    record_done(&mut exec, "a", "p", H4).await?;
    let packs = [pack("p", Source::Clickhouse)];
    let report = tick(
        &tenants(&["a", "b"]),
        &packs,
        H5 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    let for_b = report.packs.get(1).ok_or("no entry for b")?;
    assert_eq!(for_b.tenant, "b");
    assert_eq!(for_b.runs.len(), 1);
    assert_eq!(report.packs.first().ok_or("no entry for a")?.runs.len(), 1);
    assert_eq!(*log.borrow(), vec![call("a", "p", H5), call("b", "p", H5)]);
    assert_eq!(stored(&store, "a", "p"), Some(H5));
    assert_eq!(stored(&store, "b", "p"), Some(H5));
    Ok(())
}


#[tokio::test]
async fn tenant_floods_and_limits_are_refused_before_any_statement() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    let packs = [pack("p", Source::Clickhouse)];
    let limits = TickLimits {
        max_tenants: TWO,
        ..TickLimits::default()
    };
    let flood = tick(&tenants(&["a", "b", "c"]), &packs, H5, &limits, &mut exec, &mut hooks(&mut run)).await;
    let refused = flood.err().ok_or("accepted")?;
    assert!(matches!(refused, TickError::TooManyTenants { count: THREE, max: TWO }));
    assert_eq!(refused.to_string(), "3 tenants, at most 2 per tick");
    let wild_limits = [
        TickLimits {
            max_tenants: 0,
            ..TickLimits::default()
        },
        TickLimits {
            max_tenants: MAX_TENANTS_CEILING + 1,
            ..TickLimits::default()
        },
        TickLimits {
            max_runs_per_tick: MAX_RUNS_PER_TICK_CEILING + 1,
            ..TickLimits::default()
        },
    ];
    for wild in &wild_limits {
        let invalid = check_limits(wild, 1).err().ok_or("accepted")?;
        assert!(matches!(invalid, TickError::InvalidLimits));
        assert_eq!(invalid.to_string(), "max_tenants must be 1 to 10000 and max_runs_per_tick at most 10000");
    }
    assert!(log.borrow().is_empty());
    assert_eq!(*calls.borrow(), 0);
    assert_eq!(TickLimits::default().max_runs_per_tick, DEFAULT_MAX_RUNS_PER_TICK);
    Ok(())
}


#[tokio::test]
async fn bad_tenants_are_refused_once_before_any_statement_and_the_others_run() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    let packs = [pack("p", Source::Clickhouse)];
    let report = tick(
        &tenants(&["a", "-x", "b"]),
        &packs,
        H5,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    assert_eq!(report.refused_tenants, 1);
    assert_eq!(report.packs.len(), TWO);
    assert_eq!(*log.borrow(), vec![call("a", "p", H5), call("b", "p", H5)]);
    assert_eq!(*calls.borrow(), FOUR);
    let only_bad = tick(&tenants(&["-x"]), &packs, H5, &TickLimits::default(), &mut exec, &mut hooks(&mut run)).await?;
    assert_eq!((only_bad.refused_tenants, only_bad.packs.len()), (1, 0));
    assert_eq!(*calls.borrow(), FOUR);
    Ok(())
}


#[tokio::test]
async fn store_errors_stop_the_pack() -> TestResult {
    let packs = [pack("p", Source::Clickhouse)];
    let (store, calls, log) = fresh();
    let mut run = recorder(&log, never);
    let mut broken_read = fake_failing(&store, &calls, GET_SQL);
    let read = tick(
        &tenants(&["a"]),
        &packs,
        H5,
        &TickLimits::default(),
        &mut broken_read,
        &mut hooks(&mut run),
    )
    .await?;
    assert!(matches!(read.packs.first().ok_or("no entry")?.status, PackStatus::StoreFailed(_)));
    assert!(log.borrow().is_empty());
    let mut broken_write = fake_failing(&store, &calls, SET_SQL);
    let write = tick(
        &tenants(&["a"]),
        &packs,
        H5,
        &TickLimits::default(),
        &mut broken_write,
        &mut hooks(&mut run),
    )
    .await?;
    let first = write.packs.first().ok_or("no entry")?;
    assert!(matches!(first.status, PackStatus::StoreFailed(_)));
    assert!(first.runs.is_empty());
    assert_eq!(*log.borrow(), vec![call("a", "p", H5)]);
    assert_eq!(stored(&store, "a", "p"), None);
    Ok(())
}


fn findings_in(store: &Store) -> usize {
    store.borrow().keys().filter(|(_, key)| key.contains('@')).count()
}


#[tokio::test]
async fn a_finding_is_stored_and_the_state_advances() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    let packs = [pack("p", Source::Clickhouse)];
    let report = tick(
        &tenants(&["a"]),
        &packs,
        H4 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    assert_eq!(report.findings_failed, 0);
    assert_eq!(stored(&store, "a", &format!("p@{H4}")), Some(1));
    assert_eq!(stored(&store, "a", "p"), Some(H4));
    let quiet = tick(
        &tenants(&["b"]),
        &packs,
        H5 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    assert_eq!(quiet.packs.first().ok_or("no entry")?.status, PackStatus::Done);
    assert_eq!(findings_in(&store), 1);
    Ok(())
}


#[tokio::test]
async fn a_failed_finding_store_keeps_the_state_and_the_window_runs_again() -> TestResult {
    let (store, calls, log) = fresh();
    let mut run = recorder(&log, never);
    let packs = [pack("p", Source::Clickhouse)];
    let mut broken = fake_failing(&store, &calls, FINDING_SQL);
    let failed = tick(
        &tenants(&["a"]),
        &packs,
        H4 + SLACK,
        &TickLimits::default(),
        &mut broken,
        &mut hooks(&mut run),
    )
    .await?;
    let first = failed.packs.first().ok_or("no entry")?;
    assert!(matches!(first.status, PackStatus::FindingStoreFailed(_)));
    assert!(first.runs.is_empty());
    assert_eq!(failed.findings_failed, 1);
    assert_eq!(stored(&store, "a", "p"), None);
    assert_eq!(findings_in(&store), 0);
    let mut exec = fake(&store, &calls);
    let again = tick(
        &tenants(&["a"]),
        &packs,
        H4 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    assert_eq!(again.packs.first().ok_or("no entry")?.status, PackStatus::Done);
    assert_eq!(*log.borrow(), vec![call("a", "p", H4), call("a", "p", H4)]);
    assert_eq!(findings_in(&store), 1);
    assert_eq!(stored(&store, "a", "p"), Some(H4));
    Ok(())
}


#[tokio::test]
async fn a_replayed_window_inserts_its_finding_once() -> TestResult {
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    let packs = [pack("p", Source::Clickhouse)];
    tick(
        &tenants(&["a"]),
        &packs,
        H4 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    store.borrow_mut().remove(&("a".to_owned(), "p".to_owned()));
    tick(
        &tenants(&["a"]),
        &packs,
        H4 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    assert_eq!(log.borrow().len(), TWO);
    assert_eq!(findings_in(&store), 1);
    Ok(())
}


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


struct Sink(Arc<Mutex<Vec<u8>>>);


impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().map_err(|_| std::io::Error::other("poisoned"))?.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn huge_baseline() -> Result<HuntPack, std::num::TryFromIntError> {
    let mut big = pack("p", Source::Clickhouse);
    big.baseline.max_matches = u64::try_from(i64::MAX)? + 1;
    Ok(big)
}


#[tokio::test]
async fn a_finding_refused_for_good_records_the_window_once_and_never_reruns_it() -> TestResult {
    LazyLock::force(&ANCHOR);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&captured);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Sink(Arc::clone(&writer)))
            .finish(),
    );
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let (store, calls, log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = recorder(&log, never);
    let packs = [huge_baseline()?];
    let first = tick(
        &tenants(&["a"]),
        &packs,
        H4 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    let entry = first.packs.first().ok_or("no entry")?;
    assert_eq!(entry.status, PackStatus::Done);
    assert_eq!((entry.findings_refused, first.findings_refused, first.findings_failed), (1, 1, 0));
    assert_eq!(stored(&store, "a", "p"), Some(H4));
    assert_eq!(findings_in(&store), 0);
    let again = tick(
        &tenants(&["a"]),
        &packs,
        H4 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    assert_eq!(again.findings_refused, 0);
    assert_eq!(log.borrow().len(), 1);
    let text = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    let refusals = text.lines().filter(|line| line.contains("hunt finding refused for good")).count();
    assert_eq!(refusals, 1);
    assert!(text.contains("tenant a pack p"));
    Ok(())
}


#[tokio::test]
async fn a_bound_outcome_is_stored_under_the_bound_id_and_the_window_advances() -> TestResult {
    let (store, calls, _log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = |_pack: &HuntPack, _tenant: &str, _end: i64| -> Result<HuntOutcome, RunError> {
        Ok(HuntOutcome {
            matches: BOUND_MATCHES,
            finding: true,
            bound: Some(BOUND_MATCHES - 1),
        })
    };
    let packs = [pack("rarity.p", Source::Clickhouse)];
    let report = tick(
        &tenants(&["a"]),
        &packs,
        H4 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    assert_eq!(report.findings_failed, 0);
    assert_eq!(stored(&store, "a", &format!("rarity.p.bound@{H4}")), Some(BOUND_MATCHES as i64));
    assert_eq!(stored(&store, "a", &format!("rarity.p@{H4}")), None);
    assert_eq!(stored(&store, "a", "rarity.p"), Some(H4));
    Ok(())
}


#[tokio::test]
async fn a_finding_that_collides_with_another_hunts_is_refused_counted_and_named_never_stored() -> TestResult {
    let (store, calls, _log) = fresh();
    let mut exec = fake(&store, &calls);
    let mut run = |pack: &HuntPack, _tenant: &str, _end: i64| -> Result<HuntOutcome, RunError> {
        Ok(HuntOutcome {
            matches: if pack.id == "rarity.x" { BOUND_MATCHES } else { 1 },
            finding: true,
            bound: (pack.id == "rarity.x").then_some(BOUND_MATCHES - 1),
        })
    };
    let packs = [pack("rarity.x", Source::Clickhouse), pack("rarity.x.bound", Source::Clickhouse)];
    let report = tick(
        &tenants(&["a"]),
        &packs,
        H4 + SLACK,
        &TickLimits::default(),
        &mut exec,
        &mut hooks(&mut run),
    )
    .await?;
    assert_eq!((report.findings_refused, report.findings_failed), (1, 0));
    let second = report.packs.get(1).ok_or("no second entry")?;
    assert_eq!(
        (second.pack_id.as_str(), second.findings_refused, &second.status),
        ("rarity.x.bound", 1, &PackStatus::Done)
    );
    assert_eq!(stored(&store, "a", &format!("rarity.x.bound@{H4}")), Some(BOUND_MATCHES as i64));
    assert_eq!(stored(&store, "a", "rarity.x.bound"), Some(H4));
    Ok(())
}
