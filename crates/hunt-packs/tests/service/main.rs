mod clock;
mod settings;
mod types;


use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_config::reload::{current_config, ReloadContext, ReloadEngine};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use hunt_packs::clock::Reading;
use hunt_packs::model::HuntPack;
use hunt_packs::packs::{load_packs_partial, MAX_ENTRIES};
use hunt_packs::run::{HuntOutcome, RunError};
use hunt_packs::schedule::due_runs;
use hunt_packs::service::{reload_round, run_service, settings_digest, tick_round, ServiceReport, SettingsSource};
use hunt_packs::settings::{open_hunt, HuntSettings};
use hunt_packs::store::{Param, GET_SQL, SET_SQL};
use hunt_packs::tick::{Hooks, DEFAULT_MAX_TENANTS};
use hunt_packs::types::SleepFuture;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::future::{pending, ready, Ready};
use std::io;
use std::path::Path;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::watch;
use types::{Audited, OnSleep, RunLog, Store, TestResult};


const HOUR: i64 = 3_600;


const DAY: i64 = 86_400;


const START: i64 = 1_641_600_000 + 5 * HOUR + 10;


const TICK: u64 = 10;


const SLOWER: u64 = 20;


const TOO_FAST: u64 = 5;


const ROUNDS: u64 = 3;


const FOUR: u64 = 4;


const TWO: u64 = 2;


const TWO_SIZE: usize = 2;


const ROUNDS_SIZE: usize = 3;


const FIRST_CALL: usize = 0;


const TWO_STEP: i64 = 2;


const SIX: u64 = 6;


const FIVE: u64 = 5;


const OTHER_INVALID: u64 = 6;


const THIRD_CALL: usize = 3;


const PACK_TEXT: &str = "packs:
  - id: p1
    title: T
    hypothesis: H
    technique: T1059
    source: clickhouse
    query: SELECT 1 FROM events WHERE tenant = {tenant:String} AND t >= {window_start:DateTime64(3)} AND t < {window_end:DateTime64(3)}
    schedule_seconds: 3600
    window_seconds: 3600
    cost:
      max_rows: 1
      max_seconds: 1
      max_bytes_read: 1
    baseline:
      max_matches: 0
";


pub struct Rig {
    pub dir: TempDir,
    pub engine: ReloadEngine<HuntSettings>,
    pub wall: Rc<Cell<i64>>,
    pub mono: Rc<Cell<i64>>,
    pub log: RunLog,
    pub audited: Audited,
    pub errors: Rc<RefCell<Vec<String>>>,
    pub stop_tx: watch::Sender<bool>,
    pub stop_rx: watch::Receiver<bool>,
}


fn hunt_text(dir: &Path, pg: &str, tick_seconds: u64, tenants: &str) -> String {
    format!(
        "pg_settings: {pg}\nclickhouse_settings: /nonexistent/ch.yaml\npacks_dir: {}/packs\ntenants: {tenants}\ntick_seconds: {tick_seconds}\n",
        dir.display()
    )
}


fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


fn rig() -> Result<Rig, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("packs"))?;
    fs::write(dir.path().join("packs/good.yaml"), PACK_TEXT)?;
    let file = dir.path().join("hunt.yaml");
    fs::write(&file, hunt_text(dir.path(), "/nonexistent/pg.yaml", TICK, "[a, b]"))?;
    let audited: Audited = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&audited);
    let log = genesis_log(io::sink());
    let context = ReloadContext {
        actor_id: "hunt".to_owned(),
        tenant: "example".to_owned(),
        module: "hunt-packs".to_owned(),
        target: "hunt.yaml".to_owned(),
        request_id: "hunt-reload".to_owned(),
    };
    let engine = open_hunt(
        file,
        Box::new(move |entry| {
            sink.lock().map_err(|_| AuditError::LogPoisoned)?.push(format!("{:?}", entry.outcome));
            append(&log, entry)
        }),
        context,
    )?;
    let (stop_tx, stop_rx) = watch::channel(false);
    Ok(Rig {
        dir,
        engine,
        wall: Rc::new(Cell::new(START)),
        mono: Rc::new(Cell::new(0)),
        log: Rc::new(RefCell::new(Vec::new())),
        audited,
        errors: Rc::new(RefCell::new(Vec::new())),
        stop_tx,
        stop_rx,
    })
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
        _ => Err(PgError::InvalidTenant),
    }
}


fn exec_over(store: &Store) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<Result<Vec<i64>, PgError>> + '_ {
    |scope, sql, params| ready(answer(store, scope, sql, &params))
}


async fn drive(rig: &Rig, max_ticks: u64, hang: bool, on_sleep: &mut OnSleep<'_>) -> Result<ServiceReport, Box<dyn Error>> {
    let store: Store = RefCell::new(HashMap::new());
    let mut exec = exec_over(&store);
    let shared = Rc::clone(&rig.log);
    let mut runner = move |pack: &HuntPack, tenant: &str, end: i64| -> Result<HuntOutcome, RunError> {
        shared.borrow_mut().push((tenant.to_owned(), pack.id.clone(), end));
        Ok(HuntOutcome { matches: 0, finding: false })
    };
    let mut hooks = Hooks {
        run: &mut runner,
        due: due_runs,
    };
    let mut clock = || Reading {
        wall: rig.wall.get(),
        mono: rig.mono.get(),
    };
    let calls = Cell::new(FIRST_CALL);
    let mut sleep = |seconds: u64| -> SleepFuture {
        if let Err(error) = on_sleep(calls.get(), rig) {
            rig.errors.borrow_mut().push(error.to_string());
        }
        calls.set(calls.get() + 1);
        let step = i64::try_from(seconds).unwrap_or(0);
        rig.wall.set(rig.wall.get() + step);
        rig.mono.set(rig.mono.get() + step);
        if hang || *rig.stop_tx.borrow() {
            Box::pin(pending())
        } else {
            Box::pin(ready(()))
        }
    };
    let mut stop = rig.stop_rx.clone();
    let hunt_file = rig.dir.path().join("hunt.yaml");
    let source = SettingsSource {
        engine: &rig.engine,
        path: &hunt_file,
    };
    let report = run_service(&source, &mut clock, &mut sleep, &mut stop, max_ticks, &mut exec, &mut hooks).await;
    let failures = rig.errors.borrow().clone();
    failures.is_empty().then_some(report).ok_or_else(|| failures.join(", ").into())
}


fn nothing(_index: usize, _rig: &Rig) -> io::Result<()> {
    Ok(())
}


fn write_hunt(rig: &Rig, pg: &str, tick_seconds: u64, tenants: &str) -> io::Result<()> {
    replace_file(&rig.dir.path().join("hunt.yaml"), &hunt_text(rig.dir.path(), pg, tick_seconds, tenants))
}


fn skip_an_hour(rig: &Rig) {
    rig.wall.set(rig.wall.get() + HOUR);
    rig.mono.set(rig.mono.get() + HOUR);
}


fn denied(rig: &Rig) -> Result<usize, Box<dyn Error>> {
    Ok(rig
        .audited
        .lock()
        .map_err(|_| "poisoned")?
        .iter()
        .filter(|outcome| outcome.as_str() == "Denied")
        .count())
}


fn tick_step() -> i64 {
    i64::try_from(TICK).unwrap_or(0)
}


#[tokio::test]
async fn rounds_tick_once_each_and_max_ticks_ends_the_loop() -> TestResult {
    let rig = rig()?;
    let report = drive(&rig, ROUNDS, false, &mut nothing).await?;
    assert_eq!(
        (report.rounds, report.ticks, report.runs, report.clock_jumps),
        (ROUNDS, ROUNDS, TWO_SIZE, 0)
    );
    assert_eq!((report.reloads_applied, report.reloads_refused), (0, 0));
    Ok(())
}


#[tokio::test]
async fn a_stop_during_the_sleep_ends_the_loop_before_the_next_tick() -> TestResult {
    let rig = rig()?;
    let report = drive(&rig, FOUR, false, &mut |_index, held| held.stop_tx.send(true).map_err(io::Error::other)).await?;
    assert_eq!((report.rounds, report.ticks), (1, 1));
    Ok(())
}


#[tokio::test]
async fn a_dropped_stop_sender_ends_the_loop() -> TestResult {
    let mut rig = rig()?;
    let (unused, closed) = watch::channel(false);
    drop(unused);
    rig.stop_rx = closed;
    let report = drive(&rig, FOUR, true, &mut nothing).await?;
    assert_eq!(report.rounds, 1);
    Ok(())
}


#[tokio::test]
async fn a_stop_already_set_runs_no_round() -> TestResult {
    let rig = rig()?;
    rig.stop_tx.send(true)?;
    let report = drive(&rig, FOUR, false, &mut nothing).await?;
    assert_eq!(report.rounds, 0);
    Ok(())
}


#[tokio::test]
async fn a_reload_of_the_tick_and_the_tenants_applies_at_the_next_round() -> TestResult {
    let rig = rig()?;
    let report = drive(&rig, TWO, false, &mut |index, held| {
        if index == 0 {
            write_hunt(held, "/nonexistent/pg.yaml", SLOWER, "[a]")?;
            skip_an_hour(held);
        }
        Ok(())
    })
    .await?;
    assert_eq!((report.reloads_applied, report.reloads_refused, report.ticks), (1, 0, TWO));
    let log = rig.log.borrow();
    assert_eq!(log.len(), ROUNDS_SIZE);
    assert_eq!(log.iter().filter(|entry| entry.0 == "a").count(), TWO_SIZE);
    assert_eq!(rig.wall.get(), START + HOUR + tick_step() + i64::try_from(SLOWER)?);
    Ok(())
}


#[tokio::test]
async fn an_invalid_edit_keeps_the_old_settings_and_is_audited_denied() -> TestResult {
    let rig = rig()?;
    let report = drive(&rig, TWO, false, &mut |index, held| {
        if index == 0 {
            write_hunt(held, "/nonexistent/pg.yaml", TOO_FAST, "[a]")?;
        }
        Ok(())
    })
    .await?;
    assert_eq!((report.reloads_applied, report.reloads_refused), (0, 1));
    assert_eq!(denied(&rig)?, 1);
    assert_eq!(rig.wall.get(), START + TWO_STEP * tick_step());
    Ok(())
}


#[tokio::test]
async fn an_invalid_file_left_in_place_is_audited_once_and_skipped_after() -> TestResult {
    let rig = rig()?;
    let report = drive(&rig, SIX, false, &mut |index, held| {
        if index == 0 {
            write_hunt(held, "/nonexistent/pg.yaml", TOO_FAST, "[a]")?;
        }
        Ok(())
    })
    .await?;
    assert_eq!((report.reloads_refused, report.reloads_skipped), (1, FIVE - 1));
    assert_eq!(denied(&rig)?, 1);
    Ok(())
}


#[tokio::test]
async fn a_second_invalid_edit_is_audited_again() -> TestResult {
    let rig = rig()?;
    let report = drive(&rig, SIX, false, &mut |index, held| {
        if index == 0 {
            write_hunt(held, "/nonexistent/pg.yaml", TOO_FAST, "[a]")?;
        }
        if index == THIRD_CALL {
            write_hunt(held, "/nonexistent/pg.yaml", OTHER_INVALID, "[a]")?;
        }
        Ok(())
    })
    .await?;
    assert_eq!((report.reloads_refused, report.reloads_skipped), (TWO, THIRD_CALL as u64));
    assert_eq!(denied(&rig)?, TWO_SIZE);
    Ok(())
}


#[tokio::test]
async fn invalid_then_restored_then_invalid_again_is_audited_twice() -> TestResult {
    let rig = rig()?;
    let report = drive(&rig, FIVE, false, &mut |index, held| {
        if index == 0 || index == TWO_SIZE {
            write_hunt(held, "/nonexistent/pg.yaml", TOO_FAST, "[a]")?;
        }
        if index == 1 {
            write_hunt(held, "/nonexistent/pg.yaml", TICK, "[a, b]")?;
        }
        Ok(())
    })
    .await?;
    assert_eq!((report.reloads_refused, report.reloads_skipped, report.reloads_applied), (TWO, 1, 0));
    assert_eq!(denied(&rig)?, TWO_SIZE);
    Ok(())
}


#[tokio::test]
async fn an_unreadable_file_is_never_skipped() -> TestResult {
    let rig = rig()?;
    let report = drive(&rig, FOUR, false, &mut |index, held| {
        if index == 0 {
            fs::remove_file(held.dir.path().join("hunt.yaml"))?;
        }
        Ok(())
    })
    .await?;
    assert_eq!((report.reloads_refused, report.reloads_skipped), (THIRD_CALL as u64, 0));
    assert!(settings_digest(&rig.dir.path().join("hunt.yaml")).is_err());
    Ok(())
}


#[test]
fn a_file_changed_during_the_reload_is_not_remembered_as_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("hunt.yaml");
    fs::write(&file, hunt_text(dir.path(), "/nonexistent/pg.yaml", TICK, "[a]"))?;
    let touched = file.clone();
    let text = hunt_text(dir.path(), "/nonexistent/pg.yaml", TOO_FAST, "[a]");
    let context = ReloadContext {
        actor_id: "hunt".to_owned(),
        tenant: "example".to_owned(),
        module: "hunt-packs".to_owned(),
        target: "hunt.yaml".to_owned(),
        request_id: "hunt-reload".to_owned(),
    };
    let log = genesis_log(io::sink());
    let engine = open_hunt(
        file.clone(),
        Box::new(move |entry| {
            fs::write(&touched, &text).map_err(|_| AuditError::LogPoisoned)?;
            append(&log, entry)
        }),
        context,
    )?;
    fs::write(
        &file,
        hunt_text(dir.path(), "/nonexistent/pg.yaml", OTHER_INVALID, "[a]").replace("tick_seconds: 6", "tick_seconds: 7"),
    )?;
    let mut remembered = None;
    let mut report = ServiceReport::default();
    reload_round(&engine, &file, &mut remembered, &mut report);
    assert_eq!((report.reloads_refused, remembered.is_none()), (1, true));
    reload_round(&engine, &file, &mut remembered, &mut report);
    assert_eq!((report.reloads_refused, remembered.is_some()), (TWO, true));
    reload_round(&engine, &file, &mut remembered, &mut report);
    assert_eq!((report.reloads_refused, report.reloads_skipped), (TWO, 1));
    Ok(())
}


#[tokio::test]
async fn a_pg_settings_change_is_refused_as_start_only() -> TestResult {
    let rig = rig()?;
    let report = drive(&rig, TWO, false, &mut |index, held| {
        if index == 0 {
            write_hunt(held, "/nonexistent/other.yaml", SLOWER, "[a, b]")?;
        }
        Ok(())
    })
    .await?;
    assert_eq!((report.reloads_applied, report.reloads_refused), (0, 1));
    assert_eq!(denied(&rig)?, 1);
    assert_eq!(rig.wall.get(), START + TWO_STEP * tick_step());
    Ok(())
}


#[tokio::test]
async fn a_pack_file_broken_between_rounds_refuses_only_itself() -> TestResult {
    let rig = rig()?;
    let report = drive(&rig, TWO, false, &mut |index, held| {
        if index == 0 {
            fs::write(held.dir.path().join("packs/broken.yaml"), "packs: [not a pack")?;
            skip_an_hour(held);
        }
        Ok(())
    })
    .await?;
    assert_eq!((report.refused_files, report.ticks, report.runs), (1, TWO, TWO_SIZE * TWO_SIZE));
    Ok(())
}


#[tokio::test]
async fn a_missing_packs_directory_runs_no_tick() -> TestResult {
    let rig = rig()?;
    fs::remove_dir_all(rig.dir.path().join("packs"))?;
    let report = drive(&rig, TWO, false, &mut nothing).await?;
    assert_eq!((report.pack_dir_failures, report.ticks), (TWO, 0));
    Ok(())
}


async fn jump_by(shift: i64, reverts: bool) -> Result<(ServiceReport, Vec<usize>, usize), Box<dyn Error>> {
    let rig = rig()?;
    let lengths = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&lengths);
    let report = drive(&rig, FOUR, false, &mut |index, held| {
        seen.borrow_mut().push(held.log.borrow().len());
        if index == 0 {
            held.wall.set(rig.wall.get() + shift);
        }
        if index == 1 && reverts {
            held.wall.set(rig.wall.get() - shift);
        }
        Ok(())
    })
    .await?;
    let after = rig.log.borrow().len();
    let before = lengths.borrow().clone();
    Ok((report, before, after))
}


#[tokio::test]
async fn a_forward_wall_jump_runs_nothing_for_two_rounds_then_is_accepted() -> TestResult {
    let (report, lengths, after) = jump_by(DAY, false).await?;
    assert_eq!((report.clock_jumps, report.ticks), (TWO, TWO));
    assert_eq!(
        lengths.iter().take(ROUNDS_SIZE).copied().collect::<Vec<usize>>(),
        vec![TWO_SIZE; ROUNDS_SIZE]
    );
    assert!(lengths.last().is_some_and(|last| *last > TWO_SIZE));
    assert!(after > TWO_SIZE);
    Ok(())
}


#[tokio::test]
async fn a_backward_wall_jump_runs_nothing_for_two_rounds_then_is_accepted() -> TestResult {
    let (report, lengths, after) = jump_by(-DAY, false).await?;
    assert_eq!((report.clock_jumps, report.ticks), (TWO, TWO));
    assert_eq!(lengths, vec![TWO_SIZE, TWO_SIZE, TWO_SIZE, TWO_SIZE]);
    assert_eq!(after, TWO_SIZE);
    Ok(())
}


#[tokio::test]
async fn a_jump_that_reverts_never_runs_with_the_jumped_time() -> TestResult {
    let (report, _lengths, after) = jump_by(DAY, true).await?;
    assert_eq!((report.clock_jumps, report.ticks, report.rounds), (1, ROUNDS, FOUR));
    assert_eq!(after, TWO_SIZE);
    Ok(())
}


#[tokio::test]
async fn a_tick_refused_for_its_limits_is_counted() -> TestResult {
    let rig = rig()?;
    let mut settings = (*current_config(&rig.engine)).clone();
    settings.tenants = (0..=DEFAULT_MAX_TENANTS).map(|index| format!("t{index}")).collect();
    let store: Store = RefCell::new(HashMap::new());
    let mut exec = exec_over(&store);
    let mut runner = |_pack: &HuntPack, _tenant: &str, _end: i64| -> Result<HuntOutcome, RunError> { Err(RunError::Window) };
    let mut hooks = Hooks {
        run: &mut runner,
        due: due_runs,
    };
    let mut report = ServiceReport::default();
    tick_round(&settings, START, &mut exec, &mut hooks, &mut report).await;
    assert_eq!((report.tick_failures, report.ticks), (1, 0));
    settings.tenants = vec!["a".to_owned(), "-x".to_owned()];
    tick_round(&settings, START, &mut exec, &mut hooks, &mut report).await;
    assert_eq!((report.refused_tenants, report.ticks), (1, 1));
    Ok(())
}


#[test]
#[cfg(unix)]
fn a_file_with_an_id_taken_earlier_and_a_symlink_are_refused_alone() -> TestResult {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("a.yaml"), PACK_TEXT)?;
    fs::write(dir.path().join("b.yaml"), PACK_TEXT)?;
    std::os::unix::fs::symlink(dir.path().join("a.yaml"), dir.path().join("c.yaml"))?;
    let set = load_packs_partial(dir.path())?;
    assert_eq!((set.packs.len(), set.refused), (1, TWO_SIZE));
    Ok(())
}


#[test]
fn a_directory_with_too_many_entries_is_an_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    (0..=MAX_ENTRIES).try_for_each(|index| fs::write(dir.path().join(format!("{index}.txt")), ""))?;
    assert!(load_packs_partial(dir.path()).is_err());
    Ok(())
}
