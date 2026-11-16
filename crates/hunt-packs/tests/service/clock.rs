use crate::types::TestResult;
use hunt_packs::clock::{judge, ClockGuard, Reading, Verdict, CLOCK_CONFIRM_ROUNDS};


const DAY: i64 = 86_400;


const TICK: i64 = 10;


const SECOND_ROUND: i64 = 2;


const THIRD_ROUND: i64 = 3;


const TWO_ROUNDS: u32 = 2;


const START: i64 = 1_000_000;


fn at(wall: i64, mono: i64) -> Reading {
    Reading { wall, mono }
}


#[test]
fn the_first_reading_has_no_baseline_and_runs() -> TestResult {
    let mut guard = ClockGuard::default();
    assert_eq!(judge(&mut guard, at(START, 0)), Verdict::Run);
    assert_eq!(guard.baseline, Some(at(START, 0)));
    Ok(())
}


#[test]
fn a_small_skew_runs_and_moves_the_baseline() -> TestResult {
    let mut guard = ClockGuard::default();
    judge(&mut guard, at(START, 0));
    assert_eq!(judge(&mut guard, at(START + TICK + 1, TICK)), Verdict::Run);
    assert_eq!(guard.baseline, Some(at(START + TICK + 1, TICK)));
    Ok(())
}


#[test]
fn a_jump_is_confirmed_on_the_configured_round() -> TestResult {
    let mut guard = ClockGuard::default();
    judge(&mut guard, at(START, 0));
    let verdicts: Vec<Verdict> = (1..=i64::from(CLOCK_CONFIRM_ROUNDS))
        .map(|round| judge(&mut guard, at(START + DAY + round * TICK, round * TICK)))
        .collect();
    assert_eq!(
        verdicts,
        vec![
            Verdict::Jump {
                wall_delta: DAY + TICK,
                mono_delta: TICK
            },
            Verdict::Jump {
                wall_delta: DAY + SECOND_ROUND * TICK,
                mono_delta: SECOND_ROUND * TICK
            },
            Verdict::Run
        ]
    );
    assert_eq!(guard.streak, 0);
    Ok(())
}


#[test]
fn a_change_of_direction_restarts_the_count() -> TestResult {
    let mut guard = ClockGuard::default();
    judge(&mut guard, at(START, 0));
    judge(&mut guard, at(START + DAY, TICK));
    judge(&mut guard, at(START + DAY, SECOND_ROUND * TICK));
    assert_eq!(guard.streak, TWO_ROUNDS);
    judge(&mut guard, at(START - DAY, THIRD_ROUND * TICK));
    assert_eq!((guard.streak, guard.direction), (1, -1));
    Ok(())
}


#[test]
fn extreme_readings_do_not_overflow() -> TestResult {
    let mut guard = ClockGuard::default();
    judge(&mut guard, at(i64::MIN, i64::MAX));
    assert!(matches!(judge(&mut guard, at(i64::MAX, i64::MIN)), Verdict::Jump { .. }));
    Ok(())
}
