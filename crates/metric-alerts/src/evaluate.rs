use crate::model::{Condition, Direction, Rule};
use crate::state::{active_since, next_state, AlertState};
use crate::types::{Point, Timestamp};


pub const ABSENCE_INTERVALS: u64 = 3;


pub struct Level {
    pub direction: Direction,
    pub threshold: f64,
    pub clear: f64,
}


/// New alert state for `rule` over `series` at time `now`; the series may be unsorted, and no data leaves a threshold breach as it was.
pub fn evaluate(rule: &Rule, series: &[Point], previous: &AlertState, now: Timestamp) -> AlertState {
    let held = match &rule.condition {
        Condition::Absence { interval } => absence_start(series, *interval, previous, now),
        Condition::Threshold { direction, threshold, clear } => level_start(&sorted(series), &level_of(*direction, *threshold, *clear), previous),
        Condition::Rate { direction, threshold, clear } => level_start(&rates(&sorted(series)), &level_of(*direction, *threshold, *clear), previous),
    };
    next_state(previous, held, rule, now)
}


pub fn level_of(direction: Direction, threshold: f64, clear: Option<f64>) -> Level {
    Level {
        direction,
        threshold,
        clear: clear.unwrap_or(threshold),
    }
}


pub fn sorted(series: &[Point]) -> Vec<Point> {
    let mut points = series.to_vec();
    points.sort_by_key(|point| point.0);
    points
}


/// Per-second change between consecutive points, stamped with the later point; pairs sharing a timestamp are skipped.
pub fn rates(points: &[Point]) -> Vec<Point> {
    points
        .iter()
        .zip(points.iter().skip(1))
        .filter(|(earlier, later)| later.0 > earlier.0)
        .map(|(earlier, later)| (later.0, (later.1 - earlier.1) / (later.0 - earlier.0) as f64))
        .collect()
}


pub fn enters(level: &Level, value: f64) -> bool {
    match level.direction {
        Direction::Above => value > level.threshold,
        Direction::Below => value < level.threshold,
    }
}


pub fn stays(level: &Level, value: f64) -> bool {
    match level.direction {
        Direction::Above => value >= level.clear,
        Direction::Below => value <= level.clear,
    }
}


/// One sample into the breach tracker: a breach starts past the threshold and lasts until the value crosses the clear level.
pub fn step(run: Option<Timestamp>, sample: &Point, level: &Level) -> Option<Timestamp> {
    let breaching = if run.is_some() {
        stays(level, sample.1)
    } else {
        enters(level, sample.1)
    };
    breaching.then_some(run.unwrap_or(sample.0))
}


pub fn level_start(samples: &[Point], level: &Level, previous: &AlertState) -> Option<Timestamp> {
    samples.iter().fold(active_since(previous), |run, sample| step(run, sample, level))
}


/// The series is absent once `ABSENCE_INTERVALS` sampling intervals have passed after its last point.
pub fn absence_start(series: &[Point], interval: u64, previous: &AlertState, now: Timestamp) -> Option<Timestamp> {
    match series.iter().map(|point| point.0).max() {
        Some(last) => Some(last.saturating_add(ABSENCE_INTERVALS.saturating_mul(interval))).filter(|start| *start <= now),
        None => Some(active_since(previous).unwrap_or(now)),
    }
}
