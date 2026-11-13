use hunt_stats::beacon::{beaconing, median};
use hunt_stats::error::StatsError;
use hunt_stats::input::parse_timestamps;
use hunt_stats::model::{BeaconLimits, BeaconScore};


const TWO: usize = 2;


const THREE: usize = 3;


const TWICE: i64 = 2;


const THRICE: i64 = 3;


const THREE_TIMES: [i64; 3] = [1, 2, 3];


const EVEN_COUNT: [i128; 4] = [1, 2, 4, 9];


const EVEN_MEDIAN: i128 = 3;


const ODD_COUNT: [i128; 3] = [1, 2, 4];


const ODD_MEDIAN: i128 = 2;


const JITTER_MAD: i128 = 2;


const JITTER_PPM: i128 = 966_667;


const RANDOM_PPM: i128 = 113_208;


const SHORT_SERIES: usize = 6;


const LONG_SERIES: usize = 9;


const PERFECT_EVENTS: i64 = 20;


const PERIOD: i64 = 60;


const START: i64 = 1_700_000_000;


const FULL_PPM: i128 = 1_000_000;


const JITTER_INTERVALS: [i64; 9] = [55, 65, 60, 58, 62, 60, 57, 63, 60];


const RANDOM_INTERVALS: &str = include_str!("fixtures/random_intervals.txt");


fn from_intervals(intervals: &[i64]) -> Vec<i64> {
    std::iter::once(START)
        .chain(intervals.iter().scan(START, |clock, step| {
            *clock += step;
            Some(*clock)
        }))
        .collect()
}


fn run_beacon(timestamps: &[i64]) -> Result<Option<BeaconScore>, StatsError> {
    beaconing(timestamps, &BeaconLimits::default())
}


#[test]
fn perfect_series_is_fully_regular() -> Result<(), StatsError> {
    let times: Vec<i64> = (0..PERFECT_EVENTS).map(|index| START + index * PERIOD).collect();
    let found = run_beacon(&times)?;
    assert_eq!(found.as_ref().map(|value| value.regularity_ppm), Some(FULL_PPM));
    assert_eq!(found.as_ref().map(|value| value.median_interval), Some(i128::from(PERIOD)));
    assert_eq!(found.map(|value| value.mad), Some(0));
    Ok(())
}


#[test]
fn jitter_series_stays_high() -> Result<(), StatsError> {
    let found = run_beacon(&from_intervals(&JITTER_INTERVALS))?;
    assert_eq!(found.as_ref().map(|value| value.mad), Some(JITTER_MAD));
    assert_eq!(found.map(|value| value.regularity_ppm), Some(JITTER_PPM));
    Ok(())
}


#[test]
fn random_intervals_score_low() -> Result<(), StatsError> {
    let steps = parse_timestamps(RANDOM_INTERVALS)?;
    let found = run_beacon(&from_intervals(&steps))?;
    assert_eq!(found.map(|value| value.regularity_ppm), Some(RANDOM_PPM));
    Ok(())
}


#[test]
fn fewer_than_min_events_is_undefined() -> Result<(), StatsError> {
    let times = from_intervals(&[PERIOD; SHORT_SERIES]);
    assert_eq!(run_beacon(&times)?, None);
    Ok(())
}


#[test]
fn small_median_is_undefined() -> Result<(), StatsError> {
    let times: Vec<i64> = (0..PERFECT_EVENTS).map(|index| START + index).collect();
    let limits = BeaconLimits {
        min_median_seconds: TWICE,
        ..BeaconLimits::default()
    };
    assert_eq!(beaconing(&times, &limits)?, None);
    assert!(beaconing(&times, &BeaconLimits::default())?.is_some());
    let zero_floor = BeaconLimits {
        min_median_seconds: 0,
        ..BeaconLimits::default()
    };
    assert!(beaconing(&times, &zero_floor)?.is_some());
    Ok(())
}


#[test]
fn single_event_has_no_interval() -> Result<(), StatsError> {
    let limits = BeaconLimits {
        min_events: 1,
        ..BeaconLimits::default()
    };
    assert_eq!(beaconing(&[START], &limits)?, None);
    assert_eq!(beaconing(&[], &limits)?, None);
    Ok(())
}


#[test]
fn duplicates_and_order_do_not_matter() -> Result<(), StatsError> {
    let ordered = from_intervals(&[PERIOD; LONG_SERIES]);
    let mut shuffled: Vec<i64> = ordered.iter().rev().copied().collect();
    shuffled.extend(ordered.iter().copied());
    assert_eq!(run_beacon(&shuffled)?, run_beacon(&ordered)?);
    assert_eq!(run_beacon(&shuffled)?.map(|value| value.events), Some(ordered.len()));
    Ok(())
}


#[test]
fn duplicates_count_once_for_min_events() -> Result<(), StatsError> {
    let times = [
        START,
        START,
        START,
        START + PERIOD,
        START + PERIOD,
        START + TWICE * PERIOD,
        START + THRICE * PERIOD,
    ];
    assert_eq!(run_beacon(&times)?, None);
    Ok(())
}


#[test]
fn overflowing_interval_is_refused() -> Result<(), StatsError> {
    let limits = BeaconLimits {
        min_events: 1,
        ..BeaconLimits::default()
    };
    assert!(matches!(beaconing(&[i64::MIN, i64::MAX], &limits), Err(StatsError::IntervalOverflow)));
    assert!(matches!(beaconing(&[i64::MAX, 0, i64::MIN], &limits), Err(StatsError::IntervalOverflow)));
    Ok(())
}


#[test]
fn too_many_timestamps_is_refused() -> Result<(), StatsError> {
    let limits = BeaconLimits {
        max_timestamps: TWO,
        ..BeaconLimits::default()
    };
    assert!(matches!(
        beaconing(&THREE_TIMES, &limits),
        Err(StatsError::TooManyRows { count: THREE, max: TWO })
    ));
    Ok(())
}


#[test]
fn median_of_even_and_odd_counts() -> Result<(), StatsError> {
    assert_eq!(median(&EVEN_COUNT), Some(EVEN_MEDIAN));
    assert_eq!(median(&ODD_COUNT), Some(ODD_MEDIAN));
    assert_eq!(median(&[]), None);
    Ok(())
}
