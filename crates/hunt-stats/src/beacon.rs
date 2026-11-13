use crate::error::StatsError;
use crate::model::{BeaconLimits, BeaconScore};


pub const PPM: i128 = 1_000_000;


const HALF: usize = 2;


const HALF_VALUE: i128 = 2;


/// Median rounded down; the two middle values are averaged on an even count.
pub fn median(sorted: &[i128]) -> Option<i128> {
    let low = sorted.get(sorted.len().saturating_sub(1) / HALF)?;
    let high = sorted.get(sorted.len() / HALF)?;
    Some((low + high) / HALF_VALUE)
}


/// Regularity of the inter-arrival times of one pair: 1 000 000 minus MAD over median, in ppm.
pub fn beaconing(timestamps: &[i64], limits: &BeaconLimits) -> Result<Option<BeaconScore>, StatsError> {
    if timestamps.len() > limits.max_timestamps {
        Err(StatsError::TooManyRows {
            count: timestamps.len(),
            max: limits.max_timestamps,
        })
    } else {
        let mut sorted = timestamps.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let intervals = sorted
            .iter()
            .zip(sorted.iter().skip(1))
            .map(|(first, second)| second.checked_sub(*first).map(i128::from))
            .collect::<Option<Vec<i128>>>()
            .ok_or(StatsError::IntervalOverflow)?;
        Ok(score_intervals(sorted.len(), intervals, limits))
    }
}


/// Score over sorted-or-not intervals; `None` below `min_events` or when the median is under `min_median_seconds`.
pub fn score_intervals(events: usize, mut intervals: Vec<i128>, limits: &BeaconLimits) -> Option<BeaconScore> {
    intervals.sort_unstable();
    let floor = i128::from(limits.min_median_seconds.max(1));
    median(&intervals)
        .filter(|middle| events >= limits.min_events && *middle >= floor)
        .and_then(|middle| {
            let mut deviations: Vec<i128> = intervals.iter().map(|interval| (interval - middle).abs()).collect();
            deviations.sort_unstable();
            median(&deviations).map(|mad| BeaconScore {
                events,
                median_interval: middle,
                mad,
                regularity_ppm: PPM - (mad * PPM / middle).min(PPM),
            })
        })
}
