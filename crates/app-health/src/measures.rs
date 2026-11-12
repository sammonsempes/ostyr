//! Measures for the metrics pipeline.

use crate::model::{Measure, Tracking};


pub fn measures(tracking: &Tracking) -> Vec<Measure> {
    let candidates = [
        ("ntp.offset", "s", tracking.system_time_offset),
        ("ntp.frequency", "ppm", tracking.frequency),
        ("ntp.stratum", "1", tracking.stratum.map(f64::from)),
        ("ntp.root_dispersion", "s", tracking.root_dispersion),
    ];
    candidates
        .iter()
        .filter_map(|(name, unit, value)| value.map(|found| Measure { name, unit, value: found }))
        .collect()
}
