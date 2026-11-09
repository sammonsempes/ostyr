use crate::evaluate::sorted;
use crate::types::{Point, Timestamp};


const ZERO: f64 = 0.0;


#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fit {
    pub slope: f64,
    pub intercept: f64,
    pub confidence: f64,
}


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Forecast {
    TooFewPoints,
    NotGrowing,
    AlreadyReached,
    Projected { at: Timestamp, confidence: f64 },
}


/// Points of `series` in `[now - window, now]`, sorted.
pub fn window_points(series: &[Point], window: u64, now: Timestamp) -> Vec<Point> {
    let start = now.saturating_sub(window);
    sorted(
        &series
            .iter()
            .filter(|point| point.0 >= start && point.0 <= now)
            .copied()
            .collect::<Vec<Point>>(),
    )
}


/// Least-squares line through `(seconds, value)` points, with `confidence` the coefficient of determination; `None` when it is not a growing line.
pub fn fit(points: &[Point]) -> Option<Fit> {
    let count = points.len() as f64;
    let mean_x = points.iter().map(|point| point.0 as f64).sum::<f64>() / count;
    let mean_y = points.iter().map(|point| point.1).sum::<f64>() / count;
    let (sxx, sxy, syy) = points.iter().fold((ZERO, ZERO, ZERO), |(sxx, sxy, syy), point| {
        let dx = point.0 as f64 - mean_x;
        let dy = point.1 - mean_y;
        (sxx + dx * dx, sxy + dx * dy, syy + dy * dy)
    });
    let slope = sxy / sxx;
    (sxx > ZERO && syy > ZERO && slope > ZERO && slope.is_finite()).then(|| Fit {
        slope,
        intercept: mean_y - slope * mean_x,
        confidence: sxy * sxy / (sxx * syy),
    })
}


/// Projected time `capacity` is reached; checks run in order: too few points, latest value already at capacity, flat or shrinking, projection.
pub fn forecast(points: &[Point], capacity: f64, min_points: usize) -> Forecast {
    let latest = points.iter().max_by_key(|point| point.0).map(|point| point.1);
    match (points.len() >= min_points, latest) {
        (true, Some(value)) if value >= capacity => Forecast::AlreadyReached,
        (true, Some(_)) => fit(points).map_or(Forecast::NotGrowing, |line| Forecast::Projected {
            at: ((capacity - line.intercept) / line.slope).round() as Timestamp,
            confidence: line.confidence,
        }),
        _ => Forecast::TooFewPoints,
    }
}


/// `limits` is `(horizon, min_confidence, min_points)`; an already reached capacity holds, too few points or a flat series do not.
pub fn forecast_holds(points: &[Point], capacity: f64, limits: (u64, f64, usize), now: Timestamp) -> bool {
    match forecast(points, capacity, limits.2) {
        Forecast::AlreadyReached => true,
        Forecast::Projected { at, confidence } => at <= now.saturating_add(limits.0) && confidence >= limits.1,
        Forecast::TooFewPoints | Forecast::NotGrowing => false,
    }
}
