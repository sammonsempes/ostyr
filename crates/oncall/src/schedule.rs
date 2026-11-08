use crate::model::{Holiday, HolidayRule, Layer, Schedule};
use chrono::{DateTime, NaiveDateTime, TimeDelta, Utc};


/// The participant of `layer` at the local wall-clock time `local`; nobody before the first hand-off.
pub fn layer_person(layer: &Layer, local: NaiveDateTime) -> Option<&String> {
    let elapsed = local.signed_duration_since(layer.start);
    let days = elapsed.num_days().unsigned_abs();
    let slot = days / u64::from(layer.period_days).max(1);
    let index = (slot % (layer.participants.len() as u64).max(1)) as usize;
    (elapsed >= TimeDelta::zero()).then(|| layer.participants.get(index)).flatten()
}


pub fn holiday_people(holiday: &Holiday) -> Vec<String> {
    match &holiday.rule {
        HolidayRule::Nobody => Vec::new(),
        HolidayRule::Cover(people) => people.clone(),
    }
}


/// People on call at `instant`: active overrides, else the holiday rule of the local date, else one person per layer.
pub fn on_call_at(schedule: &Schedule, instant: DateTime<Utc>) -> Vec<String> {
    let local = instant.with_timezone(&schedule.time_zone).naive_local();
    let overridden: Vec<String> = schedule
        .overrides
        .iter()
        .filter(|entry| entry.start <= instant && instant < entry.end)
        .map(|entry| entry.person.clone())
        .collect();
    let holiday = schedule.holidays.iter().find(|entry| entry.date == local.date());
    if !overridden.is_empty() {
        overridden
    } else {
        holiday.map_or_else(
            || schedule.layers.iter().filter_map(|layer| layer_person(layer, local)).cloned().collect(),
            holiday_people,
        )
    }
}
