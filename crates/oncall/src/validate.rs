use crate::error::OncallError;
use crate::limits::{
    MAX_DELAY_SECONDS, MAX_HOLIDAYS, MAX_LAYERS, MAX_LEVELS, MAX_NAME_LEN, MAX_OVERRIDES, MAX_PARTICIPANTS, MAX_PERIOD_DAYS, MAX_TARGETS,
};
use crate::model::{Holiday, HolidayRule, Layer, Level, Override, Policy, Schedule, Target};


pub fn check_between(what: &'static str, value: u64, min: u64, max: u64) -> Result<(), OncallError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(OncallError::OutOfBounds { what, value, min, max })
    }
}


pub fn check_name(what: &'static str, name: &str) -> Result<(), OncallError> {
    check_between(what, name.chars().count() as u64, 1, MAX_NAME_LEN)
}


pub fn check_names(what: &'static str, names: &[String]) -> Result<(), OncallError> {
    check_between(what, names.len() as u64, 1, MAX_PARTICIPANTS)?;
    names.iter().try_for_each(|name| check_name(what, name))
}


pub fn validate_layer(layer: &Layer) -> Result<(), OncallError> {
    check_name("layer name", &layer.name)?;
    check_names("participants", &layer.participants)?;
    check_between("period_days", u64::from(layer.period_days), 1, MAX_PERIOD_DAYS)
}


pub fn validate_override(entry: &Override) -> Result<(), OncallError> {
    check_name("override person", &entry.person)?;
    if entry.start < entry.end {
        Ok(())
    } else {
        Err(OncallError::OverrideRange {
            person: entry.person.clone(),
        })
    }
}


pub fn validate_holiday(holiday: &Holiday) -> Result<(), OncallError> {
    match &holiday.rule {
        HolidayRule::Nobody => Ok(()),
        HolidayRule::Cover(people) => check_names("holiday cover", people),
    }
}


pub fn validate_schedule(schedule: &Schedule) -> Result<(), OncallError> {
    check_name("schedule name", &schedule.name)?;
    check_between("layers", schedule.layers.len() as u64, 0, MAX_LAYERS)?;
    check_between("overrides", schedule.overrides.len() as u64, 0, MAX_OVERRIDES)?;
    check_between("holidays", schedule.holidays.len() as u64, 0, MAX_HOLIDAYS)?;
    schedule.layers.iter().try_for_each(validate_layer)?;
    schedule.overrides.iter().try_for_each(validate_override)?;
    schedule.holidays.iter().try_for_each(validate_holiday)
}


pub fn validate_target(target: &Target) -> Result<(), OncallError> {
    match target {
        Target::Person(name) | Target::Schedule(name) => check_name("target", name),
    }
}


pub fn validate_level(level: &Level) -> Result<(), OncallError> {
    check_between("delay_seconds", u64::from(level.delay_seconds), 0, MAX_DELAY_SECONDS)?;
    check_between("targets", level.targets.len() as u64, 1, MAX_TARGETS)?;
    level.targets.iter().try_for_each(validate_target)
}


pub fn validate_policy(policy: &Policy) -> Result<(), OncallError> {
    check_name("policy name", &policy.name)?;
    check_between("levels", policy.levels.len() as u64, 1, MAX_LEVELS)?;
    policy.levels.iter().try_for_each(validate_level)
}
