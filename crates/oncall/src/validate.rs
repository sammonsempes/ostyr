use crate::error::OncallError;
use crate::limits::{
    MAX_ASSETS, MAX_DELAY_SECONDS, MAX_HOLIDAYS, MAX_LAYERS, MAX_LEVELS, MAX_MATCHERS, MAX_NAME_LEN, MAX_OVERRIDES, MAX_PARTICIPANTS,
    MAX_PERIOD_DAYS, MAX_REGEX_LEN, MAX_SILENCES, MAX_TARGETS, MAX_TEXT_LEN, MAX_VALUE_LEN, MAX_WINDOWS,
};
use crate::model::{
    Holiday, HolidayRule, Layer, Level, MatchKind, Matcher, Override, Policy, Schedule, Silence, SilenceFile, Target, Window, WindowFile,
};
use crate::silence::compile_regex;
use chrono::{DateTime, Utc};


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


pub fn check_text(what: &'static str, text: &str) -> Result<(), OncallError> {
    check_between(what, text.chars().count() as u64, 1, MAX_TEXT_LEN)
}


pub fn validate_matcher(matcher: &Matcher) -> Result<(), OncallError> {
    check_name("matcher label", &matcher.label)?;
    match matcher.kind {
        MatchKind::Equal => check_between("matcher value", matcher.value.chars().count() as u64, 0, MAX_VALUE_LEN),
        MatchKind::Regex => {
            check_between("matcher regex", matcher.value.chars().count() as u64, 1, MAX_REGEX_LEN)?;
            compile_regex(&matcher.value).map(drop).map_err(|source| OncallError::InvalidRegex {
                pattern: matcher.value.clone(),
                source,
            })
        }
    }
}


pub fn check_range(name: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<(), OncallError> {
    if start < end {
        Ok(())
    } else {
        Err(OncallError::ExpiryRange { name: name.to_string() })
    }
}


pub fn validate_silence(silence: &Silence) -> Result<(), OncallError> {
    check_name("silence name", &silence.name)?;
    check_name("silence author", &silence.author)?;
    check_text("silence reason", &silence.reason)?;
    check_between("matchers", silence.matchers.len() as u64, 1, MAX_MATCHERS)?;
    silence.matchers.iter().try_for_each(validate_matcher)?;
    check_range(&silence.name, silence.starts_at, silence.expires_at)
}


pub fn validate_silences(file: &SilenceFile) -> Result<(), OncallError> {
    check_between("silences", file.silences.len() as u64, 0, MAX_SILENCES)?;
    file.silences.iter().try_for_each(validate_silence)
}


pub fn validate_window(window: &Window) -> Result<(), OncallError> {
    check_name("window name", &window.name)?;
    check_name("window author", &window.author)?;
    check_text("window reason", &window.reason)?;
    check_between("assets", window.assets.len() as u64, 1, MAX_ASSETS)?;
    window.assets.iter().try_for_each(|asset| check_name("asset", asset))?;
    check_range(&window.name, window.starts_at, window.ends_at)
}


pub fn validate_windows(file: &WindowFile) -> Result<(), OncallError> {
    check_between("windows", file.windows.len() as u64, 0, MAX_WINDOWS)?;
    file.windows.iter().try_for_each(validate_window)
}
