use crate::error::GrcError;
use crate::load::{is_identifier, is_owner, is_printable_text, MAX_FILE_BYTES, MAX_ID_CHARS, MAX_TITLE_CHARS};
use crate::model::Framework;
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_text_capped};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use time::format_description::well_known::Iso8601;
use time::Date;


pub const MAX_RISKS: usize = 1_000;


pub const MAX_ACTIONS: usize = 5_000;


pub const MAX_RISK_CONTROLS: usize = 64;


pub const MIN_SCORE: u8 = 1;


pub const MAX_SCORE: u8 = 5;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Treatment {
    Mitigate,
    Accept,
    Transfer,
    Avoid,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Open,
    InProgress,
    Done,
}


#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Risk {
    pub id: String,
    pub title: String,
    pub likelihood: u8,
    pub impact: u8,
    pub treatment: Treatment,
    pub owner: String,
    pub controls: Vec<String>,
    #[serde(deserialize_with = "date_field")]
    pub review_by: Date,
}


#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub id: String,
    pub risk: String,
    pub control: Option<String>,
    pub title: String,
    pub owner: String,
    #[serde(deserialize_with = "date_field")]
    pub due: Date,
    pub status: ActionStatus,
    #[serde(default, deserialize_with = "optional_date_field")]
    pub done_on: Option<Date>,
}


#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    pub tenant: String,
    pub risks: Vec<Risk>,
    pub actions: Vec<Action>,
}


fn parse_date(text: &str) -> Result<Date, time::error::Parse> {
    Date::parse(text, &Iso8601::DATE)
}


/// A `YYYY-MM-DD` date; the error never repeats the value.
pub fn date_field<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Date, Source::Error> {
    let text = String::deserialize(deserializer)?;
    parse_date(&text).map_err(|_| Source::Error::custom("invalid date, expected YYYY-MM-DD"))
}


pub fn optional_date_field<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Option<Date>, Source::Error> {
    let text = Option::<String>::deserialize(deserializer)?;
    text.map(|value| parse_date(&value))
        .transpose()
        .map_err(|_| Source::Error::custom("invalid date, expected YYYY-MM-DD"))
}


fn check_risk(risk: &Risk, known: &BTreeSet<&str>) -> Result<(), &'static str> {
    let score_range = MIN_SCORE..=MAX_SCORE;
    if !is_identifier(&risk.id, MAX_ID_CHARS) {
        Err("invalid id")
    } else if !is_printable_text(&risk.title, MAX_TITLE_CHARS) {
        Err("invalid title")
    } else if !(score_range.contains(&risk.likelihood) && score_range.contains(&risk.impact)) {
        Err("likelihood and impact must be between 1 and 5")
    } else if !is_owner(&risk.owner) {
        Err("invalid owner")
    } else if risk.controls.len() > MAX_RISK_CONTROLS {
        Err("too many controls")
    } else if !risk.controls.iter().all(|control| known.contains(control.as_str())) {
        Err("unknown control")
    } else {
        Ok(())
    }
}


fn check_action(action: &Action, known: &BTreeSet<&str>, risks: &BTreeSet<&str>) -> Result<(), &'static str> {
    if !is_identifier(&action.id, MAX_ID_CHARS) {
        Err("invalid id")
    } else if !risks.contains(action.risk.as_str()) {
        Err("unknown risk")
    } else if !action.control.as_deref().is_none_or(|control| known.contains(control)) {
        Err("unknown control")
    } else if !is_printable_text(&action.title, MAX_TITLE_CHARS) {
        Err("invalid title")
    } else if !is_owner(&action.owner) {
        Err("invalid owner")
    } else {
        match (action.status, action.done_on) {
            (ActionStatus::Done, None) => Err("a done action needs done_on"),
            (ActionStatus::Open | ActionStatus::InProgress, Some(_)) => Err("done_on is only allowed on a done action"),
            _ => Ok(()),
        }
    }
}


fn first_duplicate<'a>(ids: impl Iterator<Item = &'a str>) -> Option<usize> {
    let mut seen = BTreeSet::new();
    ids.enumerate().find(|(_, id)| !seen.insert(*id)).map(|(index, _)| index)
}


/// Refuses the whole register on the first failure, naming the list and the index, never a value.
pub fn check_register(register: &Register, framework: &Framework, file: &str) -> Result<(), GrcError> {
    let invalid = |reason: String| GrcError::Invalid {
        file: file.to_owned(),
        reason,
    };
    let known: BTreeSet<&str> = framework.controls.iter().map(|control| control.id.as_str()).collect();
    let risk_ids: BTreeSet<&str> = register.risks.iter().map(|risk| risk.id.as_str()).collect();
    if register.risks.len() > MAX_RISKS {
        Err(invalid(format!("more than {MAX_RISKS} risks")))
    } else if register.actions.len() > MAX_ACTIONS {
        Err(invalid(format!("more than {MAX_ACTIONS} actions")))
    } else {
        register
            .risks
            .iter()
            .enumerate()
            .try_for_each(|(index, risk)| check_risk(risk, &known).map_err(|reason| invalid(format!("risks[{index}]: {reason}"))))?;
        register.actions.iter().enumerate().try_for_each(|(index, action)| {
            check_action(action, &known, &risk_ids).map_err(|reason| invalid(format!("actions[{index}]: {reason}")))
        })?;
        match (
            first_duplicate(register.risks.iter().map(|risk| risk.id.as_str())),
            first_duplicate(register.actions.iter().map(|action| action.id.as_str())),
        ) {
            (Some(index), _) => Err(invalid(format!("risks[{index}]: duplicate id"))),
            (None, Some(index)) => Err(invalid(format!("actions[{index}]: duplicate id"))),
            (None, None) => Ok(()),
        }
    }
}


pub fn parse_risks(reader: &mut dyn Read, file: &str, framework: &Framework) -> Result<Register, GrcError> {
    let text = read_text_capped(reader, file, MAX_FILE_BYTES)?;
    let register: Register = parse_document(&text, file)?;
    check_register(&register, framework, file).map(|()| register)
}


pub fn load_risks(path: &Path, framework: &Framework) -> Result<Register, GrcError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    parse_risks(&mut handle, &file, framework)
}
