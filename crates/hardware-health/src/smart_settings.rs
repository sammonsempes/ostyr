//! Strict loader of the smartctl runner settings.

use crate::error::SmartError;
use crate::limits::{MAX_DEADLINE_SECONDS, MAX_ROUND_DEADLINE_SECONDS, MAX_SETTINGS_BYTES, MIN_DEADLINE_SECONDS, MIN_ROUND_DEADLINE_SECONDS};
use crate::model::SmartSettings;
use serde::de::Error as _;


/// The parser's own message quotes the offending value, so only a fixed source is kept.
pub fn settings_error(error: serde_saphyr::Error) -> SmartError {
    let location = format!("{:?}", error.location());
    tracing::debug!(location, "settings file refused");
    SmartError::Settings(Box::new(serde_saphyr::Error::custom("settings file is not valid")))
}


pub fn parse_settings(text: &str) -> Result<SmartSettings, SmartError> {
    if text.len() > MAX_SETTINGS_BYTES {
        Err(SmartError::SettingsTooLarge { limit: MAX_SETTINGS_BYTES })
    } else {
        let options = serde_saphyr::options! { with_snippet: false };
        let settings: SmartSettings = serde_saphyr::from_str_with_options(text, options).map_err(settings_error)?;
        if !(MIN_DEADLINE_SECONDS..=MAX_DEADLINE_SECONDS).contains(&settings.deadline_seconds) {
            Err(SmartError::SettingsField { field: "deadline_seconds" })
        } else if !(MIN_ROUND_DEADLINE_SECONDS..=MAX_ROUND_DEADLINE_SECONDS).contains(&settings.round_deadline_seconds) {
            Err(SmartError::SettingsField {
                field: "round_deadline_seconds",
            })
        } else {
            Ok(settings)
        }
    }
}
