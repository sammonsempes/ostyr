//! Strict loader of the upsc runner settings.

use crate::error::SmartError;
use crate::limits::{
    MAX_DEADLINE_SECONDS, MAX_ROUND_DEADLINE_SECONDS, MAX_UPS_SETTINGS_BYTES, MAX_UPS_TARGETS, MIN_DEADLINE_SECONDS, MIN_ROUND_DEADLINE_SECONDS,
};
use crate::model::UpsSettings;
use crate::smart_settings::settings_error;


pub fn parse_ups_settings(text: &str) -> Result<UpsSettings, SmartError> {
    if text.len() > MAX_UPS_SETTINGS_BYTES {
        Err(SmartError::SettingsTooLarge {
            limit: MAX_UPS_SETTINGS_BYTES,
        })
    } else {
        let options = serde_saphyr::options! { with_snippet: false };
        let settings: UpsSettings = serde_saphyr::from_str_with_options(text, options).map_err(settings_error)?;
        if settings.ups_targets.is_empty() || settings.ups_targets.len() > MAX_UPS_TARGETS {
            Err(SmartError::SettingsField { field: "ups_targets" })
        } else if !(MIN_DEADLINE_SECONDS..=MAX_DEADLINE_SECONDS).contains(&settings.deadline_seconds) {
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
