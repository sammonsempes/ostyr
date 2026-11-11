use crate::support::{RELOADED_MILLIS, SENSOR_SETTING_COUNT, SETTING_COUNT};
use crate::types::TestResult;
use agent_channel::app::{reload_context, shared_log_audit};
use agent_linux::error::SourceError;
use agent_linux::model::{
    SensorSettings, SourceSettings, DEFAULT_POLL_MILLIS, MAX_LINES_PER_POLL_CEILING, MAX_LINE_BYTES_CEILING, MAX_POLL_MILLIS,
    MAX_RESTARTS_PER_HOUR_CEILING, MAX_SENSOR_INTERVAL_SECONDS, MAX_SENSOR_WINDOW_SECONDS, MAX_SPOOL_BYTES_CEILING,
};
use agent_linux::settings::{invalid_sensor_settings, invalid_settings, open_settings_engine, settings_loader, settings_state, validate_settings};
use core_audit::log::open_file_log;
use core_config::reload::{reload, ReloadOutcome};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;


const PATHS: &str = "agent_file: /a\nexport_path: /e\ncursor_file: /c\naudit_file: /l\n";


fn write_settings(path: &Path, extra: &str) -> std::io::Result<()> {
    fs::write(path, format!("{PATHS}{extra}"))
}


#[test]
fn every_zero_bound_is_named() -> TestResult {
    let zero = SourceSettings {
        poll_millis: 0,
        max_line_bytes: 0,
        max_spool_bytes: 0,
        max_lines_per_poll: 0,
    };
    assert_eq!(invalid_settings(&zero).len(), SETTING_COUNT);
    let refused = validate_settings(&zero);
    assert!(matches!(refused, Err(SourceError::Settings(names)) if names.contains("max_spool_bytes")));
    assert!(validate_settings(&SourceSettings::default()).is_ok());
    Ok(())
}


#[test]
fn a_reload_applies_to_the_shared_settings_and_an_invalid_one_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("agent-linux.yaml");
    write_settings(&path, "")?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let context = reload_context(&path, "agent_linux", "tenant", "reload");
    let (engine, shared, _sensor) = open_settings_engine(path.clone(), shared_log_audit(&log), context)?;
    assert_eq!(shared.load().poll_millis, DEFAULT_POLL_MILLIS);
    write_settings(&path, &format!("settings:\n  poll_millis: {RELOADED_MILLIS}\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(shared.load().poll_millis, RELOADED_MILLIS);
    write_settings(&path, "settings:\n  poll_millis: 0\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("poll_millis")));
    assert_eq!(shared.load().poll_millis, RELOADED_MILLIS);
    Ok(())
}


#[test]
fn the_first_load_must_be_valid() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("agent-linux.yaml");
    write_settings(&path, "settings:\n  max_line_bytes: 0\n")?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let context = reload_context(&path, "agent_linux", "tenant", "reload");
    assert!(matches!(
        open_settings_engine(path.clone(), shared_log_audit(&log), context),
        Err(SourceError::Settings(_))
    ));
    fs::write(&path, "not: [valid")?;
    assert!(settings_loader(path)().is_err());
    Ok(())
}


#[test]
fn the_state_has_one_entry_per_setting() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("agent-linux.yaml");
    write_settings(&path, "")?;
    let file = settings_loader(path)()?;
    let state = settings_state(&file);
    assert_eq!(state.len(), SENSOR_SETTING_COUNT);
    assert_eq!(state.get("agent_linux.poll_millis"), Some(&DEFAULT_POLL_MILLIS.to_string()));
    Ok(())
}


#[test]
fn every_bound_is_accepted_at_its_ceiling_and_refused_one_over() -> TestResult {
    let ceilings = SourceSettings {
        poll_millis: MAX_POLL_MILLIS,
        max_line_bytes: MAX_LINE_BYTES_CEILING,
        max_spool_bytes: MAX_SPOOL_BYTES_CEILING,
        max_lines_per_poll: MAX_LINES_PER_POLL_CEILING,
    };
    assert!(validate_settings(&ceilings).is_ok());
    let over = [
        (
            "poll_millis",
            SourceSettings {
                poll_millis: MAX_POLL_MILLIS + 1,
                ..ceilings.clone()
            },
        ),
        (
            "max_line_bytes",
            SourceSettings {
                max_line_bytes: MAX_LINE_BYTES_CEILING + 1,
                ..ceilings.clone()
            },
        ),
        (
            "max_spool_bytes",
            SourceSettings {
                max_spool_bytes: MAX_SPOOL_BYTES_CEILING + 1,
                ..ceilings.clone()
            },
        ),
        (
            "max_lines_per_poll",
            SourceSettings {
                max_lines_per_poll: MAX_LINES_PER_POLL_CEILING + 1,
                ..ceilings.clone()
            },
        ),
        (
            "max_line_bytes",
            SourceSettings {
                max_line_bytes: u64::MAX,
                ..ceilings
            },
        ),
    ];
    over.iter()
        .for_each(|(name, settings)| assert_eq!(invalid_settings(settings), vec![*name]));
    Ok(())
}


#[test]
fn sensor_bounds_are_refused_at_zero_and_over_their_ceiling_and_a_reload_applies_them() -> TestResult {
    let ceilings = SensorSettings {
        window_seconds: MAX_SENSOR_WINDOW_SECONDS,
        interval_seconds: MAX_SENSOR_INTERVAL_SECONDS,
        max_restarts_per_hour: MAX_RESTARTS_PER_HOUR_CEILING,
    };
    assert!(invalid_sensor_settings(&ceilings).is_empty());
    let zero_cap = SensorSettings {
        max_restarts_per_hour: 0,
        ..ceilings.clone()
    };
    assert!(invalid_sensor_settings(&zero_cap).is_empty());
    let zero = SensorSettings {
        window_seconds: 0,
        interval_seconds: 0,
        ..ceilings.clone()
    };
    assert_eq!(invalid_sensor_settings(&zero), vec!["window_seconds", "interval_seconds"]);
    let over = SensorSettings {
        window_seconds: MAX_SENSOR_WINDOW_SECONDS + 1,
        interval_seconds: MAX_SENSOR_INTERVAL_SECONDS + 1,
        max_restarts_per_hour: MAX_RESTARTS_PER_HOUR_CEILING + 1,
    };
    assert_eq!(
        invalid_sensor_settings(&over),
        vec!["window_seconds", "interval_seconds", "max_restarts_per_hour"]
    );
    let dir = tempdir()?;
    let path = dir.path().join("agent-linux.yaml");
    write_settings(&path, "sensor:\n  window_seconds: 0\n")?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let context = reload_context(&path, "agent_linux", "tenant", "reload");
    assert!(matches!(
        open_settings_engine(path.clone(), shared_log_audit(&log), context),
        Err(SourceError::Settings(names)) if names.contains("window_seconds")
    ));
    write_settings(&path, "")?;
    let context_again = reload_context(&path, "agent_linux", "tenant", "reload");
    let (engine, _shared, sensor) = open_settings_engine(path.clone(), shared_log_audit(&log), context_again)?;
    write_settings(&path, "sensor:\n  window_seconds: 7\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(sensor.load().window_seconds, RELOADED_MILLIS);
    write_settings(&path, "sensor:\n  interval_seconds: 99\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("interval_seconds")));
    assert_eq!(sensor.load().window_seconds, RELOADED_MILLIS);
    Ok(())
}
