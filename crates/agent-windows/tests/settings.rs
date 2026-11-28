#[path = "common/engine.rs"]
mod engine;
#[path = "common/types.rs"]
mod types;


use agent_windows::defender::{DEFAULT_DEFENDER_INTERVAL_SECONDS, MIN_DEFENDER_INTERVAL_SECONDS};
use agent_windows::model::{MAX_EVENTS_PER_POLL, MAX_OUTPUT_BYTES, POLL_INTERVAL_SECONDS, QUERY_DEADLINE_SECONDS, SECURITY, SYSMON};
use agent_windows::settings::{
    alphabet_text, channels_of, load_settings, parse_settings, settings_path, settings_state, validate_channels, validate_settings, OpenError,
    Settings, SettingsError, DEFAULT_MAX_SPOOL_BYTES, MAX_DEADLINE_SECONDS, MAX_DEFENDER_INTERVAL_SECONDS, MAX_POLL_INTERVAL_SECONDS,
    MAX_SETTINGS_BYTES, MAX_SPOOL_BYTES_CEILING, MIN_DEADLINE_SECONDS, MIN_OUTPUT_BYTES, MIN_POLL_INTERVAL_SECONDS, MIN_SPOOL_BYTES, SETTINGS_FILE,
};
use agent_windows::types::SharedObserved;
use agent_windows::winget::{DEFAULT_UPDATES_INTERVAL_SECONDS, MAX_UPDATES_INTERVAL_SECONDS, MIN_UPDATES_INTERVAL_SECONDS};
use core_config::error::ConfigError;
use core_config::reload::{current_config, reload, ReloadOutcome};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use types::TestResult;


struct Case {
    name: &'static str,
    build: fn(u64) -> Settings,
    low: u64,
    high: u64,
}


const BIG_FILE_BYTES: usize = 10 * 1_048_576;


const FIVE: u32 = 5;


const SEVEN: u32 = 7;


const NINE: u32 = 9;


const NUMERIC_REFUSALS: usize = 13;


const OLD_BATCH: u32 = 100;


const NEW_BATCH: u32 = 7;


const FOUR_DENIED: usize = 4;


const SETTING_COUNT: usize = 9;


const HOSTILE_FILES: usize = 14;


const UTF16_BOM: [u8; 2] = [0xFF, 0xFE];


const MARKER: &str = "zzmarkerzz";


fn base() -> Settings {
    Settings::default()
}


fn narrow(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}


fn wide(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}


fn poll_interval(value: u64) -> Settings {
    Settings {
        poll_interval_seconds: value,
        ..base()
    }
}


fn batch(value: u64) -> Settings {
    Settings {
        batch: narrow(value),
        ..base()
    }
}


fn defender(value: u64) -> Settings {
    Settings {
        defender_interval_seconds: value,
        ..base()
    }
}


fn updates(value: u64) -> Settings {
    Settings {
        updates_interval_seconds: value,
        ..base()
    }
}


fn output(value: u64) -> Settings {
    Settings {
        max_output_bytes: wide(value),
        ..base()
    }
}


fn deadline(value: u64) -> Settings {
    Settings {
        deadline_seconds: value,
        ..base()
    }
}


fn spool(value: u64) -> Settings {
    Settings {
        max_spool_bytes: value,
        ..base()
    }
}


fn cases() -> Result<Vec<Case>, std::num::TryFromIntError> {
    Ok(vec![
        Case {
            name: "poll_interval_seconds",
            build: poll_interval,
            low: MIN_POLL_INTERVAL_SECONDS,
            high: MAX_POLL_INTERVAL_SECONDS,
        },
        Case {
            name: "batch",
            build: batch,
            low: 1,
            high: u64::from(MAX_EVENTS_PER_POLL),
        },
        Case {
            name: "defender_interval_seconds",
            build: defender,
            low: MIN_DEFENDER_INTERVAL_SECONDS,
            high: MAX_DEFENDER_INTERVAL_SECONDS,
        },
        Case {
            name: "updates_interval_seconds",
            build: updates,
            low: MIN_UPDATES_INTERVAL_SECONDS,
            high: MAX_UPDATES_INTERVAL_SECONDS,
        },
        Case {
            name: "max_output_bytes",
            build: output,
            low: u64::try_from(MIN_OUTPUT_BYTES)?,
            high: u64::try_from(MAX_OUTPUT_BYTES)?,
        },
        Case {
            name: "deadline_seconds",
            build: deadline,
            low: MIN_DEADLINE_SECONDS,
            high: MAX_DEADLINE_SECONDS,
        },
        Case {
            name: "max_spool_bytes",
            build: spool,
            low: MIN_SPOOL_BYTES,
            high: MAX_SPOOL_BYTES_CEILING,
        },
    ])
}


fn field_of(settings: &Settings) -> Option<&'static str> {
    match validate_settings(settings) {
        Err(SettingsError::Range { field }) => Some(field),
        _ => None,
    }
}


fn load_text(directory: &Path, bytes: &[u8]) -> Result<Settings, ConfigError> {
    let path = directory.join(SETTINGS_FILE);
    fs::write(&path, bytes).map_err(|source| ConfigError::Io {
        file: path.display().to_string(),
        source,
    })?;
    load_settings(&path)
}


fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}


#[test]
fn defaults_are_the_values_the_agent_used_before_the_file() -> TestResult {
    let parsed = parse_settings("poll_interval_seconds: 10\n", "t.yaml")?;
    assert_eq!(parsed, base());
    assert_eq!(parsed.poll_interval_seconds, POLL_INTERVAL_SECONDS);
    assert_eq!(parsed.batch, MAX_EVENTS_PER_POLL);
    assert_eq!(parsed.defender_interval_seconds, DEFAULT_DEFENDER_INTERVAL_SECONDS);
    assert_eq!(parsed.updates_interval_seconds, DEFAULT_UPDATES_INTERVAL_SECONDS);
    assert_eq!(parsed.max_output_bytes, MAX_OUTPUT_BYTES);
    assert_eq!(parsed.deadline_seconds, QUERY_DEADLINE_SECONDS);
    assert_eq!(parsed.max_spool_bytes, DEFAULT_MAX_SPOOL_BYTES);
    assert_eq!(channels_of(&parsed), vec![SYSMON, SECURITY]);
    assert!(validate_settings(&parsed).is_ok());
    assert_eq!(settings_path(Path::new("state")), Path::new("state").join(SETTINGS_FILE));
    Ok(())
}


#[test]
fn every_field_is_checked_one_below_and_one_above_its_bounds() -> TestResult {
    cases()?.iter().for_each(|case| {
        assert_eq!(field_of(&(case.build)(case.low - 1)), Some(case.name), "{} below", case.name);
        assert_eq!(field_of(&(case.build)(case.low)), None, "{} low", case.name);
        assert_eq!(field_of(&(case.build)(case.high)), None, "{} high", case.name);
        assert_eq!(field_of(&(case.build)(case.high + 1)), Some(case.name), "{} above", case.name);
    });
    Ok(())
}


#[test]
fn an_interval_of_zero_below_the_floor_or_the_maximum_is_refused_never_clamped() -> TestResult {
    assert_eq!(field_of(&poll_interval(0)), Some("poll_interval_seconds"));
    assert_eq!(field_of(&poll_interval(u64::MAX)), Some("poll_interval_seconds"));
    assert_eq!(field_of(&defender(0)), Some("defender_interval_seconds"));
    assert_eq!(field_of(&defender(MIN_DEFENDER_INTERVAL_SECONDS - 1)), Some("defender_interval_seconds"));
    assert_eq!(field_of(&defender(u64::MAX)), Some("defender_interval_seconds"));
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let parsed = load_text(directory.path(), b"defender_interval_seconds: 18446744073709551615\n")?;
    assert_eq!(parsed.defender_interval_seconds, u64::MAX);
    assert_eq!(field_of(&parsed), Some("defender_interval_seconds"));
    assert!(load_text(directory.path(), b"defender_interval_seconds: -1\n").is_err());
    assert!(load_text(directory.path(), b"batch: 4294967296\n").is_err());
    Ok(())
}


#[test]
fn channels_are_checked_by_index() -> TestResult {
    assert!(validate_channels(&names(&["security"])).is_ok());
    assert!(validate_channels(&names(&["security", "sysmon"])).is_ok());
    assert!(matches!(validate_channels(&[]), Err(SettingsError::NoChannel)));
    assert!(matches!(
        validate_channels(&names(&["sysmon", "security", "sysmon"])),
        Err(SettingsError::TooManyChannels)
    ));
    assert!(matches!(
        validate_channels(&names(&["sysmon", MARKER])),
        Err(SettingsError::UnknownChannel { index: 1 })
    ));
    assert!(matches!(
        validate_channels(&names(&["Security"])),
        Err(SettingsError::UnknownChannel { index: 0 })
    ));
    assert!(matches!(
        validate_channels(&names(&["security", "security"])),
        Err(SettingsError::DuplicateChannel { index: 1 })
    ));
    let refused = validate_channels(&names(&["sysmon", MARKER]))
        .err()
        .map(|error| format!("{error} {error:?}"));
    assert!(refused.is_some_and(|text| !text.contains(MARKER)));
    assert_eq!(
        channels_of(&Settings {
            channels: names(&["security"]),
            ..base()
        }),
        vec![SECURITY]
    );
    Ok(())
}


#[test]
fn an_unknown_key_or_a_wrong_type_is_refused_without_echoing_the_text() -> TestResult {
    let unknown = parse_settings(&format!("{MARKER}: 1\n"), "t.yaml")
        .err()
        .map(|error| format!("{error} {error:?}"));
    assert!(unknown.as_ref().is_some_and(|text| !text.contains(MARKER)));
    assert!(unknown.is_some());
    assert!(parse_settings("batch: text\n", "t.yaml").is_err());
    assert!(parse_settings("channels: sysmon\n", "t.yaml").is_err());
    Ok(())
}


#[test]
fn bytes_outside_the_alphabet_are_refused_before_any_parse() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    assert_eq!(load_text(directory.path(), b"batch: 5\n")?.batch, FIVE);
    let utf16: Vec<u8> = UTF16_BOM
        .into_iter()
        .chain("batch: 5\n".encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    assert!(matches!(load_text(directory.path(), &utf16), Err(ConfigError::NotUtf8 { .. })));
    let hostile: [&[u8]; HOSTILE_FILES] = [
        b"\xEF\xBB\xBFbatch: 5\n",
        b"batch: &a 5\n",
        b"batch: *a\n",
        b"batch: !!int 5\n",
        b"channels: [\"sysmon\"]\n",
        b"channels: ['sysmon']\n",
        b"# comment\nbatch: 5\n",
        b"batch:\t5\n",
        b"batch: 5\r",
        b"channels: [C:\\Windows\\x]\n",
        b"channels: [/q:*]\n",
        b"<<: {}\n",
        b"channels: |\n  sysmon\n",
        b"channels: >\n  sysmon\n",
    ];
    hostile.iter().for_each(|bytes| {
        assert!(
            matches!(load_text(directory.path(), bytes), Err(ConfigError::WatchedFile { .. })),
            "{}",
            String::from_utf8_lossy(bytes)
        );
    });
    let crlf = load_text(directory.path(), b"batch: 5\r\nchannels: [sysmon]\r\n")?;
    assert_eq!((crlf.batch, crlf.channels), (FIVE, names(&["sysmon"])));
    let refused = alphabet_text(b"batch: \xC3\xA9\n", "t.yaml").err().map(|error| error.to_string());
    assert!(refused.is_some_and(|text| text.contains("byte 7")));
    Ok(())
}


#[test]
fn a_numeric_setting_is_plain_decimal_digits_only() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let refused: [&[u8]; NUMERIC_REFUSALS] = [
        b"batch: 0x1f4\n",
        b"batch: 0o764\n",
        b"batch: 1_0\n",
        b"batch: +5\n",
        b"batch: -5\n",
        b"batch: 5e1\n",
        b"batch: 007\n",
        b"batch:\n",
        b"batch: 5 5\n",
        b"poll_interval_seconds: 0b11\n",
        b"max_spool_bytes: 0x100000\n",
        b"deadline_seconds: 5 \nbatch: 0xff\n",
        b"  defender_interval_seconds: 3_600\n",
    ];
    refused.iter().for_each(|bytes| {
        assert!(
            matches!(load_text(directory.path(), bytes), Err(ConfigError::WatchedFile { .. })),
            "{}",
            String::from_utf8_lossy(bytes)
        );
    });
    let text = alphabet_text(b"channels: [sysmon]\nbatch: 0x1f4\n", "t.yaml")
        .err()
        .map(|error| error.to_string());
    assert!(text.is_some_and(|message| message.contains("line 2") && !message.contains("0x1f4")));
    assert_eq!(load_text(directory.path(), b"batch: 7\n")?.batch, SEVEN);
    assert_eq!(load_text(directory.path(), b"batch:   9  \r\n")?.batch, NINE);
    Ok(())
}


#[test]
fn a_file_over_the_cap_is_refused_unread() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let big = vec![b'a'; BIG_FILE_BYTES];
    assert!(matches!(load_text(directory.path(), &big), Err(ConfigError::TooLarge { .. })));
    let edge = vec![b'\n'; usize::try_from(MAX_SETTINGS_BYTES)? + 1];
    assert!(matches!(load_text(directory.path(), &edge), Err(ConfigError::TooLarge { .. })));
    let exact = vec![b'\n'; usize::try_from(MAX_SETTINGS_BYTES)?];
    assert!(!matches!(load_text(directory.path(), &exact), Err(ConfigError::TooLarge { .. })));
    let missing = load_settings(&directory.path().join("absent.yaml"));
    assert!(matches!(missing, Err(ConfigError::Io { .. })));
    fs::create_dir(directory.path().join("folder"))?;
    assert!(load_settings(&directory.path().join("folder")).is_err());
    Ok(())
}


#[test]
fn the_old_snapshot_is_kept_on_a_bad_file_and_a_good_change_applies() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let path = directory.path().join(SETTINGS_FILE);
    let denied = Arc::new(AtomicUsize::new(0));
    fs::write(&path, format!("batch: {OLD_BATCH}\n"))?;
    let engine = engine::open_at(&path, Arc::clone(&denied), SharedObserved::default())?;
    assert_eq!(current_config(&engine).batch, OLD_BATCH);
    fs::write(&path, "batch: 0\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!((current_config(&engine).batch, denied.load(Ordering::SeqCst)), (OLD_BATCH, 1));
    fs::write(&path, format!("batch: {OLD_BATCH}\nunknown: 1\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    fs::write(&path, format!("batch: {OLD_BATCH}\nchannels: [sysmon, zz]\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    fs::write(&path, format!("batch: {OLD_BATCH}\nchannels: [\"sysmon\"]\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!((current_config(&engine).batch, denied.load(Ordering::SeqCst)), (OLD_BATCH, FOUR_DENIED));
    fs::write(&path, format!("batch: {NEW_BATCH}\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).batch, NEW_BATCH);
    assert!(matches!(reload(&engine), ReloadOutcome::Unchanged));
    Ok(())
}


#[test]
fn the_first_file_must_load_and_validate() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let path = directory.path().join(SETTINGS_FILE);
    let denied = Arc::new(AtomicUsize::new(0));
    assert!(matches!(
        engine::open_at(&path, Arc::clone(&denied), SharedObserved::default()),
        Err(OpenError::Config(_))
    ));
    fs::write(&path, "deadline_seconds: 0\n")?;
    assert!(matches!(
        engine::open_at(&path, Arc::clone(&denied), SharedObserved::default()),
        Err(OpenError::Invalid(SettingsError::Range { field: "deadline_seconds" }))
    ));
    fs::write(&path, "channels: [sysmon, nope]\n")?;
    assert!(matches!(
        engine::open_at(&path, denied, SharedObserved::default()),
        Err(OpenError::Invalid(SettingsError::UnknownChannel { index: 1 }))
    ));
    Ok(())
}


#[test]
fn an_empty_document_is_refused_by_the_alphabet_check() -> TestResult {
    ["", "\n", " \n\n  \n", "---\n", "---", "\r\n---\r\n \n"]
        .iter()
        .for_each(|text| assert!(alphabet_text(text.as_bytes(), "settings.yaml").is_err(), "{text:?}"));
    assert!(alphabet_text(b"---\nbatch: 7\n", "settings.yaml").is_ok());
    assert!(alphabet_text(b"channels: [sysmon]\n", "settings.yaml").is_ok());
    Ok(())
}


#[test]
fn the_state_lists_every_setting() -> TestResult {
    let state = settings_state(&base());
    assert_eq!(state.len(), SETTING_COUNT);
    assert_eq!(state.get("channels").map(String::as_str), Some("sysmon,security"));
    assert_eq!(state.get("batch").map(String::as_str), Some("500"));
    Ok(())
}
