use crate::defender::{DEFAULT_DEFENDER_INTERVAL_SECONDS, MIN_DEFENDER_INTERVAL_SECONDS};
use crate::model::{Channel, KNOWN_CHANNELS, MAX_EVENTS_PER_POLL, MAX_OUTPUT_BYTES, POLL_INTERVAL_SECONDS, QUERY_DEADLINE_SECONDS};
use crate::types::{Fingerprint, SharedObserved};
use crate::winget::{DEFAULT_UPDATES_INTERVAL_SECONDS, MAX_UPDATES_INTERVAL_SECONDS, MIN_UPDATES_INTERVAL_SECONDS};
use agent_channel::spool_dirs::accept_any_entries;
use agent_channel::types::EntriesJudge;
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_bytes_capped};
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use sys_windows::types::DirAclError;
use thiserror::Error;


pub const SETTINGS_SECTION: &str = "agent-windows";


pub const SETTINGS_FILE: &str = "settings.yaml";


pub const DOCUMENT_START: &str = "---";


pub const MAX_SETTINGS_BYTES: u64 = 4_096;


pub const ALPHABET_EXTRA: &[u8] = b" \n:-_[],";


pub const NUMERIC_KEYS: &[&str] = &[
    "poll_interval_seconds",
    "batch",
    "defender_interval_seconds",
    "updates_interval_seconds",
    "max_output_bytes",
    "deadline_seconds",
    "max_spool_bytes",
];


pub const MIN_POLL_INTERVAL_SECONDS: u64 = 1;


pub const MAX_POLL_INTERVAL_SECONDS: u64 = 3_600;


pub const MAX_DEFENDER_INTERVAL_SECONDS: u64 = 86_400;


pub const MIN_OUTPUT_BYTES: usize = 2_097_152;


pub const MIN_DEADLINE_SECONDS: u64 = 1;


pub const MAX_DEADLINE_SECONDS: u64 = 300;


pub const DEFAULT_MAX_SPOOL_BYTES: u64 = 67_108_864;


pub const MIN_SPOOL_BYTES: u64 = 1_048_576;


pub const MAX_SPOOL_BYTES_CEILING: u64 = 1_073_741_824;


pub const MAX_AUDIT_FILE_BYTES: usize = 64;


pub const DEVICE_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3",
    "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];


/// The settings file: every key optional, each defaulting to the value the agent used before the file existed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    pub channels: Vec<String>,
    pub poll_interval_seconds: u64,
    pub batch: u32,
    pub defender_interval_seconds: u64,
    pub updates_interval_seconds: u64,
    pub max_output_bytes: usize,
    pub deadline_seconds: u64,
    pub max_spool_bytes: u64,
    pub audit_file: Option<String>,
}


impl Default for Settings {
    fn default() -> Self {
        Self {
            channels: KNOWN_CHANNELS.iter().map(|channel| channel.key.to_owned()).collect(),
            poll_interval_seconds: POLL_INTERVAL_SECONDS,
            batch: MAX_EVENTS_PER_POLL,
            defender_interval_seconds: DEFAULT_DEFENDER_INTERVAL_SECONDS,
            updates_interval_seconds: DEFAULT_UPDATES_INTERVAL_SECONDS,
            max_output_bytes: MAX_OUTPUT_BYTES,
            deadline_seconds: QUERY_DEADLINE_SECONDS,
            max_spool_bytes: DEFAULT_MAX_SPOOL_BYTES,
            audit_file: None,
        }
    }
}


/// A refused setting is named by field and, for a channel, by index: the text of the file never appears.
#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("setting `{field}` is out of range")]
    Range { field: &'static str },
    #[error("setting `channels` is empty")]
    NoChannel,
    #[error("setting `channels` holds more entries than there are channels")]
    TooManyChannels,
    #[error("setting `channels[{index}]` is not a known channel")]
    UnknownChannel { index: usize },
    #[error("setting `channels[{index}]` repeats an earlier entry")]
    DuplicateChannel { index: usize },
    #[error("setting `audit_file` is missing")]
    NoAuditFile,
    #[error("setting `audit_file` is not a plain file name")]
    BadAuditFile,
    #[error("setting `audit_file` is read at start only")]
    AuditFileChanged,
}


#[derive(Debug, Error)]
pub enum OpenError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Invalid(#[from] SettingsError),
}


pub fn settings_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SETTINGS_FILE)
}


/// Strict parse (unknown keys refused, input text never echoed); range checks are `validate_settings`.
pub fn parse_settings(text: &str, file: &str) -> Result<Settings, ConfigError> {
    parse_document(text, file)
}


/// Every numeric key holds plain decimal digits only (no `0x`, `0o`, leading zero, `_`, sign or exponent); a refusal names the line, never the text.
pub fn plain_numbers(text: &str, file: &str) -> Result<(), ConfigError> {
    text.lines().enumerate().try_for_each(|(index, line)| match line.split_once(':') {
        Some((key, value)) if NUMERIC_KEYS.contains(&key.trim()) => {
            let number = value.trim();
            if !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()) && (number == "0" || !number.starts_with('0')) {
                Ok(())
            } else {
                Err(ConfigError::WatchedFile {
                    file: file.to_owned(),
                    reason: format!("line {} holds a numeric setting that is not plain decimal digits", index + 1),
                })
            }
        }
        _ => Ok(()),
    })
}


/// UTF-8, CRLF read as LF, every byte a letter, a digit or `ALPHABET_EXTRA`: no tag, anchor, alias, quote, escape, block scalar or comment.
pub fn alphabet_text(bytes: &[u8], file: &str) -> Result<String, ConfigError> {
    let text = std::str::from_utf8(bytes).map_err(|error| ConfigError::NotUtf8 {
        file: file.to_owned(),
        valid_up_to: error.valid_up_to(),
    })?;
    let unified = text.replace("\r\n", "\n");
    match unified
        .bytes()
        .position(|byte| !(byte.is_ascii_alphanumeric() || ALPHABET_EXTRA.contains(&byte)))
    {
        Some(offset) => Err(ConfigError::WatchedFile {
            file: file.to_owned(),
            reason: format!("byte {offset} is outside the settings alphabet"),
        }),
        None => non_empty(&unified, file).and_then(|()| plain_numbers(&unified, file)).map(|()| unified),
    }
}


/// An empty file, blank lines only or a bare `---` is refused: a truncated save must not apply the defaults.
pub fn non_empty(text: &str, file: &str) -> Result<(), ConfigError> {
    if text.lines().map(str::trim).any(|line| !line.is_empty() && line != DOCUMENT_START) {
        Ok(())
    } else {
        Err(ConfigError::WatchedFile {
            file: file.to_owned(),
            reason: "the document is empty".to_owned(),
        })
    }
}


/// Reads the file through one checked handle (regular file, at most `MAX_SETTINGS_BYTES`), then the alphabet, then the strict parse.
pub fn load_settings(path: &Path) -> Result<Settings, ConfigError> {
    let file = path.display().to_string();
    let bytes = read_bytes_capped(path, MAX_SETTINGS_BYTES)?;
    parse_settings(&alphabet_text(&bytes, &file)?, &file)
}


/// What the loader saw last: the exact bytes it read, whether the file itself was at fault, the file bytes a refusal is remembered for, the settings in force.
#[derive(Debug, Default)]
pub struct Observed {
    pub bytes: Option<Fingerprint>,
    pub file_fault: bool,
    pub refused: Option<Fingerprint>,
    pub good: Settings,
}


pub fn observation(observed: &Mutex<Observed>) -> MutexGuard<'_, Observed> {
    observed.lock().unwrap_or_else(PoisonError::into_inner)
}


/// The loader: reads the bytes once and records those very bytes; other bytes forget a remembered refusal (a bad file that comes back is refused again); a file already refused for its own fault yields the settings in force (no reload, no second log).
pub fn observed_load(path: &Path, observed: &Mutex<Observed>) -> Result<Settings, ConfigError> {
    observed_load_with(path, observed, &accept_entries())
}


/// The entries every read of the settings file judges first: the judge and the fixed-name paths it checks (a missing path is fine).
pub struct EntryCheck {
    pub judge: EntriesJudge,
    pub paths: Vec<PathBuf>,
}


/// A check that accepts everything: for a caller that judges no entry.
pub fn accept_entries() -> EntryCheck {
    EntryCheck {
        judge: accept_any_entries,
        paths: Vec::new(),
    }
}


/// The judge over the paths: the first refused entry is named.
pub fn check_entries(check: &EntryCheck) -> Result<(), DirAclError> {
    (check.judge)(&check.paths)
}


/// The entries judged, then the settings file read through one capped handle; a refused entry is a refused read naming the cause.
pub fn judged_read(path: &Path, check: &EntryCheck) -> Result<Vec<u8>, ConfigError> {
    check_entries(check).map_err(|error| ConfigError::WatchedFile {
        file: path.display().to_string(),
        reason: error.to_string(),
    })?;
    read_bytes_capped(path, MAX_SETTINGS_BYTES)
}


/// `observed_load` that judges `check` before every read: a refusal is remembered like a bad file (one log and audit until the entry or the file changes).
pub fn observed_load_with(path: &Path, observed: &Mutex<Observed>, check: &EntryCheck) -> Result<Settings, ConfigError> {
    let read = judged_read(path, check);
    let seen: Fingerprint = read.as_ref().map(Vec::clone).map_err(ToString::to_string);
    let mut state = observation(observed);
    state.bytes = Some(seen.clone());
    state.file_fault = false;
    if state.refused.as_ref() == Some(&seen) {
        Ok(state.good.clone())
    } else {
        state.refused = None;
        let file = path.display().to_string();
        let parsed = read.and_then(|bytes| parse_settings(&alphabet_text(&bytes, &file)?, &file));
        state.file_fault = parsed.is_err();
        parsed
    }
}


pub fn validate_channels(names: &[String]) -> Result<(), SettingsError> {
    if names.is_empty() {
        Err(SettingsError::NoChannel)
    } else if names.len() > KNOWN_CHANNELS.len() {
        Err(SettingsError::TooManyChannels)
    } else {
        names.iter().enumerate().try_for_each(|(index, name)| {
            if KNOWN_CHANNELS.iter().all(|channel| channel.key != name) {
                Err(SettingsError::UnknownChannel { index })
            } else if names.iter().take(index).any(|earlier| earlier == name) {
                Err(SettingsError::DuplicateChannel { index })
            } else {
                Ok(())
            }
        })
    }
}


/// A bare file name under the state directory: ASCII letters, digits, `-` and `_` only (no dot, so no cursor, settings or temporary file can be named), no leading `-`, no Windows device name.
pub fn validate_audit_file(name: &str) -> Result<(), SettingsError> {
    let plain = name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    let device = DEVICE_NAMES.contains(&name.to_ascii_lowercase().as_str());
    if name.is_empty() || name.len() > MAX_AUDIT_FILE_BYTES || name.starts_with('-') || !plain || device {
        Err(SettingsError::BadAuditFile)
    } else {
        Ok(())
    }
}


/// The audit file name the start needs: a settings file without one is refused.
pub fn audit_file_of(settings: &Settings) -> Result<&str, SettingsError> {
    settings.audit_file.as_deref().ok_or(SettingsError::NoAuditFile)
}


/// The first refused field is named, never clamped.
pub fn validate_settings(settings: &Settings) -> Result<(), SettingsError> {
    validate_channels(&settings.channels)?;
    settings.audit_file.as_deref().map_or(Ok(()), validate_audit_file)?;
    let checks = [
        (
            "poll_interval_seconds",
            (MIN_POLL_INTERVAL_SECONDS..=MAX_POLL_INTERVAL_SECONDS).contains(&settings.poll_interval_seconds),
        ),
        ("batch", (1..=MAX_EVENTS_PER_POLL).contains(&settings.batch)),
        (
            "defender_interval_seconds",
            (MIN_DEFENDER_INTERVAL_SECONDS..=MAX_DEFENDER_INTERVAL_SECONDS).contains(&settings.defender_interval_seconds),
        ),
        (
            "updates_interval_seconds",
            (MIN_UPDATES_INTERVAL_SECONDS..=MAX_UPDATES_INTERVAL_SECONDS).contains(&settings.updates_interval_seconds),
        ),
        (
            "max_output_bytes",
            (MIN_OUTPUT_BYTES..=MAX_OUTPUT_BYTES).contains(&settings.max_output_bytes),
        ),
        (
            "deadline_seconds",
            (MIN_DEADLINE_SECONDS..=MAX_DEADLINE_SECONDS).contains(&settings.deadline_seconds),
        ),
        (
            "max_spool_bytes",
            (MIN_SPOOL_BYTES..=MAX_SPOOL_BYTES_CEILING).contains(&settings.max_spool_bytes),
        ),
    ];
    checks
        .into_iter()
        .find(|(_, within)| !within)
        .map_or(Ok(()), |(field, _)| Err(SettingsError::Range { field }))
}


/// The known channels the validated settings select, in file order.
pub fn channels_of(settings: &Settings) -> Vec<Channel> {
    settings
        .channels
        .iter()
        .filter_map(|name| KNOWN_CHANNELS.iter().find(|channel| channel.key == name).copied())
        .collect()
}


pub fn settings_state(settings: &Settings) -> ConfigState {
    [
        ("channels", settings.channels.join(",")),
        ("poll_interval_seconds", settings.poll_interval_seconds.to_string()),
        ("batch", settings.batch.to_string()),
        ("defender_interval_seconds", settings.defender_interval_seconds.to_string()),
        ("updates_interval_seconds", settings.updates_interval_seconds.to_string()),
        ("max_output_bytes", settings.max_output_bytes.to_string()),
        ("deadline_seconds", settings.deadline_seconds.to_string()),
        ("max_spool_bytes", settings.max_spool_bytes.to_string()),
        ("audit_file", settings.audit_file.as_deref().unwrap_or("").to_owned()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


/// A reload that breaks a bound is refused (audited `denied`, logged), the old settings stay and the fault is the file's; an applied one becomes the settings in force.
pub fn settings_subscriber(observed: SharedObserved) -> Subscriber<Settings> {
    let validating = Arc::clone(&observed);
    Subscriber {
        section: SETTINGS_SECTION.to_owned(),
        validate: Box::new(move |settings| {
            let mut state = observation(&validating);
            let judged = validate_settings(settings).and_then(|()| {
                if settings.audit_file == state.good.audit_file {
                    Ok(())
                } else {
                    Err(SettingsError::AuditFileChanged)
                }
            });
            judged.map_err(|error| {
                state.file_fault = true;
                BoxError::from(error)
            })
        }),
        apply: Box::new(move |settings| {
            let mut state = observation(&observed);
            state.good = settings.clone();
            state.refused = None;
        }),
    }
}


/// The first file is loaded and validated here; later reloads are validated by the subscriber.
pub fn open_settings(
    path: PathBuf,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
    observed: SharedObserved,
) -> Result<ReloadEngine<Settings>, OpenError> {
    let first = observed_load(&path, &observed)?;
    open_settings_from(path, first, audit, context, observed, accept_entries())
}


/// `first` is the one start read (`observed_load` on `path`, so its bytes are recorded): the engine opens on it without reading the file again, so the audit path taken from it and the baseline are one read.
pub fn open_settings_from(
    path: PathBuf,
    first: Settings,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
    observed: SharedObserved,
    check: EntryCheck,
) -> Result<ReloadEngine<Settings>, OpenError> {
    let loading = Arc::clone(&observed);
    let start = Mutex::new(Some(first));
    let loader: Box<LoaderFn<Settings>> = Box::new(move || match start.lock().unwrap_or_else(PoisonError::into_inner).take() {
        Some(read) => Ok(read),
        None => observed_load_with(&path, &loading, &check),
    });
    let mut engine = open_engine(loader, settings_state, Vec::new(), audit, context)?;
    let in_force = current_config(&engine);
    validate_settings(&in_force)?;
    observation(&observed).good = Settings::clone(&in_force);
    engine.subscribers.push(settings_subscriber(observed));
    Ok(engine)
}
