//! Runs `restic cat config` and `restic snapshots` read-only for one declared repository and keys the listing on the config id (Unix only).

use crate::compare::{below_floor, below_floor_named, compare};
use crate::error::BackupError;
use crate::model::{Declarations, Finding, Limits, Listing, ResticSource};
use crate::parse::parse_restic;
use crate::text::{valid_id, valid_text};
use core_config::secret_file::{open_secret, SecretFileError};
use net_topology::model::RunFailure;
use net_topology::runner::run_command;
use serde::Deserialize;
use std::fs::{symlink_metadata, File};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::debug;


pub const MAX_LOCATION_BYTES: usize = 1024;


pub const MAX_HOST_BYTES: usize = 253;


pub const MAX_PORT_DIGITS: usize = 5;


pub const MIN_PORT: u16 = 1;


pub const CONFIG_CAP_BYTES: u64 = 4096;


pub const SFTP_SCHEME: &str = "sftp";


pub const SFTP_PREFIX: &str = "sftp:";


pub const SSH_PROGRAM: &str = "/usr/bin/ssh";


pub const REST_SCHEME: &str = "rest";


pub const HTTPS_PREFIX: &str = "https://";


pub const COMMON_FLAGS: [&str; 3] = ["--no-cache", "--no-lock", "--json"];


pub const CONFIG_VERB: [&str; 2] = ["cat", "config"];


pub const SNAPSHOTS_VERB: [&str; 1] = ["snapshots"];


/// A fixed category per failure: no output, stderr, location or password text is ever kept.
#[derive(Debug, Error)]
pub enum ResticError {
    #[error("restic declaration refused")]
    Refused,
    #[error("password file refused")]
    PasswordFile,
    #[error("password file replaced during the run")]
    PasswordFileChanged,
    #[error("restic timed out")]
    Timeout,
    #[error("restic output larger than its cap")]
    Oversized,
    #[error("restic failed with exit code {code:?}")]
    Failed { code: Option<i32> },
    #[error("restic could not be started")]
    Spawn,
    #[error("restic I/O failed")]
    Io,
    #[error("restic cannot be waited on")]
    Unwaitable,
    #[error("restic config refused")]
    BadConfig,
    #[error("restic listing refused: {0}")]
    Listing(#[from] BackupError),
}


impl From<RunFailure> for ResticError {
    fn from(failure: RunFailure) -> Self {
        match failure {
            RunFailure::TimedOut => Self::Timeout,
            RunFailure::TooLarge => Self::Oversized,
            RunFailure::Failed { code, .. } => Self::Failed { code },
            RunFailure::Spawn => Self::Spawn,
            RunFailure::Io => Self::Io,
            RunFailure::Refused => Self::Refused,
            RunFailure::Unwaitable => Self::Unwaitable,
        }
    }
}


/// The raw output of one run: the config id (the repository key) and the snapshots JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRun {
    pub key: String,
    pub snapshots: Vec<u8>,
}


/// The repositories that will run (declared name and source) and the indexes of the ones refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResticPlan<'a> {
    pub runnable: Vec<(&'a str, &'a ResticSource)>,
    pub refused: Vec<usize>,
}


#[derive(Deserialize)]
pub struct ConfigFile {
    pub id: String,
}


fn path_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '/' | '+')
}


/// An absolute path of `[A-Za-z0-9._+/-]` without a `..` segment.
pub fn valid_path(text: &str) -> bool {
    text.starts_with('/') && text.chars().all(path_character) && !text.split('/').any(|segment| segment == "..")
}


/// A port of 1 to 5 digits whose value is 1 to 65535.
pub fn valid_port(port: &str) -> bool {
    (1..=MAX_PORT_DIGITS).contains(&port.len())
        && port.chars().all(|digit| digit.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|value| value >= MIN_PORT)
}


/// `host` or `host:port`, the port 1 to 65535.
pub fn valid_authority(text: &str) -> bool {
    match text.split_once(':') {
        None => valid_text(text, MAX_HOST_BYTES),
        Some((host, port)) => valid_text(host, MAX_HOST_BYTES) && valid_port(port),
    }
}


fn valid_sftp(rest: &str) -> bool {
    rest.split_once('@')
        .and_then(|(user, tail)| tail.split_once(':').map(|(host, path)| (user, host, path)))
        .is_some_and(|(user, host, path)| valid_text(user, MAX_HOST_BYTES) && valid_text(host, MAX_HOST_BYTES) && valid_path(path))
}


fn valid_rest(rest: &str) -> bool {
    rest.strip_prefix(HTTPS_PREFIX)
        .and_then(|tail| tail.split_once('/'))
        .is_some_and(|(authority, path)| valid_authority(authority) && valid_path(&format!("/{path}")))
}


/// A local absolute path, `sftp:<user>@<host>:<absolute path>` or `rest:https://<host>[:port]/<path>`, ASCII only, no credentials in the text.
pub fn valid_location(text: &str) -> bool {
    text.len() <= MAX_LOCATION_BYTES
        && match text.split_once(':') {
            None => valid_path(text),
            Some((SFTP_SCHEME, rest)) => valid_sftp(rest),
            Some((REST_SCHEME, rest)) => valid_rest(rest),
            Some(_) => false,
        }
}


pub fn valid_source(source: &ResticSource) -> bool {
    valid_location(&source.location) && source.password_file.len() <= MAX_LOCATION_BYTES && valid_path(&source.password_file)
}


fn has_borg(declarations: &Declarations, index: usize) -> bool {
    declarations.repositories.get(index).is_some_and(|entry| entry.borg.is_some())
}


/// Splits the declared repositories that carry a `restic` entry into the runnable ones and the refused indexes; an entry that also carries `borg` is refused.
pub fn plan(declarations: &Declarations) -> ResticPlan<'_> {
    let declared: Vec<(usize, &str, &ResticSource)> = declarations
        .repositories
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| entry.restic.as_ref().map(|source| (index, entry.repository.as_str(), source)))
        .collect();
    ResticPlan {
        runnable: declared
            .iter()
            .filter(|(index, _, source)| valid_source(source) && !has_borg(declarations, *index))
            .map(|(_, name, source)| (*name, *source))
            .collect(),
        refused: declared
            .iter()
            .filter(|(index, _, source)| !valid_source(source) || has_borg(declarations, *index))
            .map(|(index, _, _)| *index)
            .collect(),
    }
}


fn password_failure(error: SecretFileError) -> ResticError {
    let refusal = error.to_string();
    debug!(refusal, "password file refused");
    ResticError::PasswordFile
}


/// The environment is cleared, so restic cannot find `ssh` on a `PATH`: an `sftp:` location names `SSH_PROGRAM` and `user@host` explicitly.
pub fn sftp_transport(location: &str) -> Vec<String> {
    location
        .strip_prefix(SFTP_PREFIX)
        .and_then(|rest| rest.split_once(':'))
        .map_or_else(Vec::new, |(target, _)| {
            vec!["-o".to_owned(), format!("sftp.command={SSH_PROGRAM} -o BatchMode=yes {target} -s sftp")]
        })
}


fn command_arguments<'a>(source: &'a ResticSource, transport: &'a [String], verb: &[&'a str]) -> Vec<&'a str> {
    transport
        .iter()
        .map(String::as_str)
        .chain(["-r", source.location.as_str(), "--password-file", source.password_file.as_str()])
        .chain(COMMON_FLAGS)
        .chain(verb.iter().copied())
        .collect()
}


/// The config `id` (64 lowercase hexadecimal digits); the parse error is never kept, serde repeats the peer's text.
pub fn config_id(bytes: &[u8]) -> Result<String, ResticError> {
    let parsed = serde_json::from_slice::<ConfigFile>(bytes).map_err(|error| {
        let category = error.classify();
        debug!(?category, "restic config is not JSON");
        ResticError::BadConfig
    })?;
    if valid_id(&parsed.id) {
        Ok(parsed.id)
    } else {
        Err(ResticError::BadConfig)
    }
}


/// The path still names the file that was checked (same device and inode); restic re-opens the path, so a swap is detected after the run.
pub fn unchanged(checked: &File, path: &str) -> Result<(), ResticError> {
    let same = checked
        .metadata()
        .and_then(|before| symlink_metadata(path).map(|now| (before.dev(), before.ino()) == (now.dev(), now.ino())))
        .map_err(|error| {
            let kind = error.kind();
            debug!(?kind, "password file identity unreadable");
            ResticError::Io
        })?;
    if same {
        Ok(())
    } else {
        Err(ResticError::PasswordFileChanged)
    }
}


/// Runs `cat config` then `snapshots` (cleared environment, own process group, capped stdout) within `deadline` in total.
pub fn run_raw(program: &Path, source: &ResticSource, limits: &Limits, deadline: Duration) -> Result<RawRun, ResticError> {
    if !valid_source(source) {
        Err(ResticError::Refused)
    } else {
        let checked = open_secret(Path::new(&source.password_file)).map_err(password_failure)?;
        let transport = sftp_transport(&source.location);
        let start = Instant::now();
        let config = run_command(program, &command_arguments(source, &transport, &CONFIG_VERB), CONFIG_CAP_BYTES, deadline)?;
        let key = config_id(&config)?;
        let remaining = deadline.saturating_sub(start.elapsed());
        let snapshots = run_command(
            program,
            &command_arguments(source, &transport, &SNAPSHOTS_VERB),
            limits.max_bytes,
            remaining,
        )?;
        unchanged(&checked, &source.password_file)?;
        Ok(RawRun { key, snapshots })
    }
}


/// The listing of a raw run, keyed on the config id.
pub fn parse_run(raw: &RawRun, limits: &Limits) -> Result<Listing, ResticError> {
    Ok(parse_restic(raw.snapshots.as_slice(), &raw.key, limits)?)
}


pub fn snapshot_listing(program: &Path, source: &ResticSource, limits: &Limits, deadline: Duration) -> Result<Listing, ResticError> {
    parse_run(&run_raw(program, source, limits, deadline)?, limits)
}


/// Findings for one declared repository: `compare` against the previous run (a different config id is `RepositoryChanged`), the floor by declared name.
pub fn findings(name: &str, previous: Option<&Listing>, current: &Listing, declarations: &Declarations) -> Vec<Finding> {
    let compared = previous.map_or_else(
        || below_floor(current, declarations).into_iter().collect(),
        |before| compare(before, current, declarations),
    );
    let named = (name != current.repository)
        .then(|| below_floor_named(name, current.snapshots.len(), declarations))
        .flatten();
    compared.into_iter().chain(named).collect()
}
