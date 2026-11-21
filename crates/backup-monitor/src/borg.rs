//! Runs `borg list --json` read-only for one declared repository and keys the listing on `repository.id` (Unix only).

use crate::error::BackupError;
use crate::model::{BorgSource, Declarations, Limits, Listing};
use crate::parse::parse_borg;
use crate::restic::{valid_authority, valid_path, MAX_HOST_BYTES, MAX_LOCATION_BYTES, SSH_PROGRAM};
use crate::text::valid_text;
use core_config::secret_file::{open_secret, SecretFileError};
use core_config::trusted_dir::{open_trusted_dir, TrustedDirError};
use core_pg::scope::{tenant_of, TenantScope};
use net_topology::model::RunFailure;
use net_topology::runner::run_command_with_input;
use rustix::fs::{fstat, openat, Mode, OFlags};
use rustix::io::Errno;
use std::fs::{DirBuilder, File};
use std::io::{self, ErrorKind, PipeReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tracing::debug;


pub const BORG_PROGRAM: &str = "/usr/bin/borg";


pub const SSH_SCHEME_PREFIX: &str = "ssh://";


pub const MAX_PASSPHRASE_BYTES: u64 = 1024;


pub const BORG_DIRECTORY: &str = "borg";


pub const PRIVATE_MODE: u32 = 0o700;


pub const MODE_MASK: u32 = 0o777;


pub const LOCK_WAIT_SECONDS: &str = "1";


pub const BORG_RSH_OPTIONS: &str = "-o BatchMode=yes";


pub const LIST_ARGUMENTS: [&str; 4] = ["--lock-wait", LOCK_WAIT_SECONDS, "list", "--json"];


pub const LOCK_ROSTER: &str = "lock.roster";


const ROSTER_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC).union(OFlags::NONBLOCK);


pub const ANSWER_NO: &str = "no";


pub const PASSPHRASE_DESCRIPTOR: &str = "0";


/// A fixed category per failure: no output, stderr, location or passphrase text is ever kept.
#[derive(Debug, Error)]
pub enum BorgError {
    #[error("borg declaration refused")]
    Refused,
    #[error("local repository is not owned by the monitor")]
    LocalNotOwned,
    #[error("passphrase file refused")]
    PassphraseFile,
    #[error("borg base directory refused")]
    BaseDir,
    #[error("borg timed out")]
    Timeout,
    #[error("borg output larger than its cap")]
    Oversized,
    #[error("borg failed with exit code {code:?}")]
    Failed { code: Option<i32> },
    #[error("borg could not be started")]
    Spawn,
    #[error("borg I/O failed")]
    Io,
    #[error("borg cannot be waited on")]
    Unwaitable,
    #[error("borg listing refused: {0}")]
    Listing(#[from] BackupError),
}


impl From<RunFailure> for BorgError {
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


/// The repositories that will run (declared name and source) and the indexes of the ones refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BorgPlan<'a> {
    pub runnable: Vec<(&'a str, &'a BorgSource)>,
    pub refused: Vec<usize>,
}


fn valid_remote_path(path: &str) -> bool {
    valid_path(&format!("/{path}")) && !path.split('/').any(|segment| segment.starts_with('-'))
}


fn valid_ssh_location(rest: &str) -> bool {
    rest.split_once('@')
        .and_then(|(user, tail)| tail.split_once('/').map(|(authority, path)| (user, authority, path)))
        .is_some_and(|(user, authority, path)| valid_text(user, MAX_HOST_BYTES) && valid_authority(authority) && valid_remote_path(path))
}


/// An absolute local path or `ssh://<user>@<host>[:<port>]/<path>`, ASCII only, no part starting with `-`.
pub fn valid_location(text: &str) -> bool {
    text.len() <= MAX_LOCATION_BYTES
        && match text.strip_prefix(SSH_SCHEME_PREFIX) {
            Some(rest) => valid_ssh_location(rest),
            None => valid_path(text),
        }
}


pub fn valid_source(source: &BorgSource) -> bool {
    valid_location(&source.location) && source.passphrase_file.len() <= MAX_LOCATION_BYTES && valid_path(&source.passphrase_file)
}


fn not_owned(errno: Errno) -> BorgError {
    let kind = io::Error::from(errno).kind();
    debug!(?kind, "local repository unreadable");
    BorgError::LocalNotOwned
}


fn not_trusted(error: TrustedDirError) -> BorgError {
    let refusal = error.to_string();
    debug!(refusal, "local repository refused");
    BorgError::LocalNotOwned
}


fn owned_by(owner: u32, euid: u32) -> Result<(), BorgError> {
    if owner == euid {
        Ok(())
    } else {
        Err(BorgError::LocalNotOwned)
    }
}


/// A local repository is accepted only through `open_trusted_dir` (no ancestor or link anyone else can swap, directory owned by `euid`) and when its `lock.roster`, if present, is owned by `euid`.
pub fn local_owned(location: &str, euid: u32) -> Result<(), BorgError> {
    if location.starts_with(SSH_SCHEME_PREFIX) {
        Ok(())
    } else {
        let directory = open_trusted_dir(Path::new(location), euid).map_err(not_trusted)?;
        match openat(&directory, LOCK_ROSTER, ROSTER_FLAGS, Mode::empty()) {
            Ok(roster) => owned_by(fstat(&roster).map_err(not_owned)?.st_uid, euid),
            Err(Errno::NOENT) => Ok(()),
            Err(errno) => Err(not_owned(errno)),
        }
    }
}


/// Splits the declared repositories that carry a `borg` entry and no `restic` entry into the runnable ones and the refused indexes.
pub fn plan(declarations: &Declarations, euid: u32) -> BorgPlan<'_> {
    let (runnable, refused): (Vec<_>, Vec<_>) = declarations
        .repositories
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.restic.is_none())
        .filter_map(|(index, entry)| entry.borg.as_ref().map(|source| (index, entry.repository.as_str(), source)))
        .partition(|(_, _, source)| valid_source(source) && local_owned(&source.location, euid).is_ok());
    BorgPlan {
        runnable: runnable.iter().map(|(_, name, source)| (*name, *source)).collect(),
        refused: refused.iter().map(|(index, _, _)| *index).collect(),
    }
}


fn passphrase_refusal(error: SecretFileError) -> BorgError {
    let refusal = error.to_string();
    debug!(refusal, "passphrase file refused");
    BorgError::PassphraseFile
}


/// At most `MAX_PASSPHRASE_BYTES` are accepted; one byte more is refused before anything is spawned.
pub fn read_capped(reader: &mut dyn Read) -> Result<Vec<u8>, BorgError> {
    let mut bytes = Vec::new();
    Read::take(reader, MAX_PASSPHRASE_BYTES + 1).read_to_end(&mut bytes).map_err(|error| {
        let kind = error.kind();
        debug!(?kind, "passphrase file unreadable");
        BorgError::PassphraseFile
    })?;
    if u64::try_from(bytes.len()).map_or(true, |count| count > MAX_PASSPHRASE_BYTES) {
        Err(BorgError::PassphraseFile)
    } else {
        Ok(bytes)
    }
}


pub fn io_failure(error: io::Error) -> BorgError {
    let kind = error.kind();
    debug!(?kind, "borg input pipe failed");
    BorgError::Io
}


/// The whole passphrase goes into the pipe; at most `MAX_PASSPHRASE_BYTES` fit even a one-page pipe, so this never blocks.
pub fn fill(writer: &mut dyn Write, bytes: &[u8]) -> Result<(), BorgError> {
    writer.write_all(bytes).map_err(io_failure)
}


fn passphrase_pipe(bytes: &[u8]) -> Result<PipeReader, BorgError> {
    let (reader, mut writer) = io::pipe().map_err(io_failure)?;
    fill(&mut writer, bytes)?;
    Ok(reader)
}


fn base_refusal(error: TrustedDirError) -> BorgError {
    let refusal = error.to_string();
    debug!(refusal, "borg base directory refused");
    BorgError::BaseDir
}


fn base_io(error: io::Error) -> BorgError {
    let kind = error.kind();
    debug!(?kind, "borg base directory unusable");
    BorgError::BaseDir
}


/// True when `mode` is a directory with exactly the owner permissions.
pub fn private_directory(is_directory: bool, mode: u32) -> bool {
    is_directory && mode & MODE_MASK == PRIVATE_MODE
}


pub fn make_private_directory(path: &Path) -> io::Result<()> {
    DirBuilder::new().mode(PRIVATE_MODE).create(path)
}


fn make_level(parent: &Path, name: &str, euid: u32, make: fn(&Path) -> io::Result<()>) -> Result<PathBuf, BorgError> {
    let level = parent.join(name);
    match make(&level) {
        Err(error) if error.kind() != ErrorKind::AlreadyExists => Err(base_io(error)),
        Ok(()) | Err(_) => open_trusted_dir(&level, euid).map_err(base_refusal).map(|_| level),
    }
}


/// `<state>/borg/<tenant>`: `<state>` is checked first, each level is made 0700 and checked before the next, so nothing is created below an unchecked directory.
pub fn base_directory(state: &Path, tenant: &TenantScope, euid: u32) -> Result<PathBuf, BorgError> {
    base_directory_with(state, tenant, euid, make_private_directory)
}


/// `base_directory` with the directory maker injected, so a failing `mkdir` can be tested.
pub fn base_directory_with(state: &Path, tenant: &TenantScope, euid: u32, make: fn(&Path) -> io::Result<()>) -> Result<PathBuf, BorgError> {
    open_trusted_dir(state, euid).map_err(base_refusal)?;
    let base = make_level(&make_level(state, BORG_DIRECTORY, euid, make)?, tenant_of(tenant), euid, make)?;
    let metadata = File::from(open_trusted_dir(&base, euid).map_err(base_refusal)?)
        .metadata()
        .map_err(base_io)?;
    if private_directory(metadata.is_dir(), metadata.mode()) {
        Ok(base)
    } else {
        Err(BorgError::BaseDir)
    }
}


/// The environment is cleared first: the passphrase travels on standard input only, and `ssh` is named in full.
pub fn environment(base: &str) -> Vec<(String, String)> {
    vec![
        ("BORG_RSH".to_owned(), format!("{SSH_PROGRAM} {BORG_RSH_OPTIONS}")),
        ("BORG_PASSPHRASE_FD".to_owned(), PASSPHRASE_DESCRIPTOR.to_owned()),
        ("BORG_RELOCATED_REPO_ACCESS_IS_OK".to_owned(), ANSWER_NO.to_owned()),
        ("BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK".to_owned(), ANSWER_NO.to_owned()),
        ("HOME".to_owned(), base.to_owned()),
        ("BORG_BASE_DIR".to_owned(), base.to_owned()),
        ("TMPDIR".to_owned(), base.to_owned()),
    ]
}


/// Runs `borg --lock-wait 1 list --json <location>` once (shared repository lock, no `info`) within `deadline`; returns the raw listing.
pub fn run_raw(
    program: &Path,
    source: &BorgSource,
    tenant: &TenantScope,
    state: &Path,
    limits: &Limits,
    deadline: Duration,
) -> Result<Vec<u8>, BorgError> {
    if !valid_source(source) {
        Err(BorgError::Refused)
    } else {
        let euid = rustix::process::geteuid().as_raw();
        local_owned(&source.location, euid)?;
        let mut handle = open_secret(Path::new(&source.passphrase_file)).map_err(passphrase_refusal)?;
        let passphrase = read_capped(&mut handle)?;
        let base = base_directory(state, tenant, euid)?;
        let base_text = base.to_str().ok_or(BorgError::BaseDir)?;
        let variables = environment(base_text);
        let pairs: Vec<(&str, &str)> = variables.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
        let arguments: Vec<&str> = LIST_ARGUMENTS.iter().copied().chain([source.location.as_str()]).collect();
        let input = passphrase_pipe(&passphrase)?;
        Ok(run_command_with_input(program, &arguments, &pairs, input, limits.max_bytes, deadline)?)
    }
}


/// The listing of a raw run, keyed on `repository.id` of that same output.
pub fn parse_run(raw: &[u8], source: &BorgSource, limits: &Limits) -> Result<Listing, BorgError> {
    Ok(parse_borg(raw, source.hostname_from_name, limits)?)
}


pub fn snapshot_listing(
    program: &Path,
    source: &BorgSource,
    tenant: &TenantScope,
    state: &Path,
    limits: &Limits,
    deadline: Duration,
) -> Result<Listing, BorgError> {
    parse_run(&run_raw(program, source, tenant, state, limits, deadline)?, source, limits)
}
