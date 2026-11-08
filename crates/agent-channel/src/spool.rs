use crate::agent_app::AgentFile;
use crate::app::{bounded_lines, BoundedLine};
use crate::error::AppError;
use crate::model::DEFAULT_MAX_MESSAGE_BYTES;
use crate::proto::EventBatch;
use core_audit::log::owner_only;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};


/// Event lines claimed from the spool file per run; the rest goes back to the spool for the next run.
pub const MAX_SPOOL_BATCHES: usize = 1_000;


pub const SENDING_SUFFIX: &str = ".sending";


pub const TEMPORARY_SUFFIX: &str = ".tmp";


/// The claimed batch and the file holding it until every batch is acknowledged.
#[derive(Debug, Clone)]
pub struct Spool {
    pub batches: Vec<EventBatch>,
    pub sending: PathBuf,
    pub sending_bytes: u64,
}


/// The sequence file: the last sequence handed out and how many lines the claimed batch holds (its sequences are `used - count + 1 ..= used`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SequenceState {
    pub used: u64,
    pub count: u64,
}


pub fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}


/// A missing file is the initial state; anything else that is not `<used> <count>` is refused.
pub fn read_sequence(path: &Path) -> Result<SequenceState, AppError> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let mut fields = text.split_whitespace().map(str::parse::<u64>);
            match (fields.next(), fields.next(), fields.next()) {
                (Some(Ok(used)), Some(Ok(count)), None) => Ok(SequenceState { used, count }),
                _ => Err(AppError::Sequence(path.to_path_buf())),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(SequenceState::default()),
        Err(error) => Err(AppError::Io(error)),
    }
}


/// Written to a temporary file, synced, then renamed over the old one.
pub fn write_sequence(path: &Path, state: SequenceState) -> Result<(), AppError> {
    let temporary = suffixed(path, TEMPORARY_SUFFIX);
    let mut out = owner_only(OpenOptions::new().write(true).create(true).truncate(true)).open(&temporary)?;
    writeln!(out, "{} {}", state.used, state.count)?;
    out.sync_all()?;
    Ok(fs::rename(&temporary, path)?)
}


/// The text lines of a reader, an oversized one (more than `DEFAULT_MAX_MESSAGE_BYTES`) skipped with a logged line number.
pub fn spool_texts<Input: BufRead>(reader: &mut Input) -> impl Iterator<Item = io::Result<String>> + '_ {
    bounded_lines(reader, DEFAULT_MAX_MESSAGE_BYTES)
        .enumerate()
        .filter_map(|(index, line)| match line {
            Ok(BoundedLine::Text(text)) => Some(Ok(text)),
            Ok(BoundedLine::Oversized) => {
                tracing::warn!(line = index + 1, "oversized spool line refused");
                None
            }
            Err(error) => Some(Err(error)),
        })
}


/// How many lines the next claim takes: the first `MAX_SPOOL_BATCHES` of the spool.
pub fn count_lines(path: &Path) -> io::Result<u64> {
    let mut reader = BufReader::new(File::open(path)?);
    let taken = spool_texts(&mut reader).take(MAX_SPOOL_BATCHES).collect::<io::Result<Vec<_>>>()?;
    Ok(taken.len() as u64)
}


/// Appends the lines to the spool, creating it only when there is something to append; returns whether it appended.
pub fn append_back(lines: impl Iterator<Item = io::Result<String>>, spool: &Path) -> io::Result<bool> {
    let mut rest = lines.peekable();
    if rest.peek().is_some() {
        let mut out = owner_only(OpenOptions::new().append(true).create(true)).open(spool)?;
        rest.try_for_each(|line| writeln!(out, "{}", line?))?;
        out.sync_all()?;
        Ok(true)
    } else {
        Ok(false)
    }
}


/// Rewrites the claimed file to the given lines (temporary file, sync, rename), so a line returned to the spool is not returned again.
pub fn rewrite_lines(path: &Path, lines: &[String]) -> io::Result<()> {
    let temporary = suffixed(path, TEMPORARY_SUFFIX);
    let mut out = owner_only(OpenOptions::new().write(true).create(true).truncate(true)).open(&temporary)?;
    lines.iter().try_for_each(|line| writeln!(out, "{line}"))?;
    out.sync_all()?;
    fs::rename(&temporary, path)
}


/// The first `count` lines of the claimed file; any further line goes back to the spool and the claimed file is cut to the first lines.
pub fn load_claimed(sending: &Path, spool: &Path, count: u64) -> io::Result<Vec<String>> {
    let (first, returned) = {
        let mut reader = BufReader::new(File::open(sending)?);
        let mut texts = spool_texts(&mut reader);
        let wanted = usize::try_from(count).unwrap_or(MAX_SPOOL_BATCHES).min(MAX_SPOOL_BATCHES);
        let first = texts.by_ref().take(wanted).collect::<io::Result<Vec<_>>>()?;
        let returned = append_back(texts, spool)?;
        (first, returned)
    };
    if returned {
        rewrite_lines(sending, &first)?;
    }
    Ok(first)
}


/// Renames a fresh spool to the sending file after recording the new sequences, unless a sending file is already there (a crashed run).
pub fn claim_fresh(file: &AgentFile, sending: &Path) -> Result<(), AppError> {
    if !sending.try_exists()? && file.spool_file.try_exists()? {
        let count = count_lines(&file.spool_file)?;
        let state = read_sequence(&file.sequence_file)?;
        write_sequence(
            &file.sequence_file,
            SequenceState {
                used: state.used + count,
                count,
            },
        )?;
        Ok(fs::rename(&file.spool_file, sending)?)
    } else {
        Ok(())
    }
}


/// One event batch per line, numbered from `first`.
pub fn batches_of(lines: Vec<String>, first: u64, file: &AgentFile) -> Vec<EventBatch> {
    (first..)
        .zip(lines)
        .map(|(sequence, text)| EventBatch {
            sequence,
            ecs_json: text.into_bytes(),
            tenant: file.tenant.clone(),
            agent_id: file.agent_id.clone(),
        })
        .collect()
}


/// Claims the spool: sequences continue from the sequence file across runs and a crashed claim is resent with the same sequences.
pub fn claim_spool(file: &AgentFile) -> Result<Spool, AppError> {
    let sending = suffixed(&file.spool_file, SENDING_SUFFIX);
    claim_fresh(file, &sending)?;
    let state = read_sequence(&file.sequence_file)?;
    let (lines, sending_bytes) = if sending.try_exists()? {
        let before = fs::metadata(&sending)?.len();
        let lines = load_claimed(&sending, &file.spool_file, state.count)?;
        (lines, before.min(fs::metadata(&sending)?.len()))
    } else {
        (Vec::new(), 0)
    };
    let first = (state.used + 1).saturating_sub(state.count);
    Ok(Spool {
        batches: batches_of(lines, first, file),
        sending,
        sending_bytes,
    })
}


/// Removes the claimed file once every batch of it is acknowledged and nothing was appended to it since it was read; otherwise it stays.
pub fn finish_spool(spool: &Spool, acknowledged: &[u64]) -> Result<(), AppError> {
    if spool.batches.iter().all(|batch| acknowledged.contains(&batch.sequence)) && spool.sending.try_exists()? {
        if fs::metadata(&spool.sending)?.len() == spool.sending_bytes {
            Ok(fs::remove_file(&spool.sending)?)
        } else {
            tracing::warn!("claimed spool grew after it was read, kept for the next run");
            Ok(())
        }
    } else {
        Ok(())
    }
}
