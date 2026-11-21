use crate::model::ChannelState;
use agent_channel::spool::{suffixed, SENDING_SUFFIX};
use std::fs;
use std::io;
use std::path::Path;
use tracing::warn;


pub fn file_len(path: &Path) -> io::Result<u64> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}


pub fn pending_bytes(spool: &Path) -> io::Result<u64> {
    Ok(file_len(spool)?.saturating_add(file_len(&suffixed(spool, SENDING_SUFFIX))?))
}


pub fn fits(pending: u64, lines: &[String], limit: u64) -> bool {
    let added: u64 = lines
        .iter()
        .map(|line| u64::try_from(line.len()).unwrap_or(u64::MAX).saturating_add(1))
        .sum();
    pending == 0 || pending.saturating_add(added) <= limit
}


pub fn note_pause(state: &mut ChannelState, blocked: bool, pending: u64, limit: u64) {
    let entered = blocked && state.paused_polls == 0;
    let left = (!blocked && state.paused_polls > 0).then_some(state.paused_polls);
    if entered {
        warn!(pending, limit, "spool full, reading paused");
    }
    if let Some(polls) = left {
        warn!(polls, "spool has room again, reading resumes");
    }
    state.paused_polls = if blocked { state.paused_polls.saturating_add(1) } else { 0 };
}
