use crate::model::Identity;
use crate::types::CommandSource;
use std::fs::{self, DirEntry, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};


/// Envelope files delivered to one agent per subscription.
pub const MAX_COMMAND_FILES: usize = 64;


pub const MAX_ENVELOPE_FILE_BYTES: u64 = 65_536;


/// One directory per agent, named `<tenant>:<agent-id>`: the colon is not in the identity charset, so no path can escape `root`.
pub fn agent_directory(root: &Path, identity: &Identity) -> PathBuf {
    root.join(format!("{}:{}", identity.tenant, identity.agent_id))
}


pub fn read_envelope(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(MAX_ENVELOPE_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).is_ok_and(|length| length > MAX_ENVELOPE_FILE_BYTES) {
        Err(io::Error::other("envelope file too large"))
    } else {
        Ok(bytes)
    }
}


pub fn paths_of(entries: impl Iterator<Item = io::Result<DirEntry>>) -> io::Result<Vec<PathBuf>> {
    entries.map(|entry| entry.map(|found| found.path())).collect()
}


/// At most `MAX_COMMAND_FILES` files in name order, each at most `MAX_ENVELOPE_FILE_BYTES`.
pub fn read_envelopes(directory: &Path) -> io::Result<Vec<Vec<u8>>> {
    let mut paths = paths_of(fs::read_dir(directory)?)?;
    paths.sort();
    paths.iter().take(MAX_COMMAND_FILES).map(|path| read_envelope(path)).collect()
}


/// The command source of the server example; an unreadable directory means no command, logged.
pub fn command_source(root: PathBuf) -> CommandSource {
    Box::new(move |identity: Identity| {
        let envelopes = read_envelopes(&agent_directory(&root, &identity)).unwrap_or_else(|error| {
            tracing::warn!(%error, "no command envelopes read");
            Vec::new()
        });
        Box::pin(tokio_stream::iter(envelopes))
    })
}
