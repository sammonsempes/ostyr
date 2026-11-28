use crate::types::SenderTable;
use core_config::error::ConfigError;
use core_config::parse::{open_regular, parse_document, read_text_capped};
use core_config::strict::{refuse, refuse_features, refuse_forbidden_bytes, Rules};
use core_config::types::{ConfigState, LoaderFn};
use core_pg::scope::tenant_scope;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};


pub const MAX_TRACE_SENDERS: usize = 256;


pub const MAX_SENDERS_FILE_BYTES: u64 = 65_536;


pub const DIGEST_CHARS: usize = 64;


pub const FINGERPRINT_CHARS: usize = 8;


pub const STATE_PREFIX: &str = "senders.";


pub const STATE_DOMAIN: &str = "ostyr-sender-state:";


pub const SENDERS_KEY: &str = "senders";


pub const INVALID_FILE: &str = "the document is not a valid senders file";


pub const SENDERS_RULES: Rules<'static> = Rules {
    list_key: SENDERS_KEY,
    invalid_text: INVALID_FILE,
    allow_flow: false,
    show_line: false,
};


/// The operator-declared senders: a name and the SHA-256 of its token, never a tenant and never the token.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendersFile {
    pub senders: Vec<SenderEntry>,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderEntry {
    pub name: String,
    pub token_sha256: String,
}


pub fn valid_digest(digest: &str) -> bool {
    digest.len() == DIGEST_CHARS && digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}


/// The first grammar failure, as the index and the field name (never the value).
pub fn first_bad_entry(entries: &[SenderEntry]) -> Option<(usize, &'static str)> {
    entries.iter().enumerate().find_map(|(index, entry)| {
        if tenant_scope(&entry.name).is_err() {
            Some((index, "name"))
        } else if !valid_digest(&entry.token_sha256) {
            Some((index, "token_sha256"))
        } else {
            None
        }
    })
}


/// The indexes of the first two equal keys.
pub fn first_duplicate<'a>(keys: impl Iterator<Item = &'a str>) -> Option<(usize, usize)> {
    keys.enumerate()
        .try_fold(BTreeMap::new(), |mut seen, (index, key)| match seen.insert(key, index) {
            Some(first) => Err((first, index)),
            None => Ok(seen),
        })
        .err()
}


/// Refuses the whole file on the first defect; a refusal names the index and the field, never a digest.
pub fn validate_senders(file: &str, parsed: SendersFile) -> Result<SenderTable, ConfigError> {
    if parsed.senders.len() > MAX_TRACE_SENDERS {
        Err(refuse(file, format!("senders[{MAX_TRACE_SENDERS}]: too many senders")))
    } else if let Some((index, field)) = first_bad_entry(&parsed.senders) {
        Err(refuse(file, format!("senders[{index}].{field} is outside its grammar")))
    } else if let Some((first, second)) = first_duplicate(parsed.senders.iter().map(|entry| entry.name.as_str())) {
        Err(refuse(file, format!("senders[{second}].name repeats senders[{first}].name")))
    } else if let Some((first, second)) = first_duplicate(parsed.senders.iter().map(|entry| entry.token_sha256.as_str())) {
        Err(refuse(
            file,
            format!("senders[{second}].token_sha256 repeats senders[{first}].token_sha256"),
        ))
    } else {
        Ok(parsed.senders.into_iter().map(|entry| (entry.token_sha256, entry.name)).collect())
    }
}


/// Reads at most `MAX_SENDERS_FILE_BYTES` from `reader` and parses exactly those bytes; the byte cap bounds the entries built.
pub fn parse_senders(reader: &mut dyn Read, file: &str) -> Result<SenderTable, ConfigError> {
    let text = read_text_capped(reader, file, MAX_SENDERS_FILE_BYTES)?;
    refuse_forbidden_bytes(&text, file)?;
    refuse_features(&text, file, SENDERS_RULES)?;
    let parsed = parse_document::<SendersFile>(&text, file)?;
    validate_senders(file, parsed)
}


/// A FIFO or device at the path is refused on the opened handle.
pub fn load_senders(path: &Path) -> Result<SenderTable, ConfigError> {
    let file = path.display().to_string();
    let mut handle = open_regular(path, &file)?;
    parse_senders(&mut handle, &file)
}


pub fn senders_loader(path: PathBuf) -> Box<LoaderFn<SenderTable>> {
    Box::new(move || load_senders(&path))
}


/// A short domain-separated fingerprint of the digest, so a rotated token shows as a change in the audit without the digest itself reaching it.
pub fn fingerprint(digest: &str) -> String {
    let full = format!("{:x}", Sha256::digest(format!("{STATE_DOMAIN}{digest}").as_bytes()));
    full.chars().take(FINGERPRINT_CHARS).collect()
}


/// One key per sender: `senders.<name>` to the fingerprint of its digest.
pub fn senders_state(table: &SenderTable) -> ConfigState {
    table
        .iter()
        .map(|(digest, name)| (format!("{STATE_PREFIX}{name}"), fingerprint(digest)))
        .collect()
}
