use crate::packs::{MAX_ENTRIES, MAX_FILE_BYTES, MAX_PACKS};
use core_config::error::ConfigError;
use sha2::{Digest, Sha256};
use thiserror::Error;


pub const MAX_SHOWN_ID: usize = 64;


pub const DIGEST_CHARS: usize = 12;


pub const DIGEST_MARK: char = '#';


#[derive(Debug, Error)]
pub enum PackError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: larger than {} bytes", MAX_FILE_BYTES)]
    FileTooLarge { file: String },
    #[error("{file}: {count} packs, at most {} allowed", MAX_PACKS)]
    TooManyPacks { file: String, count: usize },
    #[error("{file}: pack `{}`: invalid `{field}`", shown_id(.pack))]
    Invalid { file: String, pack: String, field: &'static str },
    #[error("{file}: duplicate pack id `{}`", shown_id(.pack))]
    DuplicateId { file: String, pack: String },
    #[error("pack id `{}` is in both {first} and {second}", shown_id(.pack))]
    DuplicateAcrossFiles { pack: String, first: String, second: String },
    #[error("{dir}: more than {} entries", MAX_ENTRIES)]
    TooManyEntries { dir: String },
    #[error("{file}: a symbolic link is refused")]
    Symlink { file: String },
    #[error("{file}: not a regular file")]
    NotRegular { file: String },
    #[error("cannot read the directory")]
    Scan(#[from] std::io::Error),
}


/// The id itself when it is short and plain, else `#` and the first `DIGEST_CHARS` hex characters of its SHA-256.
pub fn shown_id(id: &str) -> String {
    let plain = id.len() <= MAX_SHOWN_ID && id.chars().all(|next| next.is_ascii_alphanumeric() || matches!(next, '_' | '.' | '-'));
    if plain {
        id.to_owned()
    } else {
        let digest = format!("{:x}", Sha256::digest(id.as_bytes()));
        format!("{DIGEST_MARK}{}", digest.chars().take(DIGEST_CHARS).collect::<String>())
    }
}
