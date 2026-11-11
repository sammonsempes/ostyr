//! Poller ids for the lease: a checked token, never shared by two processes by accident.

use crate::error::HolderError;
use crate::limits::{HOLDER_RANDOM_BYTES, MAX_HOLDER_CHARS};
use crate::types::FillFn;


pub fn token_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
}


/// A poller id is 1 to `MAX_HOLDER_CHARS` characters of letters, digits, `-`, `_` and `.`.
pub fn validate_holder(holder: &str) -> Result<(), HolderError> {
    if (1..=MAX_HOLDER_CHARS).contains(&holder.chars().count()) && holder.chars().all(token_char) {
        Ok(())
    } else {
        Err(HolderError::Invalid)
    }
}


pub fn hex_suffix(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        text.push_str(&format!("{byte:02x}"));
        text
    })
}


/// The id of this process: label or host, `-pid-`, random hex; a label that is not a token is refused.
pub fn process_holder(label: Option<&str>, host: &str, pid: u32, fill: FillFn) -> Result<String, HolderError> {
    let base = match label {
        Some(configured) => {
            validate_holder(configured)?;
            configured.to_owned()
        }
        None => host
            .chars()
            .map(|character| if token_char(character) { character } else { '-' })
            .collect(),
    };
    let mut random = [0; HOLDER_RANDOM_BYTES];
    fill(&mut random).map_err(HolderError::Random)?;
    let mut suffix = format!("-{pid}-");
    suffix.push_str(&hex_suffix(&random));
    let room = MAX_HOLDER_CHARS.saturating_sub(suffix.chars().count());
    let holder: String = base.chars().take(room).chain(suffix.chars()).collect();
    validate_holder(&holder)?;
    Ok(holder)
}
