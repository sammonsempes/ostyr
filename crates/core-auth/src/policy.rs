use crate::error::PolicyViolation;
use crate::types::CompromisedSet;
use std::io::{self, BufRead};


pub const MIN_PASSWORD_CHARS: usize = 12;


pub const MAX_PASSWORD_BYTES: usize = 1024;


pub fn load_compromised<Input: BufRead>(input: Input) -> io::Result<CompromisedSet> {
    input
        .lines()
        .map(|line| line.map(|text| text.trim().to_lowercase()))
        .filter(|line| line.as_ref().map_or(true, |text| !text.is_empty()))
        .collect()
}


pub fn check_password(password: &str, compromised: &CompromisedSet) -> Result<(), PolicyViolation> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        Err(PolicyViolation::TooShort)
    } else if password.len() > MAX_PASSWORD_BYTES {
        Err(PolicyViolation::TooLong)
    } else if compromised.contains(&password.to_lowercase()) {
        Err(PolicyViolation::Compromised)
    } else {
        Ok(())
    }
}
