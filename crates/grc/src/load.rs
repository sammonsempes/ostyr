use crate::error::GrcError;
use crate::evaluate::threshold_met;
use crate::model::{Control, ControlKind, Framework, Threshold};
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_text_capped};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;


pub const MAX_FILE_BYTES: u64 = 2_097_152;


pub const MAX_CONTROLS: usize = 2_000;


pub const MAX_ID_CHARS: usize = 64;


pub const MAX_INDICATOR_CHARS: usize = 128;


pub const MAX_TITLE_CHARS: usize = 200;


pub const MAX_OWNER_BYTES: usize = 128;


pub const MAX_AGE_HOURS: u32 = 8_760;


/// `[A-Za-z0-9][A-Za-z0-9._-]*` up to `max` bytes: never a leading `-`, never a control or bidirectional character.
pub fn is_identifier(text: &str, max: usize) -> bool {
    let mut characters = text.chars();
    text.len() <= max
        && characters.next().is_some_and(|first| first.is_ascii_alphanumeric())
        && characters.all(|next| next.is_ascii_alphanumeric() || matches!(next, '.' | '_' | '-'))
}


/// An identity: `[a-z0-9._@+-]`, 1 to `MAX_OWNER_BYTES` bytes, never a leading `-`.
pub fn is_owner(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_OWNER_BYTES
        && !text.starts_with('-')
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'@' | b'+' | b'-'))
}


fn printable(character: char) -> bool {
    !character.is_control()
        && !matches!(
            character,
            '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
        )
}


/// Non-empty text of at most `max` characters, none of them control, invisible or bidirectional.
pub fn is_printable_text(text: &str, max: usize) -> bool {
    !text.trim().is_empty() && text.chars().count() <= max && text.chars().all(printable)
}


fn limit_of(threshold: &Threshold) -> f64 {
    match threshold {
        Threshold::AtLeast(limit) | Threshold::AtMost(limit) => *limit,
    }
}


/// `partial` may not be stricter than `compliant`: a value meeting `compliant` must meet `partial`.
fn check_thresholds(compliant: &Threshold, partial: &Threshold) -> Result<(), &'static str> {
    if !(limit_of(compliant).is_finite() && limit_of(partial).is_finite()) {
        Err("thresholds must be finite numbers")
    } else if !matches!(
        (compliant, partial),
        (Threshold::AtLeast(_), Threshold::AtLeast(_)) | (Threshold::AtMost(_), Threshold::AtMost(_))
    ) {
        Err("thresholds must use the same direction")
    } else if threshold_met(partial, limit_of(compliant)) {
        Ok(())
    } else {
        Err("partial is stricter than compliant")
    }
}


fn check_technical(control: &Control) -> Result<(), &'static str> {
    let indicator_valid = control.indicator.as_deref().is_some_and(|name| is_identifier(name, MAX_INDICATOR_CHARS));
    let age_valid = control.max_age_hours.is_some_and(|hours| (1..=MAX_AGE_HOURS).contains(&hours));
    match (indicator_valid, age_valid, control.compliant.as_ref().zip(control.partial.as_ref())) {
        (false, _, _) => Err("technical control needs a valid indicator"),
        (_, false, _) => Err("technical control needs max_age_hours between 1 and 8760"),
        (_, _, None) => Err("technical control needs compliant and partial thresholds"),
        (_, _, Some((compliant, partial))) => check_thresholds(compliant, partial),
    }
}


fn check_control(control: &Control) -> Result<(), &'static str> {
    if !is_identifier(&control.id, MAX_ID_CHARS) {
        Err("invalid id")
    } else if !is_printable_text(&control.title, MAX_TITLE_CHARS) {
        Err("invalid title")
    } else if control.kind == ControlKind::Technical {
        check_technical(control)
    } else if control.indicator.is_some() || control.max_age_hours.is_some() || control.compliant.is_some() || control.partial.is_some() {
        Err("organisational control must not carry indicator fields")
    } else {
        Ok(())
    }
}


pub fn check_framework(framework: &Framework, file: &str) -> Result<(), GrcError> {
    let invalid = |reason: String| GrcError::Invalid {
        file: file.to_owned(),
        reason,
    };
    let mut seen = BTreeSet::new();
    if !is_identifier(&framework.framework, MAX_ID_CHARS) {
        Err(invalid("invalid framework id".to_owned()))
    } else if framework.controls.len() > MAX_CONTROLS {
        Err(invalid(format!("more than {MAX_CONTROLS} controls")))
    } else {
        framework.controls.iter().enumerate().try_for_each(|(index, control)| {
            check_control(control)
                .map_err(|reason| invalid(format!("control {index}: {reason}")))
                .and_then(|()| {
                    if seen.insert(control.id.as_str()) {
                        Ok(())
                    } else {
                        Err(invalid(format!("control {index}: duplicate id")))
                    }
                })
        })
    }
}


pub fn parse_framework(reader: &mut dyn Read, file: &str) -> Result<Framework, GrcError> {
    let text = read_text_capped(reader, file, MAX_FILE_BYTES)?;
    let framework: Framework = parse_document(&text, file)?;
    check_framework(&framework, file).map(|()| framework)
}


pub fn load_framework(path: &Path) -> Result<Framework, GrcError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    parse_framework(&mut handle, &file)
}
