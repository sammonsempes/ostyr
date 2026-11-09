use crate::error::ComplianceError;
use crate::evaluate::build_pattern;
use crate::model::{Baseline, Control, Exception, ExceptionFile, Expectation, Policy, Scope};
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_text};
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;


pub const SUPPORTED_VERSION: u32 = 1;


pub const MAX_FILE_BYTES: u64 = 4_194_304;


pub const MAX_CONTROLS: usize = 1_000;


pub const MAX_EXCEPTIONS: usize = 10_000;


pub const MAX_ACTIONS: usize = 1_000;


pub const MAX_CAP: usize = 100_000;


pub const MAX_FRAMEWORKS: usize = 16;


pub const MAX_ID_LEN: usize = 128;


pub const MAX_QUERY_LEN: usize = 4_096;


pub const MAX_TEXT_LEN: usize = 1_024;


fn check_len(field: &str, value: &str, max: usize) -> Result<(), String> {
    if value.len() > max {
        Err(format!("`{field}` is longer than {max} bytes"))
    } else {
        Ok(())
    }
}


fn check_text(field: &str, value: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("`{field}` is empty"))
    } else {
        check_len(field, value, max)
    }
}


fn check_expectation(expect: &Expectation) -> Result<(), String> {
    match expect {
        Expectation::RowCount(_) => Ok(()),
        Expectation::ColumnEquals { column, value } => {
            check_text("column", column, MAX_ID_LEN).and_then(|()| check_len("value", value, MAX_TEXT_LEN))
        }
        Expectation::ColumnMatches { column, pattern } => check_text("column", column, MAX_ID_LEN)
            .and_then(|()| check_text("pattern", pattern, MAX_TEXT_LEN))
            .and_then(|()| build_pattern(pattern).map(|_| ()).map_err(|error| format!("invalid pattern: {error}"))),
    }
}


fn check_control(control: &Control) -> Result<(), String> {
    check_text("id", &control.id, MAX_ID_LEN)?;
    check_text("query", &control.query, MAX_QUERY_LEN)?;
    check_expectation(&control.expect)?;
    if control.frameworks.len() > MAX_FRAMEWORKS {
        Err(format!("more than {MAX_FRAMEWORKS} framework references"))
    } else {
        control
            .frameworks
            .iter()
            .try_for_each(|reference| check_text("framework reference", &reference.reference, MAX_ID_LEN))?;
        control
            .correction
            .as_ref()
            .map_or(Ok(()), |correction| check_text("correction action", &correction.action, MAX_TEXT_LEN))
    }
}


fn check_actions(baseline: &Baseline) -> Result<(), String> {
    if baseline.actions.len() > MAX_ACTIONS {
        Err(format!("more than {MAX_ACTIONS} actions"))
    } else {
        baseline.actions.iter().try_for_each(|action| check_text("action", action, MAX_ID_LEN))?;
        baseline.controls.iter().try_for_each(|control| match &control.correction {
            Some(correction) if !baseline.actions.contains(&correction.action) => Err(format!(
                "control `{}`: correction action `{}` is not declared in `actions`",
                control.id, correction.action
            )),
            _ => Ok(()),
        })
    }
}


pub fn check_baseline(baseline: &Baseline) -> Result<(), String> {
    if baseline.version != SUPPORTED_VERSION {
        Err(format!("unsupported baseline version {}", baseline.version))
    } else if baseline.controls.len() > MAX_CONTROLS {
        Err(format!("more than {MAX_CONTROLS} controls"))
    } else {
        check_text("name", &baseline.name, MAX_ID_LEN)?;
        check_text("tenant", &baseline.tenant, MAX_ID_LEN)?;
        baseline
            .controls
            .iter()
            .try_for_each(|control| check_control(control).map_err(|message| format!("control `{}`: {message}", control.id)))?;
        check_actions(baseline)?;
        let identifiers: BTreeSet<&String> = baseline.controls.iter().map(|control| &control.id).collect();
        if identifiers.len() == baseline.controls.len() {
            Ok(())
        } else {
            Err("duplicate control id".to_string())
        }
    }
}


fn check_exception(exception: &Exception) -> Result<(), String> {
    check_text("control", &exception.control, MAX_ID_LEN)?;
    check_text("owner", &exception.owner, MAX_ID_LEN)?;
    check_text("reason", &exception.reason, MAX_TEXT_LEN)?;
    match &exception.scope {
        Scope::Device(value) | Scope::Tag(value) => check_text("scope", value, MAX_ID_LEN),
    }
}


pub fn check_exceptions(file: &ExceptionFile) -> Result<(), String> {
    if file.exceptions.len() > MAX_EXCEPTIONS {
        Err(format!("more than {MAX_EXCEPTIONS} exceptions"))
    } else {
        file.exceptions
            .iter()
            .try_for_each(|exception| check_exception(exception).map_err(|message| format!("exception for `{}`: {message}", exception.control)))
    }
}


fn read_bounded(reader: &mut dyn Read, file: &str) -> Result<String, ComplianceError> {
    let text = read_text(&mut reader.take(MAX_FILE_BYTES + 1), file)?;
    if text.len() as u64 > MAX_FILE_BYTES {
        Err(ComplianceError::Invalid {
            file: file.to_string(),
            message: format!("file is larger than {MAX_FILE_BYTES} bytes"),
        })
    } else {
        Ok(text)
    }
}


fn parse_checked<Document: DeserializeOwned>(
    reader: &mut dyn Read,
    file: &str,
    check: fn(&Document) -> Result<(), String>,
) -> Result<Document, ComplianceError> {
    let text = read_bounded(reader, file)?;
    let document: Document = parse_document(&text, file)?;
    check(&document).map_err(|message| ComplianceError::Invalid {
        file: file.to_string(),
        message,
    })?;
    Ok(document)
}


pub fn parse_baseline(reader: &mut dyn Read, file: &str) -> Result<Baseline, ComplianceError> {
    parse_checked(reader, file, check_baseline)
}


pub fn parse_exceptions(reader: &mut dyn Read, file: &str) -> Result<Vec<Exception>, ComplianceError> {
    parse_checked(reader, file, check_exceptions).map(|parsed: ExceptionFile| parsed.exceptions)
}


pub fn check_policy(policy: &Policy) -> Result<(), String> {
    if policy.version != SUPPORTED_VERSION {
        Err(format!("unsupported policy version {}", policy.version))
    } else if policy.max_devices == 0 || policy.max_devices > MAX_CAP {
        Err(format!("`max_devices` must be between 1 and {MAX_CAP}"))
    } else if policy.max_corrections_per_device == 0 || policy.max_corrections_per_device > MAX_CAP {
        Err(format!("`max_corrections_per_device` must be between 1 and {MAX_CAP}"))
    } else {
        check_text("tenant", &policy.tenant, MAX_ID_LEN)
    }
}


pub fn parse_policy(reader: &mut dyn Read, file: &str) -> Result<Policy, ComplianceError> {
    parse_checked(reader, file, check_policy)
}


fn open_file(path: &Path) -> Result<File, ComplianceError> {
    File::open(path).map_err(|source| {
        ComplianceError::Config(ConfigError::Io {
            file: path.display().to_string(),
            source,
        })
    })
}


pub fn load_baseline(path: &Path) -> Result<Baseline, ComplianceError> {
    parse_baseline(&mut open_file(path)?, &path.display().to_string())
}


pub fn load_exceptions(path: &Path) -> Result<Vec<Exception>, ComplianceError> {
    parse_exceptions(&mut open_file(path)?, &path.display().to_string())
}


pub fn load_policy(path: &Path) -> Result<Policy, ComplianceError> {
    parse_policy(&mut open_file(path)?, &path.display().to_string())
}
