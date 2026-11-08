use crate::audit::{validate_audited, ValidateError, ValidationContext};
use crate::model::{Decision, Proposal};
use crate::policy::LoadedPolicy;
use core_config::reload::ReloadEngine;
use serde_json::json;
use std::io::{self, BufRead, Write};
use thiserror::Error;
use tracing::warn;


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub accepted: u64,
    pub refused: u64,
    pub malformed: u64,
}


#[derive(Debug, Error)]
pub enum CliError {
    #[error("I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("cannot write the verdict: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Validate(#[from] ValidateError),
}


/// A malformed line is refused with the error category, line and column only (serde echoes the input otherwise) and counted; it never stops the stream.
pub fn handle_line(
    engine: &ReloadEngine<LoadedPolicy>,
    context: &ValidationContext,
    line: &str,
    output: &mut dyn Write,
    summary: Summary,
) -> Result<Summary, CliError> {
    match serde_json::from_str::<Proposal>(line) {
        Err(error) => {
            let category = format!("{:?}", error.classify()).to_lowercase();
            warn!(category, line = error.line(), column = error.column(), "line refused: not a proposal");
            serde_json::to_writer(
                &mut *output,
                &json!({"decision": "refused", "error": category, "line": error.line(), "column": error.column()}),
            )?;
            writeln!(output)?;
            Ok(Summary {
                malformed: summary.malformed + 1,
                ..summary
            })
        }
        Ok(proposal) => {
            let verdict = validate_audited(engine, context, &proposal)?;
            serde_json::to_writer(&mut *output, &verdict)?;
            writeln!(output)?;
            Ok(if verdict.decision == Decision::Accepted {
                Summary {
                    accepted: summary.accepted + 1,
                    ..summary
                }
            } else {
                Summary {
                    refused: summary.refused + 1,
                    ..summary
                }
            })
        }
    }
}


/// JSON lines in, verdict lines out; the reader is bounded by its caller.
pub fn run(
    engine: &ReloadEngine<LoadedPolicy>,
    context: &ValidationContext,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> Result<Summary, CliError> {
    input.lines().enumerate().try_fold(Summary::default(), |summary, (index, line)| {
        let text = line?;
        if text.trim().is_empty() {
            Ok(summary)
        } else {
            let line_context = ValidationContext {
                request_id: format!("{}-{}", context.request_id, index + 1),
                ..context.clone()
            };
            handle_line(engine, &line_context, &text, output, summary)
        }
    })
}
