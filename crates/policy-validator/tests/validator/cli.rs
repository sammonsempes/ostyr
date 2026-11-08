use crate::support::{bench, exclusion, failing_audit_engine, hash, validation_context, FailingReader, FailingWriter, NewlineFails, GOOD_PATH};
use crate::types::TestResult;
use policy_validator::cli::{run, CliError, Summary};
use policy_validator::model::{Proposal, Scope, SelectorKind};
use std::io::BufReader;


fn line(scope: Scope, kind: SelectorKind, value: &str) -> Result<String, serde_json::Error> {
    serde_json::to_string(&Proposal::Exclusion(exclusion(scope, kind, value)))
}


const THREE_LINES: usize = 3;


#[test]
fn a_stream_of_proposals_gives_one_verdict_line_each() -> TestResult {
    let bench = bench("{}")?;
    let input = [
        line(Scope::Global, SelectorKind::Hash, &hash())?,
        String::new(),
        line(Scope::Global, SelectorKind::Path, GOOD_PATH)?,
        "not json".to_owned(),
    ]
    .join("\n");
    let mut output = Vec::new();
    let summary = run(&bench.engine, &validation_context(), &mut input.as_bytes(), &mut output)?;
    assert_eq!(
        summary,
        Summary {
            accepted: 1,
            refused: 1,
            malformed: 1
        }
    );
    let text = String::from_utf8(output)?;
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), THREE_LINES);
    assert!(lines.first().is_some_and(|first| first.contains("\"decision\":\"accepted\"")));
    assert!(lines.get(1).is_some_and(|second| second.contains("path_at_wide_scope")));
    assert!(lines.last().is_some_and(|third| third.contains("\"error\"")));
    Ok(())
}


#[test]
fn a_failing_reader_stops_the_run() -> TestResult {
    let bench = bench("{}")?;
    let mut reader = BufReader::new(FailingReader);
    let outcome = run(&bench.engine, &validation_context(), &mut reader, &mut Vec::new());
    assert!(matches!(outcome, Err(CliError::Io(_))));
    Ok(())
}


#[test]
fn a_failing_audit_stops_the_run_with_the_proposal_refused() -> TestResult {
    let (_dir, engine) = failing_audit_engine()?;
    let input = line(Scope::Global, SelectorKind::Hash, &hash())?;
    let outcome = run(&engine, &validation_context(), &mut input.as_bytes(), &mut Vec::new());
    assert!(matches!(outcome, Err(CliError::Validate(_))));
    Ok(())
}


#[test]
fn a_failing_writer_is_an_error_on_every_output_path() -> TestResult {
    let bench = bench("{}")?;
    let good = line(Scope::Global, SelectorKind::Hash, &hash())?;
    for input in [good.as_str(), "not json"] {
        let body = run(&bench.engine, &validation_context(), &mut input.as_bytes(), &mut FailingWriter);
        assert!(matches!(body, Err(CliError::Json(_))), "{input}");
        let newline = run(&bench.engine, &validation_context(), &mut input.as_bytes(), &mut NewlineFails);
        assert!(matches!(newline, Err(CliError::Io(_))), "{input}");
    }
    Ok(())
}
