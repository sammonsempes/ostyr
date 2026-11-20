use attack_paths::ad::{AdGraph, DuplicateDn, IncompleteNode};
use attack_paths::model::{NodeKind, Path, PathSet, StopReason, Unsearched};
use attack_paths::report::write_report;
use attack_paths::tags::SkippedTag;
use std::io::{Error, ErrorKind, Result as IoResult, Write};
use types::TestResult;


#[path = "support/types.rs"]
mod types;


const SHOWN_POINTS: usize = 10;


const WRITE_SWEEP: usize = 200;


struct FailingWriter {
    writes_left: usize,
}


impl Write for FailingWriter {
    fn write(&mut self, buffer: &[u8]) -> IoResult<usize> {
        if self.writes_left == 0 {
            Err(Error::new(ErrorKind::BrokenPipe, "closed"))
        } else {
            self.writes_left -= 1;
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}


fn built() -> AdGraph {
    let mut built = AdGraph::default();
    built.digests.insert("a".to_string(), "da".to_string());
    built.digests.insert("m".to_string(), "dm".to_string());
    built.digests.insert("t".to_string(), "dt".to_string());
    built.labels.insert("a".to_string(), "alice".to_string());
    built.removed_digests.insert("r1".to_string(), "dr1".to_string());
    built.removed_digests.insert("r2".to_string(), "dr2".to_string());
    built.removed_kinds.insert("r1".to_string(), NodeKind::DomainController);
    built.incomplete.push(IncompleteNode {
        id: "a".to_string(),
        digest: "da".to_string(),
        field: "memberOf",
        reason: "unknown_target_while_unreadable",
        dropped: 1,
        over_limit: false,
    });
    built.duplicates.push(DuplicateDn {
        id: "a".to_string(),
        kept_digest: "k".to_string(),
        dropped_digest: "d".to_string(),
    });
    built
}


fn found() -> PathSet {
    PathSet {
        paths: vec![
            Path {
                nodes: vec!["a".to_string(), "m".to_string(), "t".to_string()],
            },
            Path {
                nodes: vec!["a".to_string(), "m".to_string(), "t".to_string()],
            },
        ],
        truncated: true,
        budget_reached: false,
        unsearched: vec![
            Unsearched {
                id: "a".to_string(),
                reason: StopReason::PathCap,
            },
            Unsearched {
                id: "unknown".to_string(),
                reason: StopReason::StepBudget,
            },
        ],
    }
}


fn skipped() -> Vec<SkippedTag> {
    vec![SkippedTag {
        index: 0,
        id: "gone".to_string(),
    }]
}


fn report_text() -> Result<String, Box<dyn std::error::Error>> {
    let mut out: Vec<u8> = Vec::new();
    write_report(&mut out, &built(), &found(), &skipped(), SHOWN_POINTS)?;
    Ok(String::from_utf8(out)?)
}


fn position(text: &str, prefix: &str) -> Result<usize, String> {
    text.lines().position(|line| line.starts_with(prefix)).ok_or(format!("no {prefix} line"))
}


#[test]
fn every_incomplete_line_comes_before_the_first_path() -> TestResult {
    let text = report_text()?;
    let first_path = position(&text, "path ")?;
    assert_eq!(position(&text, "SUMMARY")?, 0);
    ["TAG_SKIPPED", "INCOMPLETE", "REMOVED", "UNSEARCHED", "DUPLICATE_DN"]
        .iter()
        .try_for_each(|prefix| position(&text, prefix).map(|at| assert!(at < first_path, "{prefix} after the first path")))?;
    assert!(text.contains("UNSEARCHED da alice [da] reason=path_cap"));
    assert!(text.contains("UNSEARCHED ? unknown [?] reason=step_budget"));
    assert!(text.contains("REMOVED dr1 kind=domain controller reason=over_nodes"));
    assert!(text.contains("REMOVED dr2 kind=? reason=over_nodes"));
    assert!(text.contains("unsearched_entries=2"));
    assert!(text.contains("choke m"));
    Ok(())
}


#[test]
fn a_failing_writer_is_reported_at_every_line() -> TestResult {
    let refused = (0..WRITE_SWEEP)
        .filter(|writes_left| {
            let mut out = FailingWriter { writes_left: *writes_left };
            write_report(&mut out, &built(), &found(), &skipped(), SHOWN_POINTS).is_err()
        })
        .count();
    assert!(refused > 0);
    assert!(refused < WRITE_SWEEP);
    let mut sink = FailingWriter { writes_left: WRITE_SWEEP };
    sink.flush()?;
    Ok(())
}
