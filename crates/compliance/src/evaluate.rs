use crate::model::{Control, Exception, Expectation, Scope, Target, Verdict};
use crate::types::{QueryResult, Row};
use regex::{Regex, RegexBuilder};
use time::OffsetDateTime;


pub const MAX_OFFENDING_ROWS: usize = 20;


pub const PATTERN_SIZE_LIMIT: usize = 1_000_000;


pub fn build_pattern(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern).size_limit(PATTERN_SIZE_LIMIT).build()
}


pub fn scope_matches(scope: &Scope, target: &Target) -> bool {
    match scope {
        Scope::Device(device) => *device == target.device,
        Scope::Tag(tag) => target.tags.contains(tag),
    }
}


/// An exception applies until its expiry instant: at `now == expires` it no longer applies.
pub fn find_exception<'a>(control: &Control, exceptions: &'a [Exception], target: &Target, now: OffsetDateTime) -> Option<&'a Exception> {
    exceptions
        .iter()
        .find(|exception| exception.control == control.id && now < exception.expires && scope_matches(&exception.scope, target))
}


fn fail(offending: &[&Row]) -> Verdict {
    Verdict::Fail {
        offending: offending.iter().take(MAX_OFFENDING_ROWS).map(|row| (*row).clone()).collect(),
        total: offending.len(),
    }
}


fn column_check(rows: &[Row], column: &str, accepts: &dyn Fn(&str) -> bool) -> Verdict {
    let cells: Result<Vec<(&Row, &String)>, String> = rows
        .iter()
        .map(|row| {
            row.get(column)
                .map(|cell| (row, cell))
                .ok_or_else(|| format!("result has no column `{column}`"))
        })
        .collect();
    match cells {
        Err(reason) => Verdict::Error { reason },
        Ok(pairs) => {
            let offending: Vec<&Row> = pairs.into_iter().filter(|(_, cell)| !accepts(cell)).map(|(row, _)| row).collect();
            if rows.is_empty() || !offending.is_empty() {
                fail(&offending)
            } else {
                Verdict::Pass
            }
        }
    }
}


/// Zero rows never satisfy a column expectation: nothing was checked.
pub fn evaluate_rows(expect: &Expectation, rows: &[Row]) -> Verdict {
    match expect {
        Expectation::RowCount(expected) => {
            if rows.len() == *expected {
                Verdict::Pass
            } else {
                fail(&rows.iter().collect::<Vec<&Row>>())
            }
        }
        Expectation::ColumnEquals { column, value } => column_check(rows, column, &|cell| cell == value),
        Expectation::ColumnMatches { column, pattern } => match build_pattern(pattern) {
            Ok(compiled) => column_check(rows, column, &|cell| compiled.is_match(cell)),
            Err(error) => Verdict::Error {
                reason: format!("invalid pattern: {error}"),
            },
        },
    }
}


pub fn evaluate(control: &Control, exceptions: &[Exception], target: &Target, now: OffsetDateTime, result: QueryResult) -> Verdict {
    match (find_exception(control, exceptions, target, now), result) {
        (Some(exception), _) => Verdict::Excepted {
            owner: exception.owner.clone(),
            reason: exception.reason.clone(),
        },
        (None, Err(reason)) => Verdict::Error { reason: reason.to_string() },
        (None, Ok(rows)) => evaluate_rows(&control.expect, rows),
    }
}
