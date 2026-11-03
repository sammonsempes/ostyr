use crate::ecs::export;
use crate::error::AuditError;
use crate::log::{append, head, open_file_log, AuditLog};
use crate::model::{Actor, ActorKind, NewEntry, Outcome};
use crate::verify::verify;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;
use time::OffsetDateTime;


pub fn sample_entry(index: usize) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: "example".to_owned(),
        },
        tenant: "tenant-a".to_owned(),
        module: "example".to_owned(),
        action: "config.update".to_owned(),
        target: format!("setting-{index}"),
        outcome: Outcome::Success,
        request_id: format!("request-{index}"),
        justification: None,
        parameters: [("password".to_owned(), "hunter2".to_owned())].into(),
    }
}


pub fn parse_count(text: &str) -> Result<usize, AuditError> {
    text.parse().map_err(|source| AuditError::InvalidCount {
        value: text.to_owned(),
        source,
    })
}


/// Appends `total` sample records and returns the new chain head.
pub fn append_samples<Output: Write>(log: &AuditLog<Output>, total: usize) -> Result<String, AuditError> {
    (0..total)
        .try_for_each(|index| append(log, sample_entry(index)).map(|_| ()))
        .map(|()| head(log))
}


/// Runs one command of the example binary: `append <file> <count>`, `verify <file> [head]` or `export <file> [head]`.
pub fn run<Output: Write>(args: &[&str], out: &mut Output) -> Result<(), AuditError> {
    match args {
        ["append", file, count] => parse_count(count)
            .and_then(|total| open_file_log(Path::new(file)).and_then(|log| append_samples(&log, total)))
            .and_then(|new_head| writeln!(out, "head {new_head}").map_err(AuditError::from)),
        ["verify", file] => verify_file(file, None, out),
        ["verify", file, expected] => verify_file(file, Some(expected), out),
        ["export", file] => export_file(file, None, out),
        ["export", file, expected] => export_file(file, Some(expected), out),
        _ => Err(AuditError::Usage),
    }
}


pub fn verify_file<Output: Write>(file: &str, expected: Option<&str>, out: &mut Output) -> Result<(), AuditError> {
    let report = verify(BufReader::new(File::open(file)?), expected)?;
    writeln!(out, "ok {} records head {}", report.records, report.head).map_err(AuditError::from)
}


pub fn export_file<Output: Write>(file: &str, expected: Option<&str>, out: &mut Output) -> Result<(), AuditError> {
    export(|| File::open(file).map(BufReader::new), out, expected).map(|_| ())
}
