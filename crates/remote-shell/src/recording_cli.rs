use crate::grammar::valid_reference;
use crate::recording::{close, new_writer, push, read_recording, Direction, Header, Limits, RecordingError};
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::num::ParseIntError;
use std::path::Path;
use thiserror::Error;


pub const CLOSE_REASON: &str = "example";


pub const DIRECTIONS: usize = 2;


pub const OPTION_PAIR: usize = 2;


pub const DEFAULT_TENANT: &str = "tenant-a";


pub const DEFAULT_SESSION: &str = "example-session";


#[derive(Debug, Error)]
pub enum RecordCliError {
    #[error("usage: shell_record record <file> <start> <step> [--tenant <tenant>] [--session <id>] | verify <file>")]
    Usage,
    #[error("start and step must be integers")]
    Number(#[from] ParseIntError),
    #[error("the session id is outside its grammar")]
    Session,
    #[error("the tenant is refused")]
    Tenant(#[from] PgError),
    #[error("the fake clock overflowed")]
    Clock,
    #[error("file or stream error")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Recording(#[from] RecordingError),
}


pub fn direction_of(index: usize) -> Direction {
    if index.is_multiple_of(DIRECTIONS) {
        Direction::In
    } else {
        Direction::Out
    }
}


pub fn clock_at(start: i64, step: i64, index: usize) -> Result<i64, RecordCliError> {
    (index as i64)
        .checked_mul(step)
        .and_then(|delta| start.checked_add(delta))
        .ok_or(RecordCliError::Clock)
}


/// The tenant and session id of a recording, from `--tenant` and `--session` pairs; each is checked as the register checks it.
pub fn identity_of(options: &[String]) -> Result<(String, String), RecordCliError> {
    let (tenant, session) = options.chunks(OPTION_PAIR).try_fold(
        (DEFAULT_TENANT.to_owned(), DEFAULT_SESSION.to_owned()),
        |(tenant, session), pair| match pair {
            [flag, value] if flag == "--tenant" => Ok((value.clone(), session)),
            [flag, value] if flag == "--session" => Ok((tenant, value.clone())),
            _ => Err(RecordCliError::Usage),
        },
    )?;
    tenant_scope(&tenant)?;
    if valid_reference(&session) {
        Ok((tenant, session))
    } else {
        Err(RecordCliError::Session)
    }
}


fn record(path: &Path, start: i64, step: i64, identity: (String, String), input: &mut dyn BufRead) -> Result<(), RecordCliError> {
    let mut file = BufWriter::new(File::create(path)?);
    let header = Header {
        session_id: identity.1,
        tenant: identity.0,
        requester: "alice".to_string(),
        asset: "asset-1".to_string(),
        ticket: "TICKET-1".to_string(),
        opened_at: start,
    };
    let mut writer = new_writer(&mut file, &header, Limits::default())?;
    let mut count = 0;
    for (index, line) in input.lines().enumerate() {
        let mut text = line?;
        text.push('\n');
        push(&mut writer, direction_of(index), text.as_bytes(), clock_at(start, step, index + 1)?)?;
        count = index + 1;
    }
    close(&mut writer, CLOSE_REASON, clock_at(start, step, count + 1)?)?;
    Ok(())
}


fn verify(path: &Path, out: &mut dyn Write) -> Result<(), RecordCliError> {
    let mut file = BufReader::new(File::open(path)?);
    let recording = read_recording(&mut file, &Limits::default())?;
    let hash: String = recording.final_hash.iter().map(|byte| format!("{byte:02x}")).collect();
    writeln!(out, "valid frames={} final_hash={hash}", recording.frames.len() + DIRECTIONS)?;
    Ok(())
}


/// `record <file> <start> <step> [--tenant T] [--session S]` turns stdin lines into alternating input and output frames; `verify <file>` prints the verdict.
pub fn run_record_cli(args: &[String], input: &mut dyn BufRead, out: &mut dyn Write) -> Result<(), RecordCliError> {
    match args {
        [command, file, start, step, options @ ..] if command == "record" => {
            record(Path::new(file), start.parse()?, step.parse()?, identity_of(options)?, input)
        }
        [command, file] if command == "verify" => verify(Path::new(file), out),
        _ => Err(RecordCliError::Usage),
    }
}
