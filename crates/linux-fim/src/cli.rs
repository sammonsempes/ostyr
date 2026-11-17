use crate::classify::classify;
use crate::error::CliError;
use crate::limits::MAX_EVENT_LINE_BYTES;
use crate::model::{FimEvent, Limits, PlantedIdentity, Role};
use crate::policy::{kernel_device, policy_names, render_policy, watch_sets, with_planted};
use crate::roles::load_roles;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;


/// Reads the table at `table_path` under the size cap, renders the policy of `role_name` and writes it to `out`.
pub fn render_command<Output: Write>(table_path: &Path, role_name: &str, limits: &Limits, out: &mut Output) -> Result<(), CliError> {
    let role = role_of(table_path, role_name, limits)?;
    out.write_all(render_policy(&role, limits)?.as_bytes())?;
    Ok(())
}


/// The three files and the capture size cap of `classify_command`.
pub struct CaptureFiles<'a> {
    pub table: &'a Path,
    pub planted: &'a Path,
    pub capture: &'a Path,
    pub max_capture_bytes: usize,
}


/// Classifies every line of the capture file with the planted identities (`path`, `st_dev`, `inode` per line, tab separated) and writes each event to `out`.
pub fn classify_command<Output: Write>(files: &CaptureFiles, role_name: &str, limits: &Limits, out: &mut Output) -> Result<(), CliError> {
    let role = role_of(files.table, role_name, limits)?;
    let planted = parse_planted(&read_capped(files.planted, limits.max_table_bytes)?)?;
    let sets = with_planted(watch_sets(&role), planted);
    let policies = policy_names(role_name);
    let capture = read_capped(files.capture, files.max_capture_bytes)?;
    let events: Vec<FimEvent> = capture
        .lines()
        .filter_map(|line| classify(line, MAX_EVENT_LINE_BYTES, &policies, &sets))
        .collect();
    events.iter().try_for_each(|event| writeln!(out, "{event:?}"))?;
    Ok(())
}


/// The planted identities of a file of `path`, `st_dev` and `inode` fields separated by tabs, one per line; a blank line is skipped, a bad one is refused.
pub fn parse_planted(text: &str) -> Result<Vec<PlantedIdentity>, CliError> {
    let numbered: Vec<(usize, &str)> = text.lines().enumerate().filter(|(_, line)| !line.trim().is_empty()).collect();
    numbered
        .iter()
        .map(|(index, line)| planted_of(line).ok_or(CliError::Planted { line: index + 1 }))
        .collect()
}


/// One planted identity line, `None` when it does not have exactly the three fields.
pub fn planted_of(line: &str) -> Option<PlantedIdentity> {
    let fields: Vec<&str> = line.split('\t').collect();
    match fields.as_slice() {
        [path, st_dev, inode] => st_dev
            .parse::<u64>()
            .ok()
            .zip(inode.parse::<u64>().ok())
            .map(|(device, number)| planted_from(path, device, number)),
        _ => None,
    }
}


/// The identity of a path from a `stat` device and an inode number.
pub fn planted_from(path: &str, st_dev: u64, inode: u64) -> PlantedIdentity {
    PlantedIdentity {
        path: path.to_string(),
        device: kernel_device(st_dev),
        inode,
    }
}


/// The text of a file, refused when it is longer than `max` bytes (at most `max` plus one byte is read).
pub fn read_capped(path: &Path, max: usize) -> Result<String, CliError> {
    let mut text = String::new();
    File::open(path)?.take((max as u64).saturating_add(1)).read_to_string(&mut text)?;
    if text.len() > max {
        Err(CliError::TooLarge { max })
    } else {
        Ok(text)
    }
}


/// The role named `role_name` of the table at `table_path`, read under the table size cap.
pub fn role_of(table_path: &Path, role_name: &str, limits: &Limits) -> Result<Role, CliError> {
    let mut text = String::new();
    let cap = (limits.max_table_bytes as u64).saturating_add(1);
    File::open(table_path)?.take(cap).read_to_string(&mut text)?;
    let table = load_roles(&text, limits)?;
    let found = table.roles.into_iter().find(|candidate| candidate.name == role_name);
    found.ok_or_else(|| CliError::NoRole(role_name.to_string()))
}
