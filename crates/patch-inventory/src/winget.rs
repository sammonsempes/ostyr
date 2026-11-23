//! Updatable winget packages from the `winget upgrade` text table (layout facts: the crate notes).

use crate::error::{InventoryError, WingetError};
use crate::limits::{MAX_WINGET_TABLES, MAX_WINGET_UPDATES, MIN_SEPARATOR_DASHES, SOURCE_OPEN_FAILED_EXIT};
use crate::model::{CliInventory, Device, Limits, Update, WingetSkip, WingetSource};
use crate::scan::{is_forbidden, read_input};
use crate::types::{UpdatesByPackage, WingetSkipCounts};
use crate::validate::{is_winget_package_id, is_winget_version};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::io::Read;


pub const ARCHITECTURE: &str = "any";


pub const ELLIPSIS: char = '\u{2026}';


pub const PROGRESS_BLOCKS: [char; 2] = ['\u{2588}', '\u{2592}'];


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row<'a> {
    pub id: &'a str,
    pub installed: &'a str,
    pub available: &'a str,
    pub unknown_installed: bool,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowLine<'a> {
    Item(Row<'a>),
    Skipped(WingetSkip),
    Unshaped,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified<'a> {
    Blank,
    Footer(&'a str),
    Row(RowLine<'a>),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableScan<'a> {
    pub rows: Vec<RowLine<'a>>,
    pub footer: Option<&'a str>,
}


#[derive(Debug, Default)]
pub struct Built {
    pub updates: UpdatesByPackage,
    pub skipped: WingetSkipCounts,
}


pub fn parse_winget_cli<Source: Read>(
    device: &Device,
    reader: Source,
    exit_code: i32,
    source: WingetSource,
    limits: &Limits,
) -> Result<CliInventory, WingetError> {
    let buffer = read_input(reader, limits)?;
    exit_status(exit_code)?;
    let text = std::str::from_utf8(&buffer).map_err(|_| WingetError::Encoding)?;
    if lines_of(text).count() > limits.max_lines {
        Err(InventoryError::TooManyLines { limit: limits.max_lines })?;
    }
    let lines: Vec<&str> = lines_of(text).collect();
    let separators: Vec<usize> = (0..lines.len()).filter(|index| is_separator(&lines, *index)).collect();
    if separators.len() > MAX_WINGET_TABLES {
        Err(WingetError::TooManyTables { limit: MAX_WINGET_TABLES })?;
    }
    match separators.first() {
        None => empty_listing(&lines),
        Some(first) => read_tables(device, &lines, &separators, *first, source, limits),
    }
}


pub fn exit_status(code: i32) -> Result<(), WingetError> {
    match code {
        0 => Ok(()),
        SOURCE_OPEN_FAILED_EXIT => Err(WingetError::SourceOpenFailed),
        other => Err(WingetError::Exit { code: other }),
    }
}


pub fn lines_of(text: &str) -> impl Iterator<Item = &str> {
    text.split_terminator('\n')
        .map(|piece| piece.strip_suffix('\r').unwrap_or(piece))
        .flat_map(|piece| piece.split('\r'))
}


pub fn is_blank(line: &str) -> bool {
    line.trim_matches(' ').is_empty()
}


pub fn is_progress_bar(line: &str) -> bool {
    line.strip_prefix("  ").is_some_and(|rest| {
        let tail = rest.trim_start_matches(PROGRESS_BLOCKS);
        tail.len() < rest.len() && tail.chars().all(|character| character.is_ascii_graphic() || character == ' ')
    })
}


pub fn is_frame(line: &str) -> bool {
    matches!(line.as_bytes(), [b' ', b' ', b' ', b'-' | b'\\' | b'|' | b'/', b' ']) || is_progress_bar(line)
}


pub fn is_separator(lines: &[&str], index: usize) -> bool {
    let dashes = lines
        .get(index)
        .is_some_and(|line| line.len() >= MIN_SEPARATOR_DASHES && line.bytes().all(|byte| byte == b'-'));
    let after_header = index
        .checked_sub(1)
        .and_then(|previous| lines.get(previous))
        .is_some_and(|line| !is_blank(line) && !is_frame(line));
    dashes && after_header
}


pub fn empty_listing(lines: &[&str]) -> Result<CliInventory, WingetError> {
    let meaningful = lines.iter().filter(|line| !is_blank(line) && !is_frame(line)).count();
    if meaningful == 1 {
        Ok(CliInventory {
            updates: Vec::new(),
            skipped: BTreeMap::new(),
            preamble_lines: 0,
        })
    } else {
        Err(WingetError::UnrecognisedLayout)
    }
}


pub fn read_tables(
    device: &Device,
    lines: &[&str],
    separators: &[usize],
    first: usize,
    source: WingetSource,
    limits: &Limits,
) -> Result<CliInventory, WingetError> {
    let (head, _) = lines.split_at(first);
    let preamble_lines = head.iter().filter(|line| !is_blank(line) && !is_frame(line)).count().saturating_sub(1);
    let scans = separators
        .iter()
        .enumerate()
        .map(|(position, start)| {
            let stop = separators.get(position + 1).map_or(lines.len(), |next| next.saturating_sub(1));
            scan_table(lines.get(start + 1..stop).unwrap_or(&[]), limits)
        })
        .collect::<Result<Vec<TableScan>, WingetError>>()?;
    if scans.iter().map(|scan| scan.rows.len()).sum::<usize>() > MAX_WINGET_UPDATES {
        Err(WingetError::TooManyUpdates { limit: MAX_WINGET_UPDATES })?;
    }
    let built = scans
        .iter()
        .flat_map(|scan| scan.rows.iter())
        .fold(Built::default(), |state, row| add_row(device, source, state, row));
    Ok(CliInventory {
        updates: built.updates.into_values().collect(),
        skipped: built.skipped,
        preamble_lines,
    })
}


pub fn scan_table<'a>(region: &[&'a str], limits: &Limits) -> Result<TableScan<'a>, WingetError> {
    let classified: Vec<Classified> = region.iter().copied().map(|line| classify_line(line, limits)).collect();
    let rows: Vec<RowLine> = classified
        .iter()
        .map_while(|line| match line {
            Classified::Row(row) => Some(row.clone()),
            _ => None,
        })
        .collect();
    let footer = match classified.get(rows.len()) {
        Some(Classified::Footer(text)) => Some(*text),
        _ => None,
    };
    check_footer(&rows, footer)?;
    Ok(TableScan { rows, footer })
}


pub fn check_footer(rows: &[RowLine], footer: Option<&str>) -> Result<(), WingetError> {
    match footer {
        None if rows.last() == Some(&RowLine::Unshaped) => Err(WingetError::FooterUnreadable),
        None => Ok(()),
        Some(text) => {
            let count = footer_count(text)?;
            if count as usize == rows.len() {
                Ok(())
            } else {
                Err(WingetError::FooterMismatch {
                    footer: count,
                    rows: rows.len(),
                })
            }
        }
    }
}


pub fn footer_count(text: &str) -> Result<u32, WingetError> {
    text.split(|character: char| !character.is_ascii_digit())
        .find(|piece| !piece.is_empty())
        .ok_or(WingetError::FooterUnreadable)?
        .parse::<u32>()
        .map_err(|_| WingetError::FooterTooLarge)
}


pub fn digit_runs(line: &str) -> usize {
    line.split(|character: char| !character.is_ascii_digit())
        .filter(|piece| !piece.is_empty())
        .count()
}


pub fn classify_line<'a>(line: &'a str, limits: &Limits) -> Classified<'a> {
    if is_blank(line) {
        Classified::Blank
    } else if line.len() > limits.max_line_bytes {
        Classified::Row(RowLine::Skipped(WingetSkip::LineTooLong))
    } else if line.chars().any(is_forbidden) {
        Classified::Row(RowLine::Skipped(WingetSkip::ControlCharacters))
    } else {
        classify_shape(line)
    }
}


pub fn classify_shape(line: &str) -> Classified<'_> {
    let tokens: Vec<&str> = line.split(' ').filter(|token| !token.is_empty()).collect();
    match (row_of(&tokens), digit_runs(line)) {
        (Some(row), _) => Classified::Row(row),
        (None, 1) => Classified::Footer(line),
        (None, _) => Classified::Row(RowLine::Unshaped),
    }
}


pub fn row_of<'a>(tokens: &[&'a str]) -> Option<RowLine<'a>> {
    match tokens {
        [name @ .., id, marker, installed, available] if !name.is_empty() && matches!(*marker, "<" | ">") => grade(id, installed, available, true),
        [name @ .., id, installed, available] if !name.is_empty() => grade(id, installed, available, false),
        _ => None,
    }
}


pub fn grade<'a>(id: &'a str, installed: &'a str, available: &'a str, unknown_installed: bool) -> Option<RowLine<'a>> {
    if [id, installed, available].iter().any(|token| token.contains(ELLIPSIS)) {
        Some(RowLine::Skipped(WingetSkip::Truncated))
    } else if is_winget_package_id(id) && is_winget_version(installed) && is_winget_version(available) {
        Some(RowLine::Item(Row {
            id,
            installed,
            available,
            unknown_installed,
        }))
    } else {
        None
    }
}


pub fn add_row(device: &Device, source: WingetSource, mut state: Built, row: &RowLine) -> Built {
    match row {
        RowLine::Item(item) => add_item(device, source, state, item),
        RowLine::Skipped(reason) => {
            bump(&mut state.skipped, *reason);
            state
        }
        RowLine::Unshaped => {
            bump(&mut state.skipped, WingetSkip::Malformed);
            state
        }
    }
}


pub fn add_item(device: &Device, source: WingetSource, mut state: Built, item: &Row) -> Built {
    if item.unknown_installed {
        bump(&mut state.skipped, WingetSkip::UnknownInstalledVersion);
    }
    match state.updates.entry(item.id.to_ascii_lowercase()) {
        Entry::Vacant(slot) => {
            slot.insert(Update {
                tenant: device.tenant.clone(),
                device_id: device.device_id.clone(),
                package: item.id.to_string(),
                architecture: ARCHITECTURE.to_string(),
                installed_version: (!item.unknown_installed).then(|| item.installed.to_string()),
                candidate_version: item.available.to_string(),
                origin: Some(source_name(source).to_string()),
                security: false,
                advisory_id: None,
                severity: None,
            });
        }
        Entry::Occupied(_) => bump(&mut state.skipped, WingetSkip::Duplicate),
    }
    state
}


pub fn source_name(source: WingetSource) -> &'static str {
    match source {
        WingetSource::Winget => "winget",
        WingetSource::Msstore => "msstore",
    }
}


pub fn bump(skipped: &mut WingetSkipCounts, reason: WingetSkip) {
    *skipped.entry(reason).or_insert(0) += 1;
}
