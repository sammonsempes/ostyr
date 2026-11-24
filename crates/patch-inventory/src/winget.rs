//! Updatable winget packages from the `winget upgrade` text table (layout facts: the crate notes).

use crate::error::{InventoryError, WingetError};
use crate::limits::{MAX_WINGET_TABLES, MAX_WINGET_UPDATES, MIN_SEPARATOR_DASHES, SOURCE_OPEN_FAILED_EXIT};
use crate::model::{CliInventory, Device, Limits, Update, WingetSkip, WingetSource};
use crate::scan::{is_forbidden, read_input};
use crate::types::{RowCells, UpdatesByPackage, WingetSkipCounts};
use crate::validate::{is_winget_package_id, is_winget_version};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::io::Read;


pub const ARCHITECTURE: &str = "any";


pub const CRLF: &str = "\r\n";


pub const ELLIPSIS: char = '\u{2026}';


pub const LATIN_FIRST: char = '\u{00c0}';


pub const LATIN_LAST: char = '\u{024f}';


pub const PROGRESS_BLOCKS: [char; 2] = ['\u{2588}', '\u{2592}'];


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Widths {
    pub id: usize,
    pub version: usize,
}


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
    pub extra_footers: usize,
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
    let lines = table_lines(text)?;
    let separators: Vec<usize> = (0..lines.len()).filter(|index| is_separator(&lines, *index)).collect();
    if separators.len() > MAX_WINGET_TABLES {
        Err(WingetError::TooManyTables { limit: MAX_WINGET_TABLES })?;
    }
    match separators.first() {
        None => empty_listing(&lines),
        Some(first) => read_tables(device, &lines, &separators, *first, source, limits),
    }
}


pub fn table_lines(text: &str) -> Result<Vec<&str>, WingetError> {
    let head: Vec<&str> = lines_of(text).collect();
    match (0..head.len()).find(|index| is_separator(&head, *index)) {
        None => Ok(head),
        Some(first) => {
            let (kept, _) = head.split_at(first + 1);
            let end = kept
                .last()
                .map_or(0, |separator| separator.as_ptr() as usize - text.as_ptr() as usize + separator.len());
            let rest = text.split_at_checked(end).map_or("", |(_, after)| after);
            let body = if rest.is_empty() { Some(rest) } else { rest.strip_prefix(CRLF) };
            let tail = body.ok_or(WingetError::LineBreakInTable)?;
            let lines: Vec<&str> = kept.iter().copied().chain(tail.split_terminator(CRLF)).collect();
            if lines.iter().skip(first + 1).any(|line| line.contains(['\r', '\n'])) {
                Err(WingetError::LineBreakInTable)?;
            }
            Ok(lines)
        }
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
            let widths = widths_at(lines, *start, limits)?;
            scan_table(lines.get(start + 1..stop).unwrap_or(&[]), &widths, limits)
        })
        .collect::<Result<Vec<TableScan>, WingetError>>()?;
    let earlier = scans.len().saturating_sub(1);
    if scans.iter().take(earlier).any(|scan| scan.extra_footers > 0) {
        Err(WingetError::RowAfterTableEnd)?;
    }
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


pub fn widths_at(lines: &[&str], separator: usize, limits: &Limits) -> Result<Widths, WingetError> {
    let header = lines.get(separator.saturating_sub(1)).map_or("", |line| *line);
    let dashes = lines.get(separator).map_or(0, |line| line.len());
    column_widths(header, dashes, limits)
}


pub fn column_widths(header: &str, dashes: usize, limits: &Limits) -> Result<Widths, WingetError> {
    if header.len() > limits.max_line_bytes || !header.chars().all(is_header_character) {
        Err(WingetError::UnrecognisedLayout)?;
    }
    let characters: Vec<char> = header.chars().collect();
    let starts: Vec<usize> = characters
        .iter()
        .enumerate()
        .filter(|(index, character)| is_column_start(&characters, *index, **character))
        .map(|(index, _)| index)
        .collect();
    match starts.as_slice() {
        [_, id, version, available] if dashes >= *available => Ok(Widths {
            id: version - id,
            version: available - version,
        }),
        _ => Err(WingetError::UnrecognisedLayout),
    }
}


pub fn is_header_character(character: char) -> bool {
    character.is_ascii_graphic() || character == ' ' || ((LATIN_FIRST..=LATIN_LAST).contains(&character) && character.is_alphabetic())
}


pub fn is_column_start(characters: &[char], index: usize, character: char) -> bool {
    index == 0 || (character != ' ' && index.checked_sub(1).and_then(|previous| characters.get(previous)) == Some(&' '))
}


pub fn scan_table<'a>(region: &[&'a str], widths: &Widths, limits: &Limits) -> Result<TableScan<'a>, WingetError> {
    let classified: Vec<Classified> = region.iter().copied().map(|line| classify_line(line, widths, limits)).collect();
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
    let tail = classified.get(rows.len() + 1..).unwrap_or(&[]);
    if tail.iter().any(is_row_shaped) {
        Err(WingetError::RowAfterTableEnd)?;
    }
    check_footer(&rows, footer)?;
    let extra_footers = tail.iter().filter(|line| matches!(line, Classified::Footer(_))).count();
    Ok(TableScan { rows, footer, extra_footers })
}


pub fn is_row_shaped(line: &Classified) -> bool {
    matches!(line, Classified::Row(RowLine::Item(_) | RowLine::Skipped(WingetSkip::Truncated)))
}


pub fn check_footer(rows: &[RowLine], footer: Option<&str>) -> Result<(), WingetError> {
    match footer {
        None if rows.last() == Some(&RowLine::Unshaped) => Err(WingetError::FooterUnreadable),
        None if rows.is_empty() => Err(WingetError::UnrecognisedLayout),
        None => Err(WingetError::FooterMissing),
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


pub fn classify_line<'a>(line: &'a str, widths: &Widths, limits: &Limits) -> Classified<'a> {
    if is_blank(line) {
        Classified::Blank
    } else if line.len() > limits.max_line_bytes {
        Classified::Row(RowLine::Skipped(WingetSkip::LineTooLong))
    } else if line.chars().any(is_forbidden) {
        Classified::Row(RowLine::Skipped(WingetSkip::ControlCharacters))
    } else {
        classify_shape(line, widths)
    }
}


pub fn classify_shape<'a>(line: &'a str, widths: &Widths) -> Classified<'a> {
    let is_row = line
        .rsplit(' ')
        .next()
        .is_some_and(|last| last.contains(ELLIPSIS) || is_winget_version(last));
    match (is_row, digit_runs(line)) {
        (true, _) => Classified::Row(cut_row(line, widths)),
        (false, 1) => Classified::Footer(line),
        (false, _) => Classified::Row(RowLine::Unshaped),
    }
}


pub fn cut_row<'a>(line: &'a str, widths: &Widths) -> RowLine<'a> {
    row_cells(line, widths).map_or(RowLine::Skipped(WingetSkip::Malformed), |[id, version, available]| {
        grade(id, version, available)
    })
}


pub fn take_end(text: &str, count: usize) -> Option<(&str, &str)> {
    text.char_indices()
        .rev()
        .nth(count.saturating_sub(1))
        .map(|(offset, _)| text.split_at(offset))
}


pub fn is_padded_cell(cell: &str) -> bool {
    cell.ends_with(' ') && !cell.starts_with(' ')
}


pub fn row_cells<'a>(line: &'a str, widths: &Widths) -> Option<RowCells<'a>> {
    let (head, _) = line.rsplit_once(' ')?;
    let (before_available, available) = line.split_at(head.len() + 1);
    let (rest, version_cell) = take_end(before_available, widths.version)?;
    let (name_part, id_cell) = take_end(rest, widths.id)?;
    (name_part.ends_with(' ') && is_padded_cell(id_cell) && is_padded_cell(version_cell)).then_some([id_cell, version_cell, available])
}


pub fn split_marker(text: &str) -> (bool, &str) {
    match text.split_once(' ') {
        Some(("<" | ">", installed)) => (true, installed),
        _ => (false, text),
    }
}


pub fn is_cell_character(character: char) -> bool {
    character.is_ascii_graphic() || character == ' ' || character == ELLIPSIS
}


pub fn grade<'a>(id_cell: &'a str, version_cell: &'a str, available: &'a str) -> RowLine<'a> {
    let cells = [id_cell, version_cell, available];
    let id = id_cell.trim_matches(' ');
    let (unknown_installed, installed) = split_marker(version_cell.trim_matches(' '));
    if !cells.iter().all(|cell| cell.chars().all(is_cell_character)) {
        RowLine::Skipped(WingetSkip::Malformed)
    } else if cells.iter().any(|cell| cell.contains(ELLIPSIS)) {
        RowLine::Skipped(WingetSkip::Truncated)
    } else if is_winget_package_id(id) && is_winget_version(installed) {
        RowLine::Item(Row {
            id,
            installed,
            available,
            unknown_installed,
        })
    } else {
        RowLine::Skipped(WingetSkip::Malformed)
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
