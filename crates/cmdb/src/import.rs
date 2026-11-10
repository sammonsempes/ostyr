use crate::error::ImportError;
use crate::model::{Asset, AssetKind, Conflict, Event, Observation, Outcome};
use crate::reconcile::{find_asset, reconcile};
use crate::types::{ColumnMap, IdSet, KeyColumnMap, ObservedMap, RawRow, RowMap, TruthMap};
use core_config::load::load_file;
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::Path;


pub const MAX_IMPORT_BYTES: u64 = 16_777_216;


pub const MAX_IMPORT_ROWS: usize = 100_000;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    Csv,
    JsonLines,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportMapping {
    pub format: ImportFormat,
    pub source: String,
    pub kind: AssetKind,
    pub keys: KeyColumnMap,
    #[serde(default)]
    pub attributes: ColumnMap,
    pub max_bytes: Option<u64>,
    pub max_rows: Option<usize>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRow {
    pub line: u64,
    pub reason: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReport {
    pub inventory: Vec<Asset>,
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub unchanged: Vec<String>,
    pub conflicts: Vec<Conflict>,
    pub rejected: Vec<RejectedRow>,
}


#[derive(Debug, Clone, Default)]
pub struct ImportState {
    pub inventory: Vec<Asset>,
    pub created: IdSet,
    pub updated: IdSet,
    pub unchanged: IdSet,
    pub conflicts: Vec<Conflict>,
    pub rejected: Vec<RejectedRow>,
}


pub const RESERVED_SOURCE: &str = "cmdb";


pub const RESERVED_ATTRIBUTE_PREFIX: &str = "key:";


/// Refuses the source `cmdb` and attribute names starting with `key:`, which would imitate a key conflict; the error names the field, never the value.
pub fn check_mapping(mapping: &ImportMapping) -> Result<(), ImportError> {
    let source_reserved = mapping.source.trim().eq_ignore_ascii_case(RESERVED_SOURCE);
    let attribute_reserved = mapping
        .attributes
        .keys()
        .any(|name| name.trim_start().to_ascii_lowercase().starts_with(RESERVED_ATTRIBUTE_PREFIX));
    match (source_reserved, attribute_reserved) {
        (true, _) => Err(ImportError::ReservedName { field: "source" }),
        (false, true) => Err(ImportError::ReservedName { field: "attributes" }),
        (false, false) => Ok(()),
    }
}


pub fn load_mapping(path: &Path) -> Result<ImportMapping, ImportError> {
    let mapping: ImportMapping = load_file(path)?;
    check_mapping(&mapping)?;
    Ok(mapping)
}


/// Reads at most `limit` bytes; one more byte than the limit is read to detect an oversized file.
pub fn read_bounded<Input: Read>(reader: Input, limit: u64) -> Result<String, ImportError> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    let text = String::from_utf8(bytes)?;
    let within = text.len() as u64 <= limit;
    within.then_some(text).ok_or(ImportError::TooLarge { limit })
}


pub fn scalar_text(value: &Value) -> Result<String, String> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Number(number) => Ok(number.to_string()),
        Value::Bool(flag) => Ok(flag.to_string()),
        _ => Err("field is not a scalar".to_string()),
    }
}


pub fn json_row(text: &str) -> Result<RowMap, String> {
    match serde_json::from_str::<Value>(text).map_err(|error| error.to_string())? {
        Value::Object(fields) => fields
            .iter()
            .filter(|(_, value)| !value.is_null())
            .map(|(name, value)| scalar_text(value).map(|scalar| (name.clone(), scalar)))
            .collect(),
        _ => Err("line is not a JSON object".to_string()),
    }
}


pub fn json_rows(text: &str, max_rows: usize) -> Vec<RawRow> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| (index as u64 + 1, json_row(line)))
        .take(max_rows + 1)
        .collect()
}


pub fn csv_rows(text: &str, mapping: &ImportMapping, max_rows: usize) -> Result<Vec<RawRow>, ImportError> {
    let mut reader = csv::ReaderBuilder::new().from_reader(text.as_bytes());
    let headers = reader.headers().map_err(ImportError::Header)?.clone();
    mapping
        .keys
        .values()
        .chain(mapping.attributes.values())
        .find(|column| !headers.iter().any(|header| header == column.as_str()))
        .map_or(Ok(()), |column| Err(ImportError::MissingColumn { column: column.clone() }))?;
    let rows = reader
        .records()
        .take(max_rows + 1)
        .map(|record| match record {
            Ok(fields) => (
                fields.position().map_or(0, csv::Position::line),
                Ok(headers.iter().map(str::to_string).zip(fields.iter().map(str::to_string)).collect()),
            ),
            Err(error) => (error.position().map_or(0, csv::Position::line), Err(error.to_string())),
        })
        .collect();
    Ok(rows)
}


pub fn field(row: &RowMap, column: &str) -> Option<String> {
    row.get(column)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}


pub fn to_observation(row: &RowMap, mapping: &ImportMapping) -> Observation {
    let attributes: ObservedMap = mapping
        .attributes
        .iter()
        .filter_map(|(name, column)| field(row, column).map(|value| (name.clone(), value)))
        .collect();
    Observation {
        source: mapping.source.clone(),
        kind: mapping.kind,
        keys: mapping
            .keys
            .iter()
            .filter_map(|(key, column)| field(row, column).map(|value| (*key, value)))
            .collect(),
        attributes,
    }
}


pub fn reject(mut state: ImportState, line: u64, reason: String) -> ImportState {
    state.rejected.push(RejectedRow { line, reason });
    state
}


pub fn record_outcome(mut state: ImportState, observation: &Observation, outcome: Outcome) -> ImportState {
    let created = outcome.events.iter().find_map(|event| match event {
        Event::Created { asset } => Some(asset.clone()),
        Event::Reappeared { .. } => None,
    });
    let changed = outcome
        .inventory
        .iter()
        .find(|asset| !state.inventory.contains(asset))
        .map(|asset| asset.id.clone());
    let matched = find_asset(&state.inventory, observation).map(|asset| asset.id.clone());
    let was_created = created.is_some();
    let was_changed = changed.is_some();
    state.created.extend(created);
    state.updated.extend(changed.filter(|_| !was_created));
    state.unchanged.extend(matched.filter(|_| !was_changed));
    state.conflicts.extend(outcome.conflicts);
    state.inventory = outcome.inventory;
    state
}


pub fn apply_row(state: ImportState, raw: RawRow, mapping: &ImportMapping, truth: &TruthMap) -> ImportState {
    let (line, parsed) = raw;
    match parsed {
        Err(reason) => reject(state, line, reason),
        Ok(row) => {
            let observation = to_observation(&row, mapping);
            match reconcile(&state.inventory, &observation, truth) {
                Err(error) => reject(state, line, error.to_string()),
                Ok(outcome) => record_outcome(state, &observation, outcome),
            }
        }
    }
}


pub fn finish(state: ImportState) -> ImportReport {
    let updated: IdSet = state.updated.difference(&state.created).cloned().collect();
    let unchanged = state
        .unchanged
        .iter()
        .filter(|id| !state.created.contains(*id) && !updated.contains(*id))
        .cloned()
        .collect();
    ImportReport {
        inventory: state.inventory,
        created: state.created.into_iter().collect(),
        updated: updated.into_iter().collect(),
        unchanged,
        conflicts: state.conflicts,
        rejected: state.rejected,
    }
}


/// Rows are applied in file order; a rejected row never reaches the reconciliation, which is pure, so nothing is half-imported.
pub fn import_reader<Input: Read>(
    reader: Input,
    mapping: &ImportMapping,
    inventory: &[Asset],
    truth: &TruthMap,
) -> Result<ImportReport, ImportError> {
    check_mapping(mapping)?;
    let max_rows = mapping.max_rows.unwrap_or(MAX_IMPORT_ROWS).min(MAX_IMPORT_ROWS);
    let text = read_bounded(reader, mapping.max_bytes.unwrap_or(MAX_IMPORT_BYTES).min(MAX_IMPORT_BYTES))?;
    let body = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let parsed = match mapping.format {
        ImportFormat::Csv => csv_rows(body, mapping, max_rows)?,
        ImportFormat::JsonLines => json_rows(body, max_rows),
    };
    let within = parsed.len() <= max_rows;
    let rows = within.then_some(parsed).ok_or(ImportError::TooManyRows { limit: max_rows })?;
    let start = ImportState {
        inventory: inventory.to_vec(),
        ..Default::default()
    };
    Ok(finish(rows.into_iter().fold(start, |state, raw| apply_row(state, raw, mapping, truth))))
}


pub fn import_file(path: &Path, mapping: &ImportMapping, inventory: &[Asset], truth: &TruthMap) -> Result<ImportReport, ImportError> {
    import_reader(File::open(path)?, mapping, inventory, truth)
}
