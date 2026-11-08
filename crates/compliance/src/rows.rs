use crate::error::ComplianceError;
use crate::types::Row;


pub const MAX_RESULT_BYTES: usize = 4_194_304;


pub const MAX_RESULT_ROWS: usize = 10_000;


/// Parses an osquery JSON result (an array of objects with string values); anything else is an error, never a pass.
pub fn rows_from_json(text: &str) -> Result<Vec<Row>, ComplianceError> {
    let bytes = text.len();
    if bytes > MAX_RESULT_BYTES {
        Err(ComplianceError::ResultTooLarge { bytes })
    } else {
        let rows: Vec<Row> = serde_json::from_str(text)?;
        if rows.len() > MAX_RESULT_ROWS {
            Err(ComplianceError::TooManyRows { rows: rows.len() })
        } else {
            Ok(rows)
        }
    }
}
