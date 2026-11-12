use crate::error::CostError;
use crate::focus::read_focus;
use crate::model::{CostTable, Limits};
use core_pg::scope::tenant_scope;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};


/// The table parsed from an export and the SHA-256 (lowercase hex) of the very bytes that were parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub source: String,
    pub table: CostTable,
}


/// One bounded read (`take(max + 1)`), then the digest and the parse run on that same buffer, so the key always names what was stored.
pub fn read_export<Input: Read>(reader: Input, limits: &Limits, tenant: &str) -> Result<Export, CostError> {
    tenant_scope(tenant)?;
    let mut bytes = Vec::new();
    reader
        .take(limits.max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(csv::Error::from)?;
    let within = u64::try_from(bytes.len()).is_ok_and(|length| length <= limits.max_bytes);
    if within {
        let source = format!("{:x}", Sha256::digest(&bytes));
        let table = read_focus(Cursor::new(bytes), limits, tenant)?;
        Ok(Export { source, table })
    } else {
        Err(CostError::TooLarge { limit: limits.max_bytes })
    }
}
