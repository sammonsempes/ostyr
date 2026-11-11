use crate::error::StoreError;
use crate::stored::{AssetCounts, AssetDetail, AssetPage, AssetSummary, AttributeView, KeyView, SummaryList};
use crate::types::{Executor, Row};
use core_pg::scope::TenantScope;


pub const MAX_LIST_LIMIT: usize = 100;


pub const MAX_ID_BYTES: usize = 512;


pub const MAX_DETAIL_KEYS: usize = 64;


pub const MAX_DETAIL_ATTRIBUTES: usize = 500;


pub const FIRST_LIST_SQL: &str = "SELECT a.id, a.kind, a.lifecycle, a.version::text, \
    (SELECT count(*) FROM cmdb_identity_keys k WHERE k.tenant = a.tenant AND k.asset = a.id)::text, \
    (SELECT count(*) FROM cmdb_attributes t WHERE t.tenant = a.tenant AND t.asset = a.id)::text, \
    (SELECT count(*) FROM cmdb_conflicts c WHERE c.tenant = a.tenant AND c.asset = a.id AND c.status = 'open')::text \
    FROM cmdb_assets a WHERE a.tenant = $1 ORDER BY a.id COLLATE \"C\" LIMIT $2::text::bigint";


pub const NEXT_LIST_SQL: &str = "SELECT a.id, a.kind, a.lifecycle, a.version::text, \
    (SELECT count(*) FROM cmdb_identity_keys k WHERE k.tenant = a.tenant AND k.asset = a.id)::text, \
    (SELECT count(*) FROM cmdb_attributes t WHERE t.tenant = a.tenant AND t.asset = a.id)::text, \
    (SELECT count(*) FROM cmdb_conflicts c WHERE c.tenant = a.tenant AND c.asset = a.id AND c.status = 'open')::text \
    FROM cmdb_assets a WHERE a.tenant = $1 AND a.id COLLATE \"C\" > $2::text COLLATE \"C\" ORDER BY a.id COLLATE \"C\" LIMIT $3::text::bigint";


pub const DETAIL_SQL: &str = "SELECT a.id, a.kind, a.lifecycle, a.version::text, \
    (SELECT count(*) FROM cmdb_identity_keys k WHERE k.tenant = a.tenant AND k.asset = a.id)::text, \
    (SELECT count(*) FROM cmdb_attributes t WHERE t.tenant = a.tenant AND t.asset = a.id)::text, \
    (SELECT count(*) FROM cmdb_conflicts c WHERE c.tenant = a.tenant AND c.asset = a.id AND c.status = 'open')::text \
    FROM cmdb_assets a WHERE a.tenant = $1 AND a.id = $2::text";


pub const DETAIL_KEYS_SQL: &str = "SELECT key, value FROM cmdb_identity_keys WHERE tenant = $1 AND asset = $2::text \
                                   ORDER BY key COLLATE \"C\", value COLLATE \"C\" LIMIT $3::text::bigint";


pub const DETAIL_ATTRIBUTES_SQL: &str = "SELECT name, value, source FROM cmdb_attributes WHERE tenant = $1 AND asset = $2::text \
                                         ORDER BY name COLLATE \"C\" LIMIT $3::text::bigint";


pub const SUMMARY_TABLE: &str = "cmdb_assets";


pub const ID_COLUMN: usize = 0;


pub const KIND_COLUMN: usize = 1;


pub const LIFECYCLE_COLUMN: usize = 2;


pub const VERSION_COLUMN: usize = 3;


pub const KEYS_COLUMN: usize = 4;


pub const ATTRIBUTES_COLUMN: usize = 5;


pub const CONFLICTS_COLUMN: usize = 6;


pub const SOURCE_COLUMN: usize = 2;


pub const NUL: char = '\0';


pub fn cell(row: &Row, column: usize) -> Result<String, StoreError> {
    row.get(column).cloned().ok_or(StoreError::BadRow { table: SUMMARY_TABLE })
}


pub fn count(row: &Row, column: usize) -> Result<u64, StoreError> {
    cell(row, column)?
        .parse::<u64>()
        .map_err(|source| StoreError::BadNumber { column, source })
}


/// An asset id is non-empty, at most `MAX_ID_BYTES` bytes and holds no NUL; checked before any SQL.
pub fn check_id(id: &str) -> Result<(), StoreError> {
    if id.is_empty() || id.len() > MAX_ID_BYTES || id.contains(NUL) {
        Err(StoreError::BadId)
    } else {
        Ok(())
    }
}


pub fn check_page(page: &AssetPage) -> Result<(), StoreError> {
    if !(1..=MAX_LIST_LIMIT).contains(&page.size) {
        Err(StoreError::BadPageSize { limit: MAX_LIST_LIMIT })
    } else {
        page.after
            .as_deref()
            .map_or(Ok(()), |after| check_id(after).map_err(|_bad| StoreError::BadCursor))
    }
}


pub fn summary_from_row(row: &Row) -> Result<AssetSummary, StoreError> {
    Ok(AssetSummary {
        id: cell(row, ID_COLUMN)?,
        kind: cell(row, KIND_COLUMN)?,
        lifecycle: cell(row, LIFECYCLE_COLUMN)?,
        version: count(row, VERSION_COLUMN)?,
        counts: AssetCounts {
            keys: count(row, KEYS_COLUMN)?,
            attributes: count(row, ATTRIBUTES_COLUMN)?,
            open_conflicts: count(row, CONFLICTS_COLUMN)?,
        },
    })
}


pub fn key_from_row(row: &Row) -> Result<KeyView, StoreError> {
    Ok(KeyView {
        key: cell(row, 0)?,
        value: cell(row, 1)?,
    })
}


pub fn attribute_from_row(row: &Row) -> Result<AttributeView, StoreError> {
    Ok(AttributeView {
        name: cell(row, 0)?,
        value: cell(row, 1)?,
        source: cell(row, SOURCE_COLUMN)?,
    })
}


/// A page is ordered by id in byte order (`COLLATE "C"`), `size + 1` rows are read to know whether a next page exists.
pub async fn list_asset_summaries(exec: Executor<'_, '_>, scope: &TenantScope, page: &AssetPage) -> Result<SummaryList, StoreError> {
    check_page(page)?;
    let fetch = (page.size + 1).to_string();
    let rows = match &page.after {
        None => exec(scope.clone(), FIRST_LIST_SQL, vec![fetch]).await?,
        Some(after) => exec(scope.clone(), NEXT_LIST_SQL, vec![after.clone(), fetch]).await?,
    };
    let mut summaries = rows.iter().map(summary_from_row).collect::<Result<Vec<AssetSummary>, StoreError>>()?;
    let more = summaries.len() > page.size;
    summaries.truncate(page.size);
    let next = summaries.last().filter(|_last| more).map(|last| last.id.clone());
    Ok(SummaryList { summaries, next })
}


pub async fn detail_of(exec: Executor<'_, '_>, scope: &TenantScope, row: &Row) -> Result<AssetDetail, StoreError> {
    let summary = summary_from_row(row)?;
    let key_limit = MAX_DETAIL_KEYS.to_string();
    let key_rows = exec(scope.clone(), DETAIL_KEYS_SQL, vec![summary.id.clone(), key_limit]).await?;
    let attribute_limit = MAX_DETAIL_ATTRIBUTES.to_string();
    let attribute_rows = exec(scope.clone(), DETAIL_ATTRIBUTES_SQL, vec![summary.id.clone(), attribute_limit]).await?;
    let keys = key_rows.iter().map(key_from_row).collect::<Result<Vec<KeyView>, StoreError>>()?;
    let attributes = attribute_rows
        .iter()
        .map(attribute_from_row)
        .collect::<Result<Vec<AttributeView>, StoreError>>()?;
    let truncated = summary.counts.keys > keys.len() as u64 || summary.counts.attributes > attributes.len() as u64;
    Ok(AssetDetail {
        summary,
        keys,
        attributes,
        truncated,
    })
}


/// The id is checked before SQL; an asset of another tenant is not found, as a missing one.
pub async fn get_asset_detail(exec: Executor<'_, '_>, scope: &TenantScope, id: &str) -> Result<Option<AssetDetail>, StoreError> {
    check_id(id)?;
    let rows = exec(scope.clone(), DETAIL_SQL, vec![id.to_owned()]).await?;
    match rows.first() {
        None => Ok(None),
        Some(row) => detail_of(exec, scope, row).await.map(Some),
    }
}
