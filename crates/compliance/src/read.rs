//! Read side of the drift state: keyset pages and one asset's results, scoped to a tenant.

use crate::alerting::{is_grammar, is_id, ASSET_PUNCTUATION, MAX_ASSET_CHARS, MAX_ID_CHARS};
use crate::error::ReadError;
use crate::read_model::{AssetResults, StateFilter, StatePage, StoredState};
use crate::store::VERDICT_FAIL;
use crate::types::{Served, StateKey};
use alerts::types::{Executor, Row};
use core_pg::scope::TenantScope;
use data_encoding::HEXLOWER;


pub const DEFAULT_LIMIT: usize = 50;


pub const MAX_PAGE: usize = 500;


pub const MAX_ASSET_RESULTS: usize = 1_000;


/// Two hexadecimal characters per byte of `baseline NUL control NUL asset`, at the longest each.
pub const MAX_CURSOR_HEX: usize = 2 * (2 * MAX_ID_CHARS + MAX_ASSET_CHARS + 2);


pub const FIELD_SEPARATOR: char = '\0';


pub const VERDICTS: [&str; 4] = [VERDICT_FAIL, "error", "excepted", "pass"];


pub const VERDICT_ALL: &str = "all";


pub const LIST_VERDICT_SQL: &str = "SELECT baseline, control, asset, verdict, COALESCE(first_failed_micros::text, ''), last_seen_micros::text \
                                    FROM compliance_state WHERE tenant = $1 AND verdict = $2::text \
                                    AND (baseline, control, asset) > ($3::text, $4::text, $5::text) \
                                    ORDER BY baseline, control, asset LIMIT $6::text::bigint";


pub const LIST_VERDICT_BASELINE_SQL: &str =
    "SELECT baseline, control, asset, verdict, COALESCE(first_failed_micros::text, ''), last_seen_micros::text \
                                             FROM compliance_state WHERE tenant = $1 AND verdict = $2::text AND baseline = $7::text \
                                             AND (baseline, control, asset) > ($3::text, $4::text, $5::text) \
                                             ORDER BY baseline, control, asset LIMIT $6::text::bigint";


pub const LIST_ALL_SQL: &str = "SELECT baseline, control, asset, verdict, COALESCE(first_failed_micros::text, ''), last_seen_micros::text \
                                FROM compliance_state WHERE tenant = $1 \
                                AND (baseline, control, asset) > ($2::text, $3::text, $4::text) \
                                ORDER BY baseline, control, asset LIMIT $5::text::bigint";


pub const LIST_ALL_BASELINE_SQL: &str = "SELECT baseline, control, asset, verdict, COALESCE(first_failed_micros::text, ''), last_seen_micros::text \
                                         FROM compliance_state WHERE tenant = $1 AND baseline = $6::text \
                                         AND (baseline, control, asset) > ($2::text, $3::text, $4::text) \
                                         ORDER BY baseline, control, asset LIMIT $5::text::bigint";


pub const ASSET_SQL: &str = "SELECT baseline, control, asset, verdict, COALESCE(first_failed_micros::text, ''), last_seen_micros::text \
                             FROM compliance_state WHERE tenant = $1 AND asset = $2::text \
                             ORDER BY baseline, control LIMIT $3::text::bigint";


/// The key every grammar key sorts after: the first page starts there.
pub fn first_key() -> StateKey {
    (String::new(), String::new(), String::new())
}


pub fn is_asset(text: &str) -> bool {
    is_grammar(text, MAX_ASSET_CHARS, ASSET_PUNCTUATION)
}


pub fn key_ok(baseline: &str, control: &str, asset: &str) -> bool {
    is_id(baseline) && is_id(control) && is_asset(asset)
}


pub fn limit_text(limit: usize) -> Result<String, ReadError> {
    i64::try_from(limit).map(|number| number.to_string()).map_err(|_big| ReadError::BadLimit)
}


pub fn encode_cursor(key: &StateKey) -> String {
    let (baseline, control, asset) = key;
    HEXLOWER.encode(format!("{baseline}{FIELD_SEPARATOR}{control}{FIELD_SEPARATOR}{asset}").as_bytes())
}


/// Lowercase hexadecimal of exactly the form `encode_cursor` prints, its length checked before decoding.
pub fn decode_cursor(text: &str) -> Result<StateKey, ReadError> {
    (text.len() <= MAX_CURSOR_HEX).then_some(()).ok_or(ReadError::BadCursor)?;
    let bytes = HEXLOWER.decode(text.as_bytes()).map_err(|_bad| ReadError::BadCursor)?;
    let joined = String::from_utf8(bytes).map_err(|_bad| ReadError::BadCursor)?;
    let fields: Vec<&str> = joined.split(FIELD_SEPARATOR).collect();
    match fields.as_slice() {
        [baseline, control, asset] if key_ok(baseline, control, asset) => Ok(((*baseline).to_owned(), (*control).to_owned(), (*asset).to_owned())),
        _other => Err(ReadError::BadCursor),
    }
}


/// A row outside the verdict, time or first-failed rules is `None` (skipped and counted); a key outside the grammar is an unmigrated schema.
pub fn stored_of(key: &StateKey, verdict: &str, first_failed: &str, last_seen: &str) -> Option<StoredState> {
    let first_failed_micros = if first_failed.is_empty() {
        Some(None)
    } else {
        first_failed.parse::<i64>().ok().map(Some)
    }?;
    let last_seen_micros = last_seen.parse::<i64>().ok()?;
    (VERDICTS.contains(&verdict) && (verdict == VERDICT_FAIL) == first_failed_micros.is_some()).then(|| StoredState {
        baseline: key.0.clone(),
        control: key.1.clone(),
        asset: key.2.clone(),
        verdict: verdict.to_owned(),
        first_failed_micros,
        last_seen_micros,
    })
}


pub fn parse_row(row: &Row) -> Result<(StateKey, Option<StoredState>), ReadError> {
    match row.as_slice() {
        [baseline, control, asset, verdict, first_failed, last_seen] => {
            key_ok(baseline, control, asset).then_some(()).ok_or(ReadError::BadKey)?;
            let key: StateKey = (baseline.clone(), control.clone(), asset.clone());
            let stored = stored_of(&key, verdict, first_failed, last_seen);
            Ok((key, stored))
        }
        _other => Err(ReadError::BadRow),
    }
}


/// The first `limit` rows read, served or skipped; the key of the last one is the raw cursor position.
pub fn serve_rows(rows: &[Row], limit: usize) -> Result<Served, ReadError> {
    rows.iter()
        .take(limit)
        .try_fold((Vec::new(), 0, None), |(mut kept, skipped, _last), row| {
            let (key, stored) = parse_row(row)?;
            let more_skipped = skipped + usize::from(stored.is_none());
            kept.extend(stored);
            Ok((kept, more_skipped, Some(key)))
        })
}


pub fn statement_of(filter: &StateFilter, start: &StateKey, fetch: String) -> (&'static str, Vec<String>) {
    let (baseline, control, asset) = start.clone();
    match (&filter.verdict, &filter.baseline) {
        (Some(verdict), None) => (LIST_VERDICT_SQL, vec![verdict.clone(), baseline, control, asset, fetch]),
        (Some(verdict), Some(only)) => (
            LIST_VERDICT_BASELINE_SQL,
            vec![verdict.clone(), baseline, control, asset, fetch, only.clone()],
        ),
        (None, None) => (LIST_ALL_SQL, vec![baseline, control, asset, fetch]),
        (None, Some(only)) => (LIST_ALL_BASELINE_SQL, vec![baseline, control, asset, fetch, only.clone()]),
    }
}


/// One statement reading at most `limit + 1` rows; skipped rows count toward `limit` and the cursor moves past them.
pub async fn list_state(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    filter: &StateFilter,
    cursor: Option<&StateKey>,
    limit: usize,
) -> Result<StatePage, ReadError> {
    (1..=MAX_PAGE)
        .contains(&limit)
        .then_some(())
        .ok_or(ReadError::BadPageSize { limit: MAX_PAGE })?;
    let fetch = limit_text(limit + 1)?;
    let start = cursor.cloned().unwrap_or_else(first_key);
    let (sql, params) = statement_of(filter, &start, fetch);
    let rows = exec(scope.clone(), sql, params).await?;
    let (served, skipped, last) = serve_rows(&rows, limit)?;
    let more = rows.len() > limit;
    let next_cursor = last.filter(|_key| more).map(|key| encode_cursor(&key));
    if skipped > 0 {
        tracing::warn!(skipped, "stored compliance rows skipped");
    }
    Ok(StatePage {
        rows: served,
        skipped,
        next_cursor,
    })
}


/// One statement reading at most `MAX_ASSET_RESULTS + 1` rows; `None` when the asset has no row, and for a name outside the grammar without any I/O.
pub async fn asset_state(exec: Executor<'_, '_>, scope: &TenantScope, asset: &str) -> Result<Option<AssetResults>, ReadError> {
    if is_asset(asset) {
        let rows = exec(scope.clone(), ASSET_SQL, vec![asset.to_owned(), limit_text(MAX_ASSET_RESULTS + 1)?]).await?;
        let (served, skipped, _last) = serve_rows(&rows, MAX_ASSET_RESULTS)?;
        if skipped > 0 {
            tracing::warn!(skipped, "stored compliance rows skipped");
        }
        Ok((!rows.is_empty()).then_some(AssetResults {
            rows: served,
            skipped,
            truncated: rows.len() > MAX_ASSET_RESULTS,
        }))
    } else {
        Ok(None)
    }
}
