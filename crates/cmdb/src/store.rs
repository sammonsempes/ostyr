use crate::error::StoreError;
use crate::model::{
    Applied, Asset, Attribute, Conflict, DuplicateConflict, Event, IdentityKey, Limits, Observation, Outcome, RefusedConflict, Resolution, Snapshot,
    Stored,
};
use crate::reconcile::{reconcile, RESERVED_ATTRIBUTE_PREFIX};
use crate::types::{Executor, Row, TruthMap, VersionMap};
use core_pg::error::PgError;
use core_pg::migrate::Migration;
use core_pg::scope::TenantScope;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};


pub const ASSETS_TABLE: &str = "cmdb_assets";


pub const CONFLICTS_TABLE: &str = "cmdb_conflicts";


pub const KEYS_TABLE: &str = "cmdb_identity_keys";


pub const ATTRIBUTES_TABLE: &str = "cmdb_attributes";


pub const ASSETS_SQL: &str = "SELECT id, kind, lifecycle, version::text FROM cmdb_assets WHERE tenant = $1 \
                              AND ($2::text::boolean OR id > $3::text) ORDER BY id LIMIT $4::text::bigint";


pub const KEYS_SQL: &str = "SELECT asset, key, value FROM cmdb_identity_keys WHERE tenant = $1 \
                            AND ($2::text::boolean OR (key, value) > ($3::text, $4::text)) ORDER BY key, value LIMIT $5::text::bigint";


pub const ATTRIBUTES_SQL: &str = "SELECT asset, name, value, source FROM cmdb_attributes WHERE tenant = $1 \
                                  AND ($2::text::boolean OR (asset, name) > ($3::text, $4::text)) ORDER BY asset, name LIMIT $5::text::bigint";


pub const ASSET_CURSOR: [usize; 1] = [0];


pub const KEY_CURSOR: [usize; 2] = [1, 2];


pub const ATTRIBUTE_CURSOR: [usize; 2] = [0, 1];


/// One statement (one implicit transaction): `$1` tenant, `$2` JSON changes, `$3` open-conflict cap, `$4` open key-conflict cap; answers the applied flag, the refused conflicts and the duplicates of open ones, each as a JSON array.
pub const APPLY_SQL: &str = include_str!("../migrations/apply.sql");


pub const UNIQUE_VIOLATION: &str = "23505";


pub const MAX_PAGES: usize = 10_000;


pub const MAX_PAGE_SIZE: usize = 5_000;


pub const ATTEMPT_CEILING: usize = 10;


pub const MAX_OPEN_CONFLICTS_CEILING: usize = 100_000;


pub const MAX_OPEN_KEY_CONFLICTS_CEILING: usize = 10_000;


pub const DUPLICATES_COLUMN: usize = 2;


pub const KIND_COLUMN: usize = 1;


pub const KEY_COLUMN: usize = 1;


pub const LIFECYCLE_COLUMN: usize = 2;


pub const VALUE_COLUMN: usize = 2;


pub const VERSION_COLUMN: usize = 3;


pub const SOURCE_COLUMN: usize = 3;


pub const MIGRATION_NAMESPACE: &str = "cmdb";


pub const MIGRATIONS: [Migration; 2] = [
    Migration {
        version: "001_cmdb",
        sql: include_str!("../migrations/001_cmdb.sql"),
    },
    Migration {
        version: "002_cmdb_conflict_status",
        sql: include_str!("../migrations/002_cmdb_conflict_status.sql"),
    },
];


pub fn conflict_of(error: PgError) -> StoreError {
    match error {
        PgError::Server { ref code, .. } if code == UNIQUE_VIOLATION => StoreError::VersionConflict,
        other => StoreError::Pg(other),
    }
}


/// A page size that is zero, above `MAX_PAGE_SIZE`, or too small to reach the row caps within `MAX_PAGES` pages is refused, as is a conflict cap (either) of 0 or above its ceiling.
pub fn check_limits(limits: &Limits) -> Result<(), StoreError> {
    let reach = limits.page_size.saturating_mul(MAX_PAGES);
    if limits.page_size == 0
        || limits.page_size > MAX_PAGE_SIZE
        || reach <= limits.max_assets.max(limits.max_child_rows)
        || limits.max_open_conflicts == 0
        || limits.max_open_conflicts > MAX_OPEN_CONFLICTS_CEILING
        || limits.max_open_key_conflicts == 0
        || limits.max_open_key_conflicts > MAX_OPEN_KEY_CONFLICTS_CEILING
    {
        Err(StoreError::BadLimits)
    } else {
        Ok(())
    }
}


pub fn cursor_of(row: &Row, cursor_columns: &[usize], table: &'static str) -> Result<Vec<String>, StoreError> {
    cursor_columns.iter().map(|column| cell(row, *column, table).cloned()).collect()
}


/// Reads one table by keyset pages; a table not ending within `max_rows` or `MAX_PAGES` is `TooManyRows`, never partial.
pub async fn read_table(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    table: &'static str,
    sql: &'static str,
    cursor_columns: &[usize],
    page_size: usize,
    max_rows: usize,
) -> Result<Vec<Row>, StoreError> {
    let max_pages = max_rows / page_size.max(1) + 1;
    let mut rows: Vec<Row> = Vec::new();
    let mut cursor: Vec<String> = cursor_columns.iter().map(|_| String::new()).collect();
    let mut done = false;
    let mut pages = 0;
    while !done && pages < MAX_PAGES && pages < max_pages {
        let mut params = vec![(pages == 0).to_string()];
        params.extend(cursor.iter().cloned());
        params.push(page_size.to_string());
        let page = exec(scope.clone(), sql, params).await?;
        done = page.len() < page_size;
        if let Some(last) = page.last() {
            cursor = cursor_of(last, cursor_columns, table)?;
        }
        rows.extend(page);
        pages += 1;
    }
    if !done || rows.len() > max_rows {
        Err(StoreError::TooManyRows { table, limit: max_rows })
    } else {
        Ok(rows)
    }
}


pub fn cell<'a>(row: &'a Row, index: usize, table: &'static str) -> Result<&'a String, StoreError> {
    row.get(index).ok_or(StoreError::BadRow { table })
}


pub fn parse_enum<Wanted: DeserializeOwned>(text: &str, table: &'static str) -> Result<Wanted, StoreError> {
    serde_json::from_value(Value::String(text.to_owned())).map_err(|source| StoreError::BadValue { table, source })
}


pub fn asset_from_row(row: &Row) -> Result<(Asset, i64), StoreError> {
    let version = cell(row, VERSION_COLUMN, ASSETS_TABLE)?.parse::<i64>().map_err(StoreError::BadVersion)?;
    let asset = Asset {
        id: cell(row, 0, ASSETS_TABLE)?.clone(),
        kind: parse_enum(cell(row, KIND_COLUMN, ASSETS_TABLE)?, ASSETS_TABLE)?,
        lifecycle: parse_enum(cell(row, LIFECYCLE_COLUMN, ASSETS_TABLE)?, ASSETS_TABLE)?,
        keys: Default::default(),
        attributes: Default::default(),
    };
    Ok((asset, version))
}


pub fn asset_of<'a>(assets: &'a mut BTreeMap<String, Asset>, id: &str) -> Result<&'a mut Asset, StoreError> {
    assets.get_mut(id).ok_or(StoreError::VersionConflict)
}


/// The tenant scope reaches every statement through the executor, which binds it as `$1`.
pub async fn load_assets(exec: Executor<'_, '_>, scope: &TenantScope, limits: &Limits) -> Result<Snapshot, StoreError> {
    check_limits(limits)?;
    let asset_rows = read_table(exec, scope, ASSETS_TABLE, ASSETS_SQL, &ASSET_CURSOR, limits.page_size, limits.max_assets).await?;
    let key_rows = read_table(exec, scope, KEYS_TABLE, KEYS_SQL, &KEY_CURSOR, limits.page_size, limits.max_child_rows).await?;
    let attribute_rows = read_table(
        exec,
        scope,
        ATTRIBUTES_TABLE,
        ATTRIBUTES_SQL,
        &ATTRIBUTE_CURSOR,
        limits.page_size,
        limits.max_child_rows,
    )
    .await?;
    let mut by_id: BTreeMap<String, Asset> = BTreeMap::new();
    let mut versions = VersionMap::new();
    for row in &asset_rows {
        let (asset, version) = asset_from_row(row)?;
        versions.insert(asset.id.clone(), version);
        by_id.insert(asset.id.clone(), asset);
    }
    for row in &key_rows {
        let key: IdentityKey = parse_enum(cell(row, KEY_COLUMN, KEYS_TABLE)?, KEYS_TABLE)?;
        let value = cell(row, VALUE_COLUMN, KEYS_TABLE)?.clone();
        asset_of(&mut by_id, cell(row, 0, KEYS_TABLE)?)?.keys.insert(key, value);
    }
    for row in &attribute_rows {
        let attribute = Attribute {
            value: cell(row, VALUE_COLUMN, ATTRIBUTES_TABLE)?.clone(),
            source: cell(row, SOURCE_COLUMN, ATTRIBUTES_TABLE)?.clone(),
        };
        let name = cell(row, KEY_COLUMN, ATTRIBUTES_TABLE)?.clone();
        asset_of(&mut by_id, cell(row, 0, ATTRIBUTES_TABLE)?)?.attributes.insert(name, attribute);
    }
    Ok(Snapshot {
        assets: by_id.into_values().collect(),
        versions,
    })
}


/// Assets new or different from what was read, plus every asset a conflict or event names (their version is checked and bumped).
pub fn changed_assets<'a>(snapshot: &Snapshot, outcome: &'a Outcome) -> Vec<&'a Asset> {
    let known: BTreeMap<&str, &Asset> = snapshot.assets.iter().map(|asset| (asset.id.as_str(), asset)).collect();
    let named: BTreeSet<&str> = outcome
        .conflicts
        .iter()
        .map(|conflict| conflict.asset.as_str())
        .chain(outcome.events.iter().map(event_asset))
        .collect();
    outcome
        .inventory
        .iter()
        .filter(|asset| named.contains(asset.id.as_str()) || known.get(asset.id.as_str()).copied() != Some(*asset))
        .collect()
}


pub fn event_asset(event: &Event) -> &str {
    match event {
        Event::Created { asset } | Event::Reappeared { asset, .. } => asset,
    }
}


/// An asset needs a new version unless it is only named by conflicts, which the statement bumps when one of them is new.
pub fn is_touched(snapshot: &Snapshot, outcome: &Outcome, asset: &Asset) -> bool {
    let known = snapshot.assets.iter().find(|stored| stored.id == asset.id);
    known != Some(asset) || outcome.events.iter().any(|event| event_asset(event) == asset.id)
}


pub fn asset_doc(asset: &Asset, version: i64, touch: bool) -> Value {
    json!({
        "id": asset.id,
        "touch": touch,
        "kind": asset.kind,
        "lifecycle": asset.lifecycle,
        "version": version,
        "keys": asset.keys.iter().map(|(key, value)| json!({"key": key, "value": value})).collect::<Vec<Value>>(),
        "attributes": asset
            .attributes
            .iter()
            .map(|(name, attribute)| json!({"name": name, "value": attribute.value, "source": attribute.source}))
            .collect::<Vec<Value>>(),
    })
}


pub fn resolution_text(resolution: Resolution) -> &'static str {
    match resolution {
        Resolution::TookObserved => "took_observed",
        Resolution::KeptCurrent => "kept_current",
        Resolution::Undecided => "undecided",
    }
}


/// A conflict recording a write by the source of truth is never refused: refusing it would hide the write.
pub fn is_exempt(conflict: &Conflict) -> bool {
    conflict.resolution == Resolution::TookObserved
}


/// An identity signal (`key:` attribute) is capped apart from the other conflicts.
pub fn is_key_signal(conflict: &Conflict) -> bool {
    conflict.attribute.starts_with(RESERVED_ATTRIBUTE_PREFIX)
}


pub fn conflict_doc(conflict: &Conflict) -> Value {
    json!({
        "exempt": is_exempt(conflict),
        "is_key": is_key_signal(conflict),
        "asset": conflict.asset,
        "attribute": conflict.attribute,
        "current_value": conflict.current.value,
        "current_source": conflict.current.source,
        "observed_value": conflict.observed.value,
        "observed_source": conflict.observed.source,
        "resolution": resolution_text(conflict.resolution),
    })
}


pub fn event_doc(event: &Event) -> Value {
    match event {
        Event::Created { asset } => json!({"asset": asset, "kind": "created", "lifecycle": null}),
        Event::Reappeared { asset, lifecycle } => json!({"asset": asset, "kind": "reappeared", "lifecycle": lifecycle}),
    }
}


/// Writes the changed assets, their keys and attributes, the conflicts and the events in one statement; a stale version fails it whole.
pub async fn apply_outcome(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    snapshot: &Snapshot,
    outcome: &Outcome,
    limits: &Limits,
) -> Result<Applied, StoreError> {
    let assets: Vec<Value> = changed_assets(snapshot, outcome)
        .into_iter()
        .map(|asset| {
            asset_doc(
                asset,
                snapshot.versions.get(&asset.id).copied().unwrap_or(0),
                is_touched(snapshot, outcome, asset),
            )
        })
        .collect();
    let document = json!({
        "assets": assets,
        "conflicts": outcome.conflicts.iter().map(conflict_doc).collect::<Vec<Value>>(),
        "events": outcome.events.iter().map(event_doc).collect::<Vec<Value>>(),
    });
    let rows = exec(
        scope.clone(),
        APPLY_SQL,
        vec![
            document.to_string(),
            limits.max_open_conflicts.to_string(),
            limits.max_open_key_conflicts.to_string(),
        ],
    )
    .await
    .map_err(conflict_of)?;
    let answer = rows.first().ok_or(StoreError::BadRow { table: CONFLICTS_TABLE })?;
    let applied = cell(answer, 0, CONFLICTS_TABLE)? == "true";
    let refused: Vec<RefusedConflict> = serde_json::from_str(cell(answer, 1, CONFLICTS_TABLE)?).map_err(StoreError::BadRefused)?;
    let duplicates: Vec<DuplicateConflict> =
        serde_json::from_str(cell(answer, DUPLICATES_COLUMN, CONFLICTS_TABLE)?).map_err(StoreError::BadDuplicates)?;
    if applied {
        Ok(Applied { refused, duplicates })
    } else {
        Err(StoreError::VersionConflict)
    }
}


/// Enforces the one conflict per asset, attribute and observed source that `without_listed` relies on.
pub fn check_one_conflict_per_triple(outcome: &Outcome) -> Result<(), StoreError> {
    let mut seen: BTreeSet<(&str, &str, &str)> = BTreeSet::new();
    outcome.conflicts.iter().try_for_each(|conflict| {
        let triple = (conflict.asset.as_str(), conflict.attribute.as_str(), conflict.observed.source.as_str());
        if seen.insert(triple) {
            Ok(())
        } else {
            Err(StoreError::DuplicateConflict {
                asset: conflict.asset.clone(),
                attribute: conflict.attribute.clone(),
                source_name: conflict.observed.source.clone(),
            })
        }
    })
}


/// One observation has one conflict per asset, attribute and observed source, so that triple identifies a refused or duplicate conflict.
pub fn without_listed(outcome: Outcome, listed: &[(&str, &str, &str)]) -> Outcome {
    let conflicts = outcome
        .conflicts
        .into_iter()
        .filter(|conflict| !listed.contains(&(conflict.asset.as_str(), conflict.attribute.as_str(), conflict.observed.source.as_str())))
        .collect();
    Outcome { conflicts, ..outcome }
}


pub fn without_refused(outcome: Outcome, refused: &[RefusedConflict]) -> Outcome {
    let listed: Vec<(&str, &str, &str)> = refused
        .iter()
        .map(|gone| (gone.asset.as_str(), gone.attribute.as_str(), gone.observed_source.as_str()))
        .collect();
    without_listed(outcome, &listed)
}


pub fn without_duplicates(outcome: Outcome, duplicates: &[DuplicateConflict]) -> Outcome {
    let listed: Vec<(&str, &str, &str)> = duplicates
        .iter()
        .map(|gone| (gone.asset.as_str(), gone.attribute.as_str(), gone.observed_source.as_str()))
        .collect();
    without_listed(outcome, &listed)
}


pub async fn attempt(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    observation: &Observation,
    truth: &TruthMap,
    limits: &Limits,
) -> Result<Stored, StoreError> {
    let snapshot = load_assets(exec, scope, limits).await?;
    let outcome = reconcile(&snapshot.assets, observation, truth)?;
    check_one_conflict_per_triple(&outcome)?;
    let applied = apply_outcome(exec, scope, &snapshot, &outcome, limits).await?;
    Ok(Stored {
        outcome: without_duplicates(without_refused(outcome, &applied.refused), &applied.duplicates),
        refused_conflicts: applied.refused,
        duplicate_conflicts: applied.duplicates,
    })
}


/// Load, reconcile, apply; a version conflict reloads and retries up to `limits.max_attempts` times.
pub async fn reconcile_stored(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    observation: &Observation,
    truth: &TruthMap,
    limits: &Limits,
) -> Result<Stored, StoreError> {
    let mut attempts = 0;
    let mut result = Err(StoreError::VersionConflict);
    while matches!(result, Err(StoreError::VersionConflict)) && attempts < ATTEMPT_CEILING && attempts < limits.max_attempts {
        attempts += 1;
        result = attempt(exec, scope, observation, truth, limits).await;
    }
    match result {
        Err(StoreError::VersionConflict) => Err(StoreError::RetriesExhausted { attempts }),
        other => other,
    }
}
