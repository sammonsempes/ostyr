mod memory;
mod types;


use cmdb::error::StoreError;
use cmdb::model::{
    Asset, AssetKind, Attribute, Conflict, IdentityKey, Limits, Observation, Outcome, RefusedConflict, Resolution, DEFAULT_MAX_OPEN_CONFLICTS,
};
use cmdb::store::{
    apply_outcome, attempt, changed_assets, check_limits, conflict_of, event_doc, is_exempt, load_assets, read_table, reconcile_stored,
    resolution_text, without_refused, APPLY_SQL, ASSETS_SQL, ASSETS_TABLE, ASSET_CURSOR, ATTEMPT_CEILING, ATTRIBUTES_SQL, KEYS_SQL,
    MAX_OPEN_CONFLICTS_CEILING, MAX_PAGES, MAX_PAGE_SIZE, MIGRATIONS,
};
use cmdb::types::{Row, RowFuture, TruthMap};
use core_pg::error::PgError;
use core_pg::migrate::check_embedded;
use core_pg::scope::{tenant_scope, TenantScope};
use memory::{handle, lock, other_error, unique_violation, Db, Forced, Tenant};
use std::future::ready;
use types::TestResult;


const SMALL_PAGE: usize = 2;


const SMALL_ROWS: usize = 100;


const FIVE: usize = 5;


const FOUR: usize = 4;


const THREE: usize = 3;


const TWICE: usize = 2;


const SECOND_VERSION: i64 = 2;


const THIRD_VERSION: i64 = 3;


pub fn executor<'a>(db: &'a Db) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(handle(db, &scope, sql, &params))) }
}


pub fn endless<'a>() -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |_scope, _sql, _params| -> RowFuture<'a> { Box::pin(ready(Ok(vec![raw(&["a"])]))) }
}


pub fn observation(source: &str, serial: &str, attributes: &[(&str, &str)]) -> Observation {
    Observation {
        source: source.to_owned(),
        kind: AssetKind::Server,
        keys: [(IdentityKey::SerialNumber, serial.to_owned())].into_iter().collect(),
        attributes: attributes.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect(),
    }
}


pub fn with_tenant<Output>(db: &Db, name: &str, action: impl FnOnce(&mut Tenant) -> Output) -> Output {
    let mut tenants = lock(&db.tenants);
    action(tenants.entry(name.to_owned()).or_default())
}


pub fn seed_assets(db: &Db, name: &str, count: usize) {
    with_tenant(db, name, |tenant| {
        (0..count).for_each(|index| {
            tenant
                .assets
                .insert(format!("a{index}"), ("server".to_owned(), "in_service".to_owned(), 1));
        });
    });
}


#[tokio::test]
async fn migrations_are_valid_and_every_table_is_keyed_by_tenant() -> TestResult {
    check_embedded(&MIGRATIONS)?;
    let sql = MIGRATIONS.first().ok_or("no migration")?.sql;
    let tables = sql.matches("CREATE TABLE").count();
    assert_eq!(tables, FOUR + 1);
    assert_eq!(sql.matches("PRIMARY KEY (tenant,").count(), tables);
    [ASSETS_SQL, KEYS_SQL, ATTRIBUTES_SQL, APPLY_SQL]
        .iter()
        .for_each(|statement| assert!(statement.contains("tenant = $1") || statement.contains("t.tenant = $1"), "{statement}"));
    Ok(())
}


#[tokio::test]
async fn a_new_observation_is_created_then_updated_with_a_new_version() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let truth = TruthMap::new();
    let first = reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[("owner", "ann")]), &truth, &limits).await?;
    assert_eq!(first.outcome.events.len(), 1);
    let loaded = load_assets(&exec, &scope, &limits).await?;
    assert_eq!(loaded.assets.len(), 1);
    assert_eq!(loaded.versions.get("serial_number:SN1"), Some(&1));
    let second = reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[("owner", "bob")]), &truth, &limits).await?;
    assert!(second.outcome.events.is_empty());
    let reloaded = load_assets(&exec, &scope, &limits).await?;
    assert_eq!(reloaded.versions.get("serial_number:SN1"), Some(&SECOND_VERSION));
    let owner = reloaded
        .assets
        .first()
        .and_then(|asset| asset.attributes.get("owner"))
        .ok_or("no owner")?;
    assert_eq!(owner.value, "bob");
    Ok(())
}


#[tokio::test]
async fn an_unchanged_observation_writes_no_asset() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let truth = TruthMap::new();
    let seen = observation("agent", "SN1", &[("owner", "ann")]);
    reconcile_stored(&exec, &scope, &seen, &truth, &limits).await?;
    reconcile_stored(&exec, &scope, &seen, &truth, &limits).await?;
    let loaded = load_assets(&exec, &scope, &limits).await?;
    assert_eq!(loaded.versions.get("serial_number:SN1"), Some(&1));
    Ok(())
}


#[tokio::test]
async fn a_tenant_never_sees_or_changes_another_tenants_asset() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let limits = Limits::default();
    let truth = TruthMap::new();
    reconcile_stored(&exec, &acme, &observation("agent", "SN1", &[("owner", "ann")]), &truth, &limits).await?;
    assert!(load_assets(&exec, &other, &limits).await?.assets.is_empty());
    let created = reconcile_stored(&exec, &other, &observation("agent", "SN1", &[("owner", "zed")]), &truth, &limits).await?;
    assert_eq!(created.outcome.events.len(), 1);
    let acme_assets = load_assets(&exec, &acme, &limits).await?.assets;
    let other_assets = load_assets(&exec, &other, &limits).await?.assets;
    assert_eq!(acme_assets.len(), 1);
    assert_eq!(other_assets.len(), 1);
    assert_eq!(
        acme_assets.first().map(|asset| asset.id.as_str()),
        other_assets.first().map(|asset| asset.id.as_str())
    );
    let owner_of = |assets: &[Asset]| {
        assets
            .first()
            .and_then(|asset| asset.attributes.get("owner"))
            .map(|attribute| attribute.value.clone())
    };
    assert_eq!(owner_of(&acme_assets).as_deref(), Some("ann"));
    assert_eq!(owner_of(&other_assets).as_deref(), Some("zed"));
    let reads = lock(&db.reads).clone();
    assert!(reads.iter().any(|(tenant, _)| tenant == "acme") && reads.iter().any(|(tenant, _)| tenant == "other"));
    Ok(())
}


#[tokio::test]
async fn a_stale_version_applies_nothing_and_a_retry_succeeds() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    lock(&db.forced).extend([Forced::Stale, Forced::UniqueViolation]);
    reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[]), &TruthMap::new(), &limits).await?;
    assert_eq!(*lock(&db.apply_calls), THREE);
    assert_eq!(load_assets(&exec, &scope, &limits).await?.assets.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_real_concurrent_change_is_detected_by_the_version() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let truth = TruthMap::new();
    reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[("owner", "ann")]), &truth, &limits).await?;
    let snapshot = load_assets(&exec, &scope, &limits).await?;
    let outcome = cmdb::reconcile::reconcile(&snapshot.assets, &observation("agent", "SN1", &[("owner", "bob")]), &truth)?;
    reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[("owner", "cy")]), &truth, &limits).await?;
    let result = apply_outcome(&exec, &scope, &snapshot, &outcome, DEFAULT_MAX_OPEN_CONFLICTS).await;
    assert!(matches!(result, Err(StoreError::VersionConflict)), "{result:?}");
    let owner = load_assets(&exec, &scope, &limits)
        .await?
        .assets
        .first()
        .and_then(|asset| asset.attributes.get("owner").cloned());
    assert_eq!(owner.map(|attribute| attribute.value).as_deref(), Some("cy"));
    let direct = attempt(&exec, &scope, &observation("agent", "SN1", &[("owner", "di")]), &truth, &limits).await;
    assert!(direct.is_ok());
    Ok(())
}


#[tokio::test]
async fn retries_are_bounded() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits {
        max_attempts: TWICE,
        ..Limits::default()
    };
    lock(&db.forced).extend([Forced::Stale, Forced::Stale, Forced::Stale]);
    let result = reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[]), &TruthMap::new(), &limits).await;
    assert!(
        matches!(result, Err(StoreError::RetriesExhausted { attempts }) if attempts == TWICE),
        "{result:?}"
    );
    assert_eq!(*lock(&db.apply_calls), TWICE);
    let none = Limits {
        max_attempts: 0,
        ..Limits::default()
    };
    let zero = reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[]), &TruthMap::new(), &none).await;
    assert!(matches!(zero, Err(StoreError::RetriesExhausted { attempts: 0 })), "{zero:?}");
    Ok(())
}


#[tokio::test]
async fn other_errors_are_not_retried() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    lock(&db.forced).push_back(Forced::OtherError);
    let result = reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[]), &TruthMap::new(), &Limits::default()).await;
    assert!(matches!(result, Err(StoreError::Pg(PgError::Server { .. }))), "{result:?}");
    assert_eq!(*lock(&db.apply_calls), 1);
    assert!(matches!(conflict_of(unique_violation()), StoreError::VersionConflict));
    assert!(matches!(conflict_of(other_error()), StoreError::Pg(_)));
    let no_identity = Observation {
        keys: Default::default(),
        ..observation("agent", "SN1", &[])
    };
    let missing = reconcile_stored(&exec, &scope, &no_identity, &TruthMap::new(), &Limits::default()).await;
    assert!(matches!(missing, Err(StoreError::Cmdb(_))), "{missing:?}");
    Ok(())
}


#[tokio::test]
async fn reads_are_paged_and_capped() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    seed_assets(&db, "acme", FIVE);
    let paged = Limits {
        page_size: SMALL_PAGE,
        max_child_rows: SMALL_ROWS,
        ..Limits::default()
    };
    assert_eq!(load_assets(&exec, &scope, &paged).await?.assets.len(), FIVE);
    let capped = Limits {
        page_size: SMALL_PAGE,
        max_assets: THREE,
        max_child_rows: SMALL_ROWS,
        ..Limits::default()
    };
    let error = load_assets(&exec, &scope, &capped).await.err().ok_or("accepted")?;
    assert!(
        matches!(error, StoreError::TooManyRows { table, limit } if table == "cmdb_assets" && limit == THREE),
        "{error}"
    );
    let wide = Limits {
        page_size: SMALL_ROWS,
        max_assets: THREE,
        max_child_rows: SMALL_ROWS,
        ..Limits::default()
    };
    let over = load_assets(&exec, &scope, &wide).await.err().ok_or("accepted")?;
    assert!(matches!(over, StoreError::TooManyRows { .. }), "{over}");
    let exact = Limits {
        page_size: SMALL_PAGE,
        max_assets: FOUR,
        max_child_rows: SMALL_ROWS,
        ..Limits::default()
    };
    seed_assets(&db, "exact", FOUR);
    assert_eq!(load_assets(&exec, &tenant_scope("exact")?, &exact).await?.assets.len(), FOUR);
    let rows = read_table(&exec, &scope, ASSETS_TABLE, ASSETS_SQL, &ASSET_CURSOR, 1, 0).await;
    assert!(matches!(rows, Err(StoreError::TooManyRows { .. })), "{rows:?}");
    Ok(())
}


#[tokio::test]
async fn child_tables_are_capped_too() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    seed_assets(&db, "acme", 1);
    with_tenant(&db, "acme", |tenant| {
        (0..FIVE).for_each(|index| {
            tenant
                .attributes
                .insert(("a0".to_owned(), format!("n{index}")), ("v".to_owned(), "s".to_owned()));
        });
    });
    let limits = Limits {
        page_size: SMALL_PAGE,
        max_assets: SMALL_ROWS,
        max_child_rows: THREE,
        ..Limits::default()
    };
    let error = load_assets(&exec, &scope, &limits).await.err().ok_or("accepted")?;
    assert!(
        matches!(error, StoreError::TooManyRows { table, .. } if table == "cmdb_attributes"),
        "{error}"
    );
    Ok(())
}


pub fn raw(cells: &[&str]) -> Row {
    cells.iter().map(|cell| (*cell).to_owned()).collect()
}


pub async fn load_with(db: &Db, setup: impl FnOnce(&mut Tenant)) -> Result<(), StoreError> {
    with_tenant(db, "acme", setup);
    let exec = executor(db);
    load_assets(&exec, &tenant_scope("acme").map_err(StoreError::Pg)?, &Limits::default())
        .await
        .map(|_| ())
}


#[tokio::test]
async fn malformed_rows_are_refused() -> TestResult {
    let short = load_with(&Db::default(), |tenant| tenant.raw_assets.push(raw(&["a"]))).await;
    assert!(matches!(short, Err(StoreError::BadRow { .. })), "{short:?}");
    let kind = load_with(&Db::default(), |tenant| tenant.raw_assets.push(raw(&["a", "toaster", "in_service", "1"]))).await;
    assert!(matches!(kind, Err(StoreError::BadValue { .. })), "{kind:?}");
    let version = load_with(&Db::default(), |tenant| tenant.raw_assets.push(raw(&["a", "server", "in_service", "x"]))).await;
    assert!(matches!(version, Err(StoreError::BadVersion(_))), "{version:?}");
    let orphan = load_with(&Db::default(), |tenant| tenant.raw_keys.push(raw(&["ghost", "mac", "m"]))).await;
    assert!(matches!(orphan, Err(StoreError::VersionConflict)), "{orphan:?}");
    let short_key = load_with(&Db::default(), |tenant| tenant.raw_keys.push(raw(&["ghost", "mac"]))).await;
    assert!(matches!(short_key, Err(StoreError::BadRow { .. })), "{short_key:?}");
    let bad_key = load_with(&Db::default(), |tenant| {
        tenant.raw_assets.push(raw(&["a", "server", "in_service", "1"]));
        tenant.raw_keys.push(raw(&["a", "shoe_size", "9"]));
    })
    .await;
    assert!(matches!(bad_key, Err(StoreError::BadValue { .. })), "{bad_key:?}");
    let short_attribute = load_with(&Db::default(), |tenant| {
        tenant.raw_assets.push(raw(&["a", "server", "in_service", "1"]));
        tenant.raw_attributes.push(raw(&["a", "owner", "ann"]));
    })
    .await;
    assert!(matches!(short_attribute, Err(StoreError::BadRow { .. })), "{short_attribute:?}");
    let attribute_orphan = load_with(&Db::default(), |tenant| tenant.raw_attributes.push(raw(&["ghost", "owner", "ann", "s"]))).await;
    assert!(matches!(attribute_orphan, Err(StoreError::VersionConflict)), "{attribute_orphan:?}");
    Ok(())
}


#[tokio::test]
async fn conflicts_and_events_are_stored_with_their_asset() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let truth: TruthMap = [("owner".to_owned(), "hr".to_owned())].into_iter().collect();
    reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[("owner", "ann")]), &truth, &limits).await?;
    reconcile_stored(&exec, &scope, &observation("hr", "SN1", &[("owner", "bob")]), &truth, &limits).await?;
    with_tenant(&db, "acme", |tenant| {
        tenant
            .assets
            .insert("serial_number:SN1".to_owned(), ("server".to_owned(), "retired".to_owned(), THIRD_VERSION));
    });
    reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[]), &truth, &limits).await?;
    let (conflicts, events) = with_tenant(&db, "acme", |tenant| (tenant.conflicts.clone(), tenant.events.clone()));
    assert_eq!(conflicts.len(), 1);
    assert_eq!(
        memory::text(conflicts.first().ok_or("none")?, "resolution"),
        resolution_text(cmdb::model::Resolution::TookObserved)
    );
    assert_eq!(events.len(), TWICE);
    let reappeared = events
        .iter()
        .find(|event| memory::text(event, "kind") == "reappeared")
        .ok_or("no reappeared")?;
    assert_eq!(memory::text(reappeared, "lifecycle"), "retired");
    assert_eq!(resolution_text(cmdb::model::Resolution::KeptCurrent), "kept_current");
    assert_eq!(resolution_text(cmdb::model::Resolution::Undecided), "undecided");
    let created = event_doc(&cmdb::model::Event::Created { asset: "x".to_owned() });
    assert!(created.get("lifecycle").is_some_and(serde_json::Value::is_null));
    Ok(())
}


#[tokio::test]
async fn a_server_that_never_ends_a_table_is_too_many_rows_not_a_partial_read() -> TestResult {
    let never_ending = endless();
    let scope = tenant_scope("acme")?;
    let result = read_table(&never_ending, &scope, ASSETS_TABLE, ASSETS_SQL, &ASSET_CURSOR, 1, usize::MAX / TWICE).await;
    assert!(matches!(result, Err(StoreError::TooManyRows { .. })), "{result:?}");
    let short_cursor = read_table(&never_ending, &scope, ASSETS_TABLE, ASSETS_SQL, &[1], 1, TWICE).await;
    assert!(matches!(short_cursor, Err(StoreError::BadRow { .. })), "{short_cursor:?}");
    Ok(())
}


#[test]
fn limits_are_validated() -> TestResult {
    let good = Limits::default();
    assert!(check_limits(&good).is_ok());
    let refused = |limits: Limits| matches!(check_limits(&limits), Err(StoreError::BadLimits));
    assert!(refused(Limits { page_size: 0, ..good }));
    assert!(refused(Limits {
        page_size: MAX_PAGE_SIZE + 1,
        ..good
    }));
    assert!(refused(Limits { page_size: 1, ..good }));
    assert!(refused(Limits {
        max_open_conflicts: 0,
        ..good
    }));
    assert!(refused(Limits {
        max_open_conflicts: MAX_OPEN_CONFLICTS_CEILING + 1,
        ..good
    }));
    assert!(check_limits(&Limits {
        max_open_conflicts: MAX_OPEN_CONFLICTS_CEILING,
        ..good
    })
    .is_ok());
    assert!(refused(Limits {
        page_size: usize::MAX,
        ..good
    }));
    let edge = Limits {
        page_size: 1,
        max_assets: MAX_PAGES - 1,
        max_child_rows: MAX_PAGES - 1,
        ..good
    };
    assert!(check_limits(&edge).is_ok());
    assert!(refused(Limits {
        max_assets: MAX_PAGES,
        ..edge
    }));
    Ok(())
}


#[tokio::test]
async fn load_refuses_bad_limits_before_any_read() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let result = load_assets(
        &exec,
        &tenant_scope("acme")?,
        &Limits {
            page_size: 0,
            ..Limits::default()
        },
    )
    .await;
    assert!(matches!(result, Err(StoreError::BadLimits)), "{result:?}");
    assert!(lock(&db.reads).is_empty());
    Ok(())
}


#[tokio::test]
async fn keyset_paging_reads_every_row_once_across_pages() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    seed_assets(&db, "acme", FIVE);
    with_tenant(&db, "acme", |tenant| {
        (0..FIVE).for_each(|index| {
            tenant.keys.insert(("mac".to_owned(), format!("m{index}")), format!("a{index}"));
            tenant
                .attributes
                .insert((format!("a{index}"), "owner".to_owned()), ("v".to_owned(), "s".to_owned()));
        });
    });
    let limits = Limits {
        page_size: SMALL_PAGE,
        max_child_rows: SMALL_ROWS,
        ..Limits::default()
    };
    let snapshot = load_assets(&exec, &scope, &limits).await?;
    assert_eq!(snapshot.assets.len(), FIVE);
    assert!(snapshot.assets.iter().all(|asset| asset.keys.len() == 1 && asset.attributes.len() == 1));
    let statements = lock(&db.reads).len();
    assert_eq!(statements, THREE * THREE);
    Ok(())
}


#[tokio::test]
async fn an_identity_key_taken_by_a_concurrent_create_is_a_version_conflict_then_retried() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let truth = TruthMap::new();
    let seen = Observation {
        keys: [(IdentityKey::SerialNumber, "S9".to_owned()), (IdentityKey::Mac, "M".to_owned())]
            .into_iter()
            .collect(),
        ..observation("agent", "S9", &[])
    };
    let stale = load_assets(&exec, &scope, &limits).await?;
    let outcome = cmdb::reconcile::reconcile(&stale.assets, &seen, &truth)?;
    reconcile_stored(
        &exec,
        &scope,
        &Observation {
            keys: [(IdentityKey::Mac, "M".to_owned())].into_iter().collect(),
            ..observation("agent", "x", &[])
        },
        &truth,
        &limits,
    )
    .await?;
    let refused = apply_outcome(&exec, &scope, &stale, &outcome, DEFAULT_MAX_OPEN_CONFLICTS).await;
    assert!(matches!(refused, Err(StoreError::VersionConflict)), "{refused:?}");
    assert_eq!(load_assets(&exec, &scope, &limits).await?.assets.len(), 1);
    reconcile_stored(&exec, &scope, &seen, &truth, &limits).await?;
    let merged = load_assets(&exec, &scope, &limits).await?;
    assert_eq!(merged.assets.len(), 1);
    assert_eq!(merged.assets.first().map(|asset| asset.keys.len()), Some(TWICE));
    Ok(())
}


#[tokio::test]
async fn two_stale_applies_of_a_conflict_on_an_unchanged_asset_write_one_conflict() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let truth: TruthMap = [("owner".to_owned(), "hr".to_owned())].into_iter().collect();
    reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[("owner", "ann")]), &truth, &limits).await?;
    let snapshot = load_assets(&exec, &scope, &limits).await?;
    let outcome = cmdb::reconcile::reconcile(&snapshot.assets, &observation("hr", "SN1", &[("owner", "bob")]), &truth)?;
    let outcome_again = cmdb::reconcile::reconcile(&snapshot.assets, &observation("hr", "SN1", &[("owner", "bob")]), &truth)?;
    assert_eq!(outcome.conflicts.len(), 1);
    let changed = changed_assets(&snapshot, &outcome);
    assert!(changed
        .iter()
        .any(|asset| outcome.conflicts.iter().any(|conflict| conflict.asset == asset.id)));
    let only_event = cmdb::model::Outcome {
        inventory: snapshot.assets.clone(),
        conflicts: Vec::new(),
        events: Vec::new(),
    };
    assert!(changed_assets(&snapshot, &only_event).is_empty());
    apply_outcome(&exec, &scope, &snapshot, &outcome, DEFAULT_MAX_OPEN_CONFLICTS).await?;
    let second = apply_outcome(&exec, &scope, &snapshot, &outcome_again, DEFAULT_MAX_OPEN_CONFLICTS).await;
    assert!(matches!(second, Err(StoreError::VersionConflict)), "{second:?}");
    assert_eq!(with_tenant(&db, "acme", |tenant| tenant.conflicts.len()), 1);
    Ok(())
}


#[tokio::test]
async fn the_retry_count_never_passes_the_ceiling() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits {
        max_attempts: usize::MAX,
        ..Limits::default()
    };
    lock(&db.forced).extend(std::iter::repeat_n(Forced::Stale, ATTEMPT_CEILING + TWICE));
    let result = reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[]), &TruthMap::new(), &limits).await;
    assert!(
        matches!(result, Err(StoreError::RetriesExhausted { attempts }) if attempts == ATTEMPT_CEILING),
        "{result:?}"
    );
    Ok(())
}


#[test]
fn default_limits_are_the_production_values() -> TestResult {
    let limits = Limits::default();
    assert!(limits.page_size < limits.max_assets && limits.max_assets < limits.max_child_rows && limits.max_attempts > 0);
    Ok(())
}


fn nic_swap(source: &str, serial: &str, mac: &str) -> Observation {
    let mut swapped = observation(source, serial, &[("rack", "r1")]);
    swapped.keys.insert(IdentityKey::Mac, mac.to_owned());
    swapped
}


#[tokio::test]
async fn a_key_owned_by_another_asset_is_one_conflict_and_no_retry() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let truth = TruthMap::new();
    reconcile_stored(&exec, &scope, &observation("agent", "S1", &[]), &truth, &limits).await?;
    let mut owner_b = observation("agent", "S2", &[]);
    owner_b.keys.insert(IdentityKey::Mac, "M".to_owned());
    reconcile_stored(&exec, &scope, &owner_b, &truth, &limits).await?;
    let before = *lock(&db.apply_calls);
    let outcome = reconcile_stored(&exec, &scope, &nic_swap("agent", "S1", "M"), &truth, &limits)
        .await?
        .outcome;
    assert_eq!(*lock(&db.apply_calls), before + 1);
    assert_eq!(outcome.conflicts.len(), 1);
    let conflict = outcome.conflicts.first().ok_or("no conflict")?;
    assert_eq!(
        (conflict.asset.as_str(), conflict.current.value.as_str()),
        ("serial_number:S1", "serial_number:S2")
    );
    let loaded = load_assets(&exec, &scope, &limits).await?;
    let first = loaded.assets.iter().find(|asset| asset.id == "serial_number:S1").ok_or("no S1")?;
    assert!(!first.keys.contains_key(&IdentityKey::Mac));
    assert_eq!(first.attributes.get("rack").map(|attribute| attribute.value.as_str()), Some("r1"));
    Ok(())
}


fn version_of(db: &Db, id: &str) -> Option<i64> {
    with_tenant(db, "acme", |tenant| tenant.assets.get(id).map(|stored| stored.2))
}


#[tokio::test]
async fn an_identical_open_conflict_is_stored_once_and_leaves_the_version_alone() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let truth = TruthMap::new();
    reconcile_stored(&exec, &scope, &observation("agent", "S1", &[]), &truth, &limits).await?;
    let mut owner_b = observation("agent", "S2", &[]);
    owner_b.keys.insert(IdentityKey::Mac, "M".to_owned());
    reconcile_stored(&exec, &scope, &owner_b, &truth, &limits).await?;
    reconcile_stored(&exec, &scope, &nic_swap("agent", "S1", "M"), &truth, &limits).await?;
    let after_first = version_of(&db, "serial_number:S1");
    let second = reconcile_stored(&exec, &scope, &nic_swap("agent", "S1", "M"), &truth, &limits).await?;
    let third = reconcile_stored(&exec, &scope, &nic_swap("agent", "S1", "M"), &truth, &limits).await?;
    assert_eq!((second.outcome.conflicts.len(), third.outcome.conflicts.len()), (1, 1));
    assert_eq!(with_tenant(&db, "acme", |tenant| tenant.conflicts.len()), 1);
    assert_eq!(version_of(&db, "serial_number:S1"), after_first);
    Ok(())
}


#[tokio::test]
async fn a_conflict_differing_in_value_is_stored_and_bumps_the_version() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let truth = TruthMap::new();
    reconcile_stored(&exec, &scope, &observation("agent", "S1", &[("owner", "ann")]), &truth, &limits).await?;
    reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "bob")]), &truth, &limits).await?;
    let before = version_of(&db, "serial_number:S1");
    reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "cat")]), &truth, &limits).await?;
    assert_eq!(with_tenant(&db, "acme", |tenant| tenant.conflicts.len()), TWICE);
    assert!(version_of(&db, "serial_number:S1") > before);
    Ok(())
}


#[tokio::test]
async fn duplicates_inside_one_document_are_stored_once() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    reconcile_stored(&exec, &scope, &observation("agent", "S1", &[("owner", "ann")]), &TruthMap::new(), &limits).await?;
    let snapshot = load_assets(&exec, &scope, &limits).await?;
    let mut outcome = cmdb::reconcile::reconcile(&snapshot.assets, &observation("hr", "S1", &[("owner", "bob")]), &TruthMap::new())?;
    let duplicate = outcome.conflicts.clone();
    outcome.conflicts.extend(duplicate);
    apply_outcome(&exec, &scope, &snapshot, &outcome, DEFAULT_MAX_OPEN_CONFLICTS).await?;
    assert_eq!(with_tenant(&db, "acme", |tenant| tenant.conflicts.len()), 1);
    Ok(())
}


fn resolve_all(db: &Db) {
    with_tenant(db, "acme", |tenant| {
        tenant.conflicts.iter_mut().for_each(|conflict| memory::set_status(conflict, "resolved"));
    });
}


#[tokio::test]
async fn a_resolved_conflict_can_come_back_as_a_new_open_one() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    let truth = TruthMap::new();
    reconcile_stored(&exec, &scope, &observation("agent", "S1", &[("owner", "ann")]), &truth, &limits).await?;
    reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "bob")]), &truth, &limits).await?;
    assert_eq!(with_tenant(&db, "acme", |tenant| tenant.conflicts.len()), 1);
    resolve_all(&db);
    let again = reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "bob")]), &truth, &limits).await?;
    assert_eq!(again.refused_conflicts.len(), 0);
    assert_eq!(with_tenant(&db, "acme", |tenant| tenant.conflicts.len()), TWICE);
    let repeated = reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "bob")]), &truth, &limits).await?;
    assert_eq!(repeated.refused_conflicts.len(), 0);
    assert_eq!(with_tenant(&db, "acme", |tenant| tenant.conflicts.len()), TWICE);
    Ok(())
}


#[tokio::test]
async fn open_conflicts_are_capped_per_asset_and_the_refusal_is_counted() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let truth = TruthMap::new();
    let limits = Limits {
        max_open_conflicts: TWICE,
        ..Limits::default()
    };
    reconcile_stored(&exec, &scope, &observation("agent", "S1", &[("owner", "ann")]), &truth, &limits).await?;
    let at_bound_one = reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "bob")]), &truth, &limits).await?;
    let at_bound_two = reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "cat")]), &truth, &limits).await?;
    assert!(at_bound_one.refused_conflicts.is_empty() && at_bound_two.refused_conflicts.is_empty());
    let before = version_of(&db, "serial_number:S1");
    let over = reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "dan")]), &truth, &limits).await?;
    assert_eq!((over.outcome.conflicts.len(), over.refused_conflicts.len()), (0, 1));
    assert_eq!(with_tenant(&db, "acme", |tenant| tenant.conflicts.len()), TWICE);
    assert_eq!(version_of(&db, "serial_number:S1"), before);
    resolve_all(&db);
    let after_resolution = reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "dan")]), &truth, &limits).await?;
    assert_eq!(after_resolution.refused_conflicts.len(), 0);
    assert_eq!(with_tenant(&db, "acme", |tenant| tenant.conflicts.len()), TWICE + 1);
    Ok(())
}


#[tokio::test]
async fn the_cap_of_one_tenant_never_counts_another_tenants_conflicts() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let truth = TruthMap::new();
    let limits = Limits {
        max_open_conflicts: 1,
        ..Limits::default()
    };
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    reconcile_stored(&exec, &acme, &observation("agent", "S1", &[("owner", "ann")]), &truth, &limits).await?;
    reconcile_stored(&exec, &acme, &observation("hr", "S1", &[("owner", "bob")]), &truth, &limits).await?;
    reconcile_stored(&exec, &other, &observation("agent", "S1", &[("owner", "ann")]), &truth, &limits).await?;
    let result = reconcile_stored(&exec, &other, &observation("hr", "S1", &[("owner", "bob")]), &truth, &limits).await?;
    assert_eq!(result.refused_conflicts.len(), 0);
    Ok(())
}


pub async fn apply_answer(rows: Vec<Row>) -> Result<Vec<RefusedConflict>, StoreError> {
    let exec = move |_: TenantScope, _: &'static str, _: Vec<String>| -> RowFuture<'static> { Box::pin(ready(Ok(rows.clone()))) };
    let scope = tenant_scope("acme")?;
    let snapshot = cmdb::model::Snapshot {
        assets: Vec::new(),
        versions: cmdb::types::VersionMap::new(),
    };
    let outcome = cmdb::model::Outcome {
        inventory: Vec::new(),
        conflicts: Vec::new(),
        events: Vec::new(),
    };
    apply_outcome(&exec, &scope, &snapshot, &outcome, 1).await
}


#[tokio::test]
async fn a_malformed_apply_answer_is_refused() -> TestResult {
    assert!(matches!(apply_answer(Vec::new()).await, Err(StoreError::BadRow { .. })));
    assert!(matches!(apply_answer(vec![Vec::new()]).await, Err(StoreError::BadRow { .. })));
    assert!(matches!(
        apply_answer(vec![vec!["true".to_owned()]]).await,
        Err(StoreError::BadRow { .. })
    ));
    assert!(matches!(
        apply_answer(vec![vec!["true".to_owned(), "many".to_owned()]]).await,
        Err(StoreError::BadRefused(_))
    ));
    assert!(matches!(
        apply_answer(vec![vec!["false".to_owned(), "[]".to_owned()]]).await,
        Err(StoreError::VersionConflict)
    ));
    let listed = apply_answer(vec![vec![
        "true".to_owned(),
        r#"[{"asset":"a","attribute":"owner","observed_source":"hr"}]"#.to_owned(),
    ]])
    .await?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed.first().map(|refused| refused.attribute.as_str()), Some("owner"));
    Ok(())
}


#[test]
fn the_conflict_status_migration_adds_the_status_and_the_duplicate_index() -> TestResult {
    let sql = MIGRATIONS.get(1).ok_or("no second migration")?.sql;
    assert!(sql.contains("status IN ('open', 'resolved')"));
    assert!(sql.contains("ON cmdb_conflicts (tenant, asset, attribute)"));
    assert!(APPLY_SQL.contains("o.status = 'open'"));
    Ok(())
}


#[tokio::test]
async fn an_overwrite_by_the_source_of_truth_at_the_cap_still_records_its_conflict() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits {
        max_open_conflicts: 1,
        ..Limits::default()
    };
    let truth = TruthMap::from([("owner".to_owned(), "hr".to_owned())]);
    reconcile_stored(
        &exec,
        &scope,
        &observation("agent", "S1", &[("owner", "ann"), ("rack", "r1")]),
        &truth,
        &limits,
    )
    .await?;
    let filled = reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("rack", "r2")]), &truth, &limits).await?;
    assert_eq!(filled.outcome.conflicts.len(), 1);
    let third = reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "eve")]), &truth, &limits).await?;
    assert!(third.refused_conflicts.is_empty(), "{third:?}");
    assert_eq!(third.outcome.conflicts.len(), 1);
    assert_eq!(with_tenant(&db, "acme", |tenant| tenant.conflicts.len()), TWICE);
    Ok(())
}


#[tokio::test]
async fn a_key_conflict_is_never_refused_by_the_cap() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits {
        max_open_conflicts: 1,
        ..Limits::default()
    };
    let truth = TruthMap::new();
    reconcile_stored(&exec, &scope, &observation("agent", "S1", &[("owner", "ann")]), &truth, &limits).await?;
    reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "bob")]), &truth, &limits).await?;
    reconcile_stored(&exec, &scope, &observation("agent", "S2", &[]), &truth, &limits).await?;
    let swapped = reconcile_stored(&exec, &scope, &nic_swap("agent", "S1", "m1"), &truth, &limits).await?;
    assert!(swapped.refused_conflicts.is_empty());
    let taken = reconcile_stored(&exec, &scope, &nic_swap("agent", "S2", "m1"), &truth, &limits).await?;
    assert!(taken.refused_conflicts.is_empty());
    assert!(with_tenant(&db, "acme", |tenant| tenant.conflicts.iter().any(|conflict| memory::text(
        conflict,
        "attribute"
    )
    .starts_with("key:"))));
    Ok(())
}


#[tokio::test]
async fn one_source_at_its_cap_does_not_block_another_and_refusals_are_listed() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let limits = Limits {
        max_open_conflicts: 1,
        ..Limits::default()
    };
    let truth = TruthMap::new();
    reconcile_stored(&exec, &scope, &observation("agent", "S1", &[("owner", "ann")]), &truth, &limits).await?;
    reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "bob")]), &truth, &limits).await?;
    let blocked = reconcile_stored(&exec, &scope, &observation("hr", "S1", &[("owner", "cat")]), &truth, &limits).await?;
    assert_eq!(
        blocked.refused_conflicts,
        vec![RefusedConflict {
            asset: "serial_number:S1".to_owned(),
            attribute: "owner".to_owned(),
            observed_source: "hr".to_owned(),
        }]
    );
    assert!(blocked.outcome.conflicts.is_empty());
    let other = reconcile_stored(&exec, &scope, &observation("cmms", "S1", &[("owner", "dan")]), &truth, &limits).await?;
    assert!(other.refused_conflicts.is_empty());
    assert_eq!(other.outcome.conflicts.len(), 1);
    assert_eq!(with_tenant(&db, "acme", |tenant| tenant.conflicts.len()), TWICE);
    Ok(())
}


fn conflict_of_source(asset: &str, attribute: &str, source: &str, resolution: Resolution) -> Conflict {
    let side = |value: &str, from: &str| Attribute {
        value: value.to_owned(),
        source: from.to_owned(),
    };
    Conflict {
        asset: asset.to_owned(),
        attribute: attribute.to_owned(),
        current: side("x", "agent"),
        observed: side("y", source),
        resolution,
    }
}


#[test]
fn a_refused_conflict_is_matched_on_asset_attribute_and_source_together() -> TestResult {
    let kept = [
        conflict_of_source("a2", "owner", "hr", Resolution::Undecided),
        conflict_of_source("a1", "rack", "hr", Resolution::Undecided),
        conflict_of_source("a1", "owner", "cmms", Resolution::Undecided),
    ];
    let gone = conflict_of_source("a1", "owner", "hr", Resolution::Undecided);
    let outcome = Outcome {
        inventory: Vec::new(),
        conflicts: kept.iter().cloned().chain([gone]).collect(),
        events: Vec::new(),
    };
    let refused = [RefusedConflict {
        asset: "a1".to_owned(),
        attribute: "owner".to_owned(),
        observed_source: "hr".to_owned(),
    }];
    assert_eq!(without_refused(outcome, &refused).conflicts, kept);
    Ok(())
}


#[test]
fn only_a_took_observed_or_key_conflict_is_exempt() -> TestResult {
    assert!(is_exempt(&conflict_of_source("a", "owner", "hr", Resolution::TookObserved)));
    assert!(is_exempt(&conflict_of_source("a", "key:mac", "hr", Resolution::Undecided)));
    assert!(!is_exempt(&conflict_of_source("a", "owner", "hr", Resolution::KeptCurrent)));
    Ok(())
}
