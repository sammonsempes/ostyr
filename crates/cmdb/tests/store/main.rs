mod memory;
mod types;


use cmdb::error::StoreError;
use cmdb::model::{Asset, AssetKind, IdentityKey, Limits, Observation};
use cmdb::store::{
    apply_outcome, attempt, conflict_of, event_doc, load_assets, read_table, reconcile_stored, resolution_text, APPLY_SQL, ASSETS_SQL, ASSETS_TABLE,
    ATTEMPT_CEILING, ATTRIBUTES_SQL, KEYS_SQL, MAX_PAGES, MIGRATIONS,
};
use cmdb::types::{Row, RowFuture, TruthMap};
use core_pg::error::PgError;
use core_pg::migrate::check_embedded;
use core_pg::scope::{tenant_scope, TenantScope};
use memory::{handle, lock, other_error, unique_violation, Db, Forced, Tenant};
use std::future::ready;
use types::TestResult;


const SMALL_PAGE: usize = 2;


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
    assert_eq!(first.events.len(), 1);
    let loaded = load_assets(&exec, &scope, &limits).await?;
    assert_eq!(loaded.assets.len(), 1);
    assert_eq!(loaded.versions.get("serial_number:SN1"), Some(&1));
    let second = reconcile_stored(&exec, &scope, &observation("agent", "SN1", &[("owner", "bob")]), &truth, &limits).await?;
    assert!(second.events.is_empty());
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
    assert_eq!(created.events.len(), 1);
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
    let result = apply_outcome(&exec, &scope, &snapshot, &outcome).await;
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
        ..Limits::default()
    };
    assert_eq!(load_assets(&exec, &scope, &paged).await?.assets.len(), FIVE);
    let capped = Limits {
        page_size: SMALL_PAGE,
        max_assets: THREE,
        ..Limits::default()
    };
    let error = load_assets(&exec, &scope, &capped).await.err().ok_or("accepted")?;
    assert!(
        matches!(error, StoreError::TooManyRows { table, limit } if table == "cmdb_assets" && limit == THREE),
        "{error}"
    );
    let exact = Limits {
        page_size: SMALL_PAGE,
        max_assets: FOUR,
        ..Limits::default()
    };
    seed_assets(&db, "exact", FOUR);
    assert_eq!(load_assets(&exec, &tenant_scope("exact")?, &exact).await?.assets.len(), FOUR);
    let rows = read_table(&exec, &scope, ASSETS_TABLE, ASSETS_SQL, 1, 0).await;
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
    assert!(matches!(orphan, Err(StoreError::BadRow { .. })), "{orphan:?}");
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
    assert!(matches!(attribute_orphan, Err(StoreError::BadRow { .. })), "{attribute_orphan:?}");
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
async fn a_server_that_never_ends_a_table_is_cut_at_the_page_ceiling() -> TestResult {
    let never_ending = endless();
    let scope = tenant_scope("acme")?;
    let rows = read_table(&never_ending, &scope, ASSETS_TABLE, ASSETS_SQL, 1, usize::MAX / TWICE).await?;
    assert_eq!(rows.len(), MAX_PAGES);
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
