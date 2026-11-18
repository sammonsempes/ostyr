#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/memory.rs"]
mod memory;
#[path = "common/types.rs"]
mod types;


use cmdb::model::{AssetKind, IdentityKey, Limits};
use cmdb::store::{ASSETS_TABLE, ATTEMPT_CEILING, ATTRIBUTES_TABLE, KEYS_TABLE};
use cmdb::types::{RowFuture, TruthMap};
use core_pg::scope::TenantScope;
use fixtures::{list, node, pod, set, uid};
use k8s_inventory::cmdb_sync::{
    blocked_cap, cap_label, cloud_id, node_observation, observations, pod_observation, refused_page, source_of, sync, Room, SyncReport,
    PAGE_OBSERVATIONS,
};
use k8s_inventory::error::SyncError;
use k8s_inventory::inventory::{build_inventory, Inventory};
use k8s_inventory::limits::Limits as ParseLimits;
use k8s_inventory::model::{NodeItem, PodItem};
use k8s_inventory::parse::{parse_nodes, parse_pods};
use k8s_inventory::settings::FetchSettings;
use memory::{handle, lock, Db, Forced};
use serde_json::Value;
use std::future::ready;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use tracing::Dispatch;
use types::TestResult;


const TWO: usize = 2;


const THREE: usize = 3;


const FIVE: usize = 5;


const TEN: usize = 10;


const ATTEMPTS: usize = 3;


const TIMEOUT_MS: u64 = 5_000;


const BIG_BYTES: usize = 65_536;


const MANY_PODS: usize = 250;


const ROOM_CAP: usize = 50;


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


struct Capture(Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        lock(&self.0).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn executor<'a>(db: &'a Db) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(handle(db, &scope, sql, &params))) }
}


fn settings(tenant: &str, cluster: &str) -> FetchSettings {
    FetchSettings {
        api_url: "https://k8s.lab:6443".to_owned(),
        ca_file: PathBuf::from("ca.pem"),
        token_file: PathBuf::from("token"),
        tenant: tenant.to_owned(),
        cluster: cluster.to_owned(),
        timeout_ms: TIMEOUT_MS,
        page_size: None,
        max_bytes: None,
        max_run_bytes: None,
        max_pages: None,
        max_total_items: None,
        max_namespaces: None,
    }
}


fn inventory_for(tenant: &str, cluster: &str, pods: Vec<Value>, nodes: Vec<Value>) -> Result<Inventory, Box<dyn std::error::Error>> {
    let limits = ParseLimits::default();
    Ok(build_inventory(
        tenant,
        cluster,
        parse_pods(list("PodList", pods).as_slice(), &limits)?,
        parse_nodes(list("NodeList", nodes).as_slice(), &limits)?,
    )?)
}


fn three() -> Result<Inventory, Box<dyn std::error::Error>> {
    inventory_for("a", "prod-1", vec![pod("web-1", "p1"), pod("web-2", "p2")], vec![node("node-a", "n1")])
}


fn many(count: usize) -> Result<Inventory, Box<dyn std::error::Error>> {
    let pods = (0..count).map(|i| pod("web", &format!("many-{i}"))).collect();
    inventory_for("a", "prod-1", pods, Vec::new())
}


fn pod_item() -> Result<PodItem, Box<dyn std::error::Error>> {
    let parsed = parse_pods(list("PodList", vec![pod("web-1", "p1")]).as_slice(), &ParseLimits::default())?;
    Ok(parsed.items.first().ok_or("no pod")?.clone())
}


fn node_item() -> Result<NodeItem, Box<dyn std::error::Error>> {
    let parsed = parse_nodes(list("NodeList", vec![node("node-a", "n1")]).as_slice(), &ParseLimits::default())?;
    Ok(parsed.items.first().ok_or("no node")?.clone())
}


fn seed(db: &Db, id: &str, key: (&str, &str)) {
    let mut tenants = lock(&db.tenants);
    let tenant = tenants.entry("a".to_owned()).or_default();
    tenant
        .assets
        .insert(id.to_owned(), ("virtual_machine".to_owned(), "in_service".to_owned(), 1));
    tenant.keys.insert((key.0.to_owned(), key.1.to_owned()), id.to_owned());
}


fn capped(assets: usize) -> Limits {
    Limits {
        max_assets: assets,
        ..Limits::default()
    }
}


fn child_capped(rows: usize) -> Limits {
    Limits {
        max_child_rows: rows,
        ..Limits::default()
    }
}


fn stored_ids(db: &Db) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(lock(&db.tenants).get("a").ok_or("no tenant a")?.assets.keys().cloned().collect())
}


async fn run_logged(inventory: &Inventory, limits: &Limits) -> Result<(SyncReport, String), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = buffer.clone();
    let guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Capture(writer.clone()))
            .finish(),
    );
    let db = Db::default();
    let exec = executor(&db);
    let report = sync(&exec, &settings("a", "prod-1"), inventory, &TruthMap::new(), limits).await?;
    drop(guard);
    let logged = String::from_utf8(lock(&buffer).clone())?;
    Ok((report, logged))
}


#[test]
fn a_node_and_two_pods_map_to_kinds_ids_and_attributes() -> TestResult {
    let inventory = three()?;
    let nodes = k8s_inventory::inventory::inventory_nodes(&inventory);
    let pods = k8s_inventory::inventory::inventory_pods(&inventory);
    let (found, counters) = observations("prod-1", nodes, pods);
    assert_eq!((counters.observed, counters.refused), (THREE, 0));
    let kinds: Vec<AssetKind> = found.iter().map(|one| one.kind).collect();
    assert_eq!(kinds, vec![AssetKind::Server, AssetKind::Container, AssetKind::Container]);
    let first = found.first().ok_or("no observation")?;
    assert_eq!(first.keys.get(&IdentityKey::CloudId), Some(&format!("k8s:prod-1:node:{}", uid("n1"))));
    assert_eq!(first.source, "k8s:prod-1");
    assert_eq!(source_of("prod-1"), "k8s:prod-1");
    let attribute = |name: &str| first.attributes.get(name).map(String::as_str);
    assert_eq!(attribute("k8s.name"), Some("node-a"));
    assert_eq!(attribute("k8s.internal_ip"), Some("10.0.0.5"));
    assert_eq!(attribute("k8s.kubelet_version"), Some("v1.30.2+k3s1"));
    assert_eq!(attribute("k8s.os_image"), Some("Ubuntu 24.04 LTS"));
    let second = found.get(1).ok_or("no pod")?;
    let attribute_of = |name: &str| second.attributes.get(name).map(String::as_str);
    assert_eq!(attribute_of("k8s.namespace"), Some("default"));
    assert_eq!(attribute_of("k8s.node"), Some("node-a"));
    assert_eq!(attribute_of("k8s.phase"), Some("Running"));
    assert_eq!(attribute_of("k8s.owner_kind"), Some("ReplicaSet"));
    assert_eq!(attribute_of("k8s.owner_name"), Some("web-1"));
    assert!(second.attributes.keys().all(|name| !name.contains("label")));
    Ok(())
}


#[test]
fn a_refused_pod_gives_no_observation() -> TestResult {
    let mut bad = pod_item()?;
    bad.uid = "not-a-uid".to_owned();
    let (found, counters) = observations("prod-1", &[], &[bad.clone()]);
    assert_eq!((found.len(), counters.refused), (0, 1));
    assert!(pod_observation("prod-1", &bad).is_err_and(|error| error.to_string().contains("uid")));
    let (none, refused) = observations("bad cluster", &[node_item()?], &[pod_item()?]);
    assert_eq!((none.len(), refused.refused), (0, TWO));
    assert!(cloud_id("-x", "pod", &uid("p1")).is_err_and(|error| error.to_string().starts_with("invalid cluster id")));
    Ok(())
}


#[test]
fn hostile_owner_text_is_refused_by_the_cmdb_check_alone() -> TestResult {
    let mut escape = pod_item()?;
    escape.owner_name = Some("bad\u{1b}[31mname".to_owned());
    let mut big = pod_item()?;
    big.owner_name = Some("a".repeat(BIG_BYTES));
    let mut node_bad = node_item()?;
    node_bad.os_image = Some("x\u{1b}y".to_owned());
    assert!(pod_observation("prod-1", &escape).is_err_and(|error| error.to_string().starts_with("cmdb store")));
    assert!(pod_observation("prod-1", &big).is_err());
    assert!(node_observation("prod-1", &node_bad).is_err());
    assert!(node_observation("prod-1", &node_item()?).is_ok());
    let (found, counters) = observations("prod-1", &[node_bad], &[escape, big, pod_item()?]);
    assert_eq!((found.len(), counters.refused), (1, THREE));
    Ok(())
}


#[test]
fn a_node_without_optional_fields_has_only_its_name() -> TestResult {
    let mut bare = node_item()?;
    bare.addresses.clear();
    bare.kubelet_version = None;
    bare.os_image = None;
    let found = node_observation("prod-1", &bare)?;
    assert_eq!(found.attributes.len(), 1);
    Ok(())
}


#[tokio::test]
async fn the_first_run_creates_and_the_rerun_is_unchanged() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let truth = TruthMap::new();
    let first = sync(&exec, &settings("a", "prod-1"), &three()?, &truth, &Limits::default()).await?;
    assert_eq!((first.created, first.updated, first.unchanged, first.skipped), (THREE, 0, 0, 0));
    let second = sync(&exec, &settings("a", "prod-1"), &three()?, &truth, &Limits::default()).await?;
    assert_eq!((second.created, second.updated, second.unchanged), (0, 0, THREE));
    assert_eq!(lock(&db.tenants).get("a").ok_or("no tenant a")?.assets.len(), THREE);
    let mut moved = pod("web-1", "p1");
    set(&mut moved, "/status/phase", Value::String("Failed".to_owned()))?;
    let changed = inventory_for("a", "prod-1", vec![moved, pod("web-2", "p2")], vec![node("node-a", "n1")])?;
    let third = sync(&exec, &settings("a", "prod-1"), &changed, &truth, &Limits::default()).await?;
    assert_eq!((third.created, third.updated, third.unchanged), (0, 1, TWO));
    Ok(())
}


#[tokio::test]
async fn skipped_elements_are_counted_and_never_written() -> TestResult {
    let mut bad = pod("bad", "p3");
    set(&mut bad, "/metadata/uid", Value::String("NOT-A-UID".to_owned()))?;
    let inventory = inventory_for("a", "prod-1", vec![pod("web-1", "p1"), bad], Vec::new())?;
    let db = Db::default();
    let exec = executor(&db);
    let report = sync(&exec, &settings("a", "prod-1"), &inventory, &TruthMap::new(), &Limits::default()).await?;
    assert_eq!((report.created, report.skipped), (1, 1));
    Ok(())
}


#[tokio::test]
async fn two_tenants_with_the_same_cluster_and_uids_get_separate_assets() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let other = inventory_for("b", "prod-1", vec![pod("web-1", "p1"), pod("web-2", "p2")], vec![node("node-a", "n1")])?;
    sync(&exec, &settings("a", "prod-1"), &three()?, &TruthMap::new(), &Limits::default()).await?;
    let second = sync(&exec, &settings("b", "prod-1"), &other, &TruthMap::new(), &Limits::default()).await?;
    assert_eq!(second.created, THREE);
    let tenants = lock(&db.tenants);
    assert_eq!(tenants.get("a").ok_or("no a")?.assets.len(), THREE);
    assert_eq!(tenants.get("b").ok_or("no b")?.assets.len(), THREE);
    Ok(())
}


#[tokio::test]
async fn an_inventory_of_another_tenant_or_cluster_is_refused_before_any_io() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let tenant = sync(&exec, &settings("b", "prod-1"), &three()?, &TruthMap::new(), &Limits::default()).await;
    let cluster = sync(&exec, &settings("a", "prod-2"), &three()?, &TruthMap::new(), &Limits::default()).await;
    let bad_tenant = sync(&exec, &settings("-x", "prod-1"), &three()?, &TruthMap::new(), &Limits::default()).await;
    let bad_cluster = sync(&exec, &settings("a", "-x"), &three()?, &TruthMap::new(), &Limits::default()).await;
    assert!(matches!(tenant, Err(SyncError::ScopeMismatch)));
    assert!(matches!(cluster, Err(SyncError::ScopeMismatch)));
    assert!(bad_tenant.is_err_and(|error| error.to_string().starts_with("invalid tenant")));
    assert!(bad_cluster.is_err_and(|error| error.to_string().starts_with("invalid cluster id")));
    assert!(lock(&db.reads).is_empty());
    Ok(())
}


#[tokio::test]
async fn only_the_settings_tenant_is_read_or_written() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    sync(&exec, &settings("a", "prod-1"), &three()?, &TruthMap::new(), &Limits::default()).await?;
    assert!(lock(&db.reads).iter().all(|(tenant, _)| tenant == "a"));
    assert!(!lock(&db.tenants).contains_key("b"));
    Ok(())
}


#[tokio::test]
async fn an_asset_of_the_same_name_from_another_source_is_never_merged() -> TestResult {
    let db = Db::default();
    seed(&db, "name:web-1", ("name", "web-1"));
    let exec = executor(&db);
    let report = sync(&exec, &settings("a", "prod-1"), &three()?, &TruthMap::new(), &Limits::default()).await?;
    assert_eq!(report.created, THREE);
    assert_eq!(stored_ids(&db)?.len(), THREE + 1);
    Ok(())
}


#[tokio::test]
async fn a_derived_id_owned_by_another_asset_is_refused_alone() -> TestResult {
    let db = Db::default();
    seed(&db, &format!("cloud_id:k8s:prod-1:pod:{}", uid("p1")), ("name", "x"));
    let exec = executor(&db);
    let report = sync(&exec, &settings("a", "prod-1"), &three()?, &TruthMap::new(), &Limits::default()).await?;
    assert_eq!((report.created, report.skipped, report.unchanged), (TWO, 1, 0));
    Ok(())
}


#[tokio::test]
async fn a_version_conflict_is_retried_then_reported_after_the_cap() -> TestResult {
    let db = Db::default();
    lock(&db.forced).extend([Forced::Stale, Forced::UniqueViolation]);
    let exec = executor(&db);
    let retried = sync(&exec, &settings("a", "prod-1"), &three()?, &TruthMap::new(), &Limits::default()).await?;
    assert_eq!((retried.created, retried.unapplied), (THREE, 0));
    let other = Db::default();
    lock(&other.forced).extend([Forced::Stale; ATTEMPTS]);
    let exec_other = executor(&other);
    let exhausted = sync(&exec_other, &settings("a", "prod-1"), &three()?, &TruthMap::new(), &Limits::default()).await?;
    assert_eq!((exhausted.created, exhausted.unapplied, exhausted.unchanged), (0, THREE, 0));
    assert_eq!(*lock(&other.apply_calls), ATTEMPTS);
    Ok(())
}


#[tokio::test]
async fn the_attempt_ceiling_binds_whatever_the_configured_cap() -> TestResult {
    let db = Db::default();
    lock(&db.forced).extend([Forced::Stale; ATTEMPT_CEILING + 1]);
    let exec = executor(&db);
    let limits = Limits {
        max_attempts: ATTEMPT_CEILING + 1,
        ..Limits::default()
    };
    let report = sync(&exec, &settings("a", "prod-1"), &three()?, &TruthMap::new(), &limits).await?;
    assert_eq!(report.unapplied, THREE);
    assert_eq!(*lock(&db.apply_calls), ATTEMPT_CEILING);
    Ok(())
}


#[tokio::test]
async fn another_store_error_stops_the_run() -> TestResult {
    let db = Db::default();
    lock(&db.forced).push_back(Forced::OtherError);
    let exec = executor(&db);
    let failed = sync(&exec, &settings("a", "prod-1"), &three()?, &TruthMap::new(), &Limits::default()).await;
    assert!(matches!(failed, Err(SyncError::Store(_))));
    Ok(())
}


#[tokio::test]
async fn a_large_inventory_is_applied_in_pages() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let report = sync(&exec, &settings("a", "prod-1"), &many(MANY_PODS)?, &TruthMap::new(), &Limits::default()).await?;
    assert_eq!(report.created, MANY_PODS);
    assert_eq!(*lock(&db.apply_calls), MANY_PODS.div_ceil(PAGE_OBSERVATIONS));
    Ok(())
}


#[tokio::test]
async fn ten_pods_under_a_small_asset_cap_are_bounded_loud_and_name_the_table() -> TestResult {
    let (report, logged) = run_logged(&many(TEN)?, &capped(FIVE)).await?;
    assert_eq!((report.created, report.refused_no_room, report.cap), (FIVE, FIVE, Some(ASSETS_TABLE)));
    assert_eq!(logged.matches("tenant at the asset cap").count(), 1);
    assert!(logged.contains("5 creations and 0 updates refused, inventory incomplete"));
    let (big, big_logged) = run_logged(&many(MANY_PODS)?, &capped(ROOM_CAP)).await?;
    assert_eq!((big.created, big.refused_no_room), (ROOM_CAP, MANY_PODS - ROOM_CAP));
    assert_eq!(big_logged.matches("inventory incomplete").count(), 1);
    Ok(())
}


#[tokio::test]
async fn a_run_with_room_for_everything_does_not_warn() -> TestResult {
    let (report, logged) = run_logged(&three()?, &Limits::default()).await?;
    assert_eq!(report.created, THREE);
    assert!(logged.is_empty());
    Ok(())
}


#[tokio::test]
async fn skipped_elements_warn_once() -> TestResult {
    let mut bad = pod("bad", "p3");
    set(&mut bad, "/metadata/uid", Value::String("NOT-A-UID".to_owned()))?;
    let inventory = inventory_for("a", "prod-1", vec![pod("web-1", "p1"), bad], Vec::new())?;
    let (_, logged) = run_logged(&inventory, &Limits::default()).await?;
    assert!(logged.contains("1 elements skipped"));
    Ok(())
}


#[tokio::test]
async fn the_warning_names_the_key_and_attribute_row_caps() -> TestResult {
    let (keys, keys_logged) = run_logged(&three()?, &child_capped(0)).await?;
    assert_eq!((keys.created, keys.refused_no_room, keys.cap), (0, THREE, Some(KEYS_TABLE)));
    assert!(keys_logged.contains("tenant at the identity key row cap"));
    let (rows, rows_logged) = run_logged(&three()?, &child_capped(1)).await?;
    assert_eq!(rows.created, 0);
    assert!(rows_logged.contains("tenant at the"));
    Ok(())
}


#[tokio::test]
async fn a_tenant_at_the_cap_gets_no_creation_but_its_updates() -> TestResult {
    let db = Db::default();
    seed(
        &db,
        &format!("cloud_id:k8s:prod-1:node:{}", uid("n1")),
        ("cloud_id", &format!("k8s:prod-1:node:{}", uid("n1"))),
    );
    seed(&db, "name:other", ("name", "other"));
    let exec = executor(&db);
    let report = sync(&exec, &settings("a", "prod-1"), &three()?, &TruthMap::new(), &capped(TWO)).await?;
    assert_eq!((report.created, report.updated, report.refused_no_room), (0, 1, TWO));
    assert_eq!(stored_ids(&db)?.len(), TWO);
    Ok(())
}


#[tokio::test]
async fn a_cap_reached_at_commit_after_the_snapshot_is_counted_by_table() -> TestResult {
    let db = Db::default();
    let raced = Mutex::new(false);
    let exec = |scope: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> {
        let first_apply = sql == cmdb::store::APPLY_SQL && !std::mem::replace(&mut *lock(&raced), true);
        if first_apply {
            seed(&db, "name:x", ("name", "x"));
            seed(&db, "name:y", ("name", "y"));
        }
        Box::pin(ready(handle(&db, &scope, sql, &params)))
    };
    let report = sync(&exec, &settings("a", "prod-1"), &three()?, &TruthMap::new(), &capped(TWO)).await?;
    assert_eq!((report.created, report.refused_no_room, report.refused_attribute_room), (0, THREE, 0));
    assert_eq!(report.cap, Some(ASSETS_TABLE));
    Ok(())
}


#[tokio::test]
async fn updates_that_still_pass_the_child_cap_are_counted_refused() -> TestResult {
    let db = Db::default();
    let id = format!("k8s:prod-1:pod:{}", uid("p1"));
    seed(&db, &format!("cloud_id:{id}"), ("cloud_id", &id));
    let exec = executor(&db);
    let one = inventory_for("a", "prod-1", vec![pod("web-1", "p1")], Vec::new())?;
    let report = sync(&exec, &settings("a", "prod-1"), &one, &TruthMap::new(), &child_capped(1)).await?;
    assert_eq!(
        (report.created, report.updated, report.refused_no_room, report.refused_attribute_room),
        (0, 0, 0, 1)
    );
    assert_eq!(report.cap, Some(ATTRIBUTES_TABLE));
    Ok(())
}


#[test]
fn caps_have_labels_and_refused_pages_count_by_table() -> TestResult {
    let assets = refused_page(ASSETS_TABLE, THREE);
    assert_eq!((assets.refused_no_room, assets.refused_attribute_room), (THREE, 0));
    let rows = refused_page(ATTRIBUTES_TABLE, THREE);
    assert_eq!((rows.refused_no_room, rows.refused_attribute_room), (0, THREE));
    let (found, _) = observations("prod-1", &[node_item()?], &[]);
    let one = found.first().ok_or("no observation")?;
    let full = Room {
        assets: 1,
        keys: 1,
        attributes: ROOM_CAP,
    };
    assert_eq!(blocked_cap(&Room { assets: 0, ..full }, one), ASSETS_TABLE);
    assert_eq!(blocked_cap(&Room { keys: 0, ..full }, one), KEYS_TABLE);
    assert_eq!(blocked_cap(&Room { attributes: 0, ..full }, one), ATTRIBUTES_TABLE);
    assert_eq!(
        [ASSETS_TABLE, KEYS_TABLE, ATTRIBUTES_TABLE].map(cap_label),
        ["asset", "identity key row", "attribute row"]
    );
    Ok(())
}
