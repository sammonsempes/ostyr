#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/memory.rs"]
mod memory;
#[path = "common/types.rs"]
mod types;


use cmdb::model::{AssetKind, IdentityKey, Limits};
use cmdb::store::ATTEMPT_CEILING;
use cmdb::types::{RowFuture, TruthMap};
use core_pg::scope::TenantScope;
use fixtures::{data, guest, node, set, storage};
use memory::{handle, lock, Db, Forced};
use serde_json::Value;
use std::future::ready;
use std::path::PathBuf;
use types::TestResult;
use virt_inventory::cmdb_sync::{
    asset_kind, cloud_id, kind_text, observation_of, observations, source_of, sync, MAX_ID_PART_BYTES, PAGE_OBSERVATIONS,
};
use virt_inventory::error::SyncError;
use virt_inventory::model::{Parsed, Resource, ResourceKind};
use virt_inventory::proxmox::parse_resources;
use virt_inventory::settings::FetchSettings;


const CPUS: u64 = 2;


const TWO: usize = 2;


const THREE: usize = 3;


const FOUR: usize = 4;


const FIVE: usize = 5;


const MAX_MEM_BYTES: u64 = 2_147_483_648;


const BIGGER_MEM_BYTES: u64 = 4_294_967_296;


const BIG_NAME_BYTES: usize = 65_536;


const MANY_GUESTS: usize = 250;


const FIRST_VMID: usize = 100;


const ATTEMPTS: usize = 3;


const TIMEOUT_MS: u64 = 5_000;


fn executor<'a>(db: &'a Db) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(handle(db, &scope, sql, &params))) }
}


fn settings(tenant: &str, cluster: &str) -> FetchSettings {
    FetchSettings {
        api_url: "https://pve.lab:8006".to_owned(),
        ca_file: PathBuf::from("ca.pem"),
        token_file: PathBuf::from("token"),
        tenant: tenant.to_owned(),
        cluster: cluster.to_owned(),
        timeout_ms: TIMEOUT_MS,
        limits: Default::default(),
    }
}


fn parsed_of(items: Vec<Value>) -> Result<Parsed, Box<dyn std::error::Error>> {
    Ok(parse_resources(data(items).as_slice(), &Default::default())?)
}


fn resource(kind: ResourceKind, key: &str, name: Option<&str>) -> Resource {
    Resource {
        kind,
        key: key.to_owned(),
        name: name.map(str::to_owned),
        node: "pve".to_owned(),
        status: Some("running".to_owned()),
        max_cpu: Some(CPUS),
        max_mem: Some(MAX_MEM_BYTES),
        max_disk: None,
        template: false,
    }
}


fn three() -> Result<Parsed, Box<dyn std::error::Error>> {
    parsed_of(vec![guest("qemu", "100", "web"), guest("lxc", "101", "ct"), node("pve")])
}


fn seed(db: &Db, id: &str, key: (&str, &str)) {
    let mut tenants = lock(&db.tenants);
    let tenant = tenants.entry("a".to_owned()).or_default();
    tenant
        .assets
        .insert(id.to_owned(), ("virtual_machine".to_owned(), "in_service".to_owned(), 1));
    tenant.keys.insert((key.0.to_owned(), key.1.to_owned()), id.to_owned());
}


#[test]
fn kinds_and_cloud_ids_are_mapped_and_storage_is_skipped() -> TestResult {
    let parsed = parsed_of(vec![
        guest("qemu", "100", "web"),
        guest("lxc", "101", "ct"),
        node("pve"),
        storage("pve", "local"),
    ])?;
    let (found, counters) = observations("pve-1", &parsed.items);
    let ids: Vec<(AssetKind, String)> = found
        .iter()
        .filter_map(|one| one.keys.get(&IdentityKey::CloudId).map(|id| (one.kind, id.clone())))
        .collect();
    assert_eq!(
        ids,
        vec![
            (AssetKind::VirtualMachine, "proxmox:pve-1/qemu/100".to_owned()),
            (AssetKind::Container, "proxmox:pve-1/lxc/101".to_owned()),
            (AssetKind::Server, "proxmox:pve-1/node/pve".to_owned()),
        ]
    );
    assert_eq!((counters.observed, counters.storage_skipped, counters.refused), (THREE, 1, 0));
    assert!(found
        .iter()
        .all(|one| one.keys.len() == 1 && one.source == "virt-inventory:proxmox:pve-1"));
    assert_eq!(source_of("pve-1"), "virt-inventory:proxmox:pve-1");
    Ok(())
}


#[test]
fn attributes_carry_the_template_flag_and_the_name_for_display() -> TestResult {
    let mut template = resource(ResourceKind::Qemu, "100", Some("web"));
    template.template = true;
    let found = observation_of("pve-1", &template)?;
    assert_eq!(found.attributes.get("virt.template").map(String::as_str), Some("true"));
    assert_eq!(found.attributes.get("virt.name").map(String::as_str), Some("web"));
    assert_eq!(found.attributes.get("virt.max_mem_bytes").map(String::as_str), Some("2147483648"));
    assert_eq!(found.attributes.get("virt.max_disk_bytes"), None);
    Ok(())
}


#[test]
fn two_clusters_give_distinct_ids_for_one_vmid() -> TestResult {
    let one = resource(ResourceKind::Qemu, "100", None);
    assert_ne!(cloud_id("pve-1", &one)?, cloud_id("pve-2", &one)?);
    Ok(())
}


#[test]
fn a_refused_resource_is_skipped_alone_and_counted() -> TestResult {
    let big = "a".repeat(BIG_NAME_BYTES);
    let items = vec![
        resource(ResourceKind::Qemu, "100", Some("ok")),
        resource(ResourceKind::Qemu, "101", Some("bad\u{1b}[31mname")),
        resource(ResourceKind::Qemu, "102", Some(&big)),
        resource(ResourceKind::Qemu, "103/../x", None),
        resource(ResourceKind::Qemu, "", None),
    ];
    let (found, counters) = observations("pve-1", &items);
    assert_eq!((found.len(), counters.observed, counters.refused), (1, 1, FOUR));
    let (none, refused) = observations("bad cluster", &items);
    assert_eq!((none.len(), refused.refused), (0, FIVE));
    Ok(())
}


#[test]
fn a_hostile_long_name_is_dropped_by_the_parse_and_the_guest_is_kept() -> TestResult {
    let big = "a".repeat(BIG_NAME_BYTES);
    let parsed = parsed_of(vec![guest("qemu", "100", &big)])?;
    let (found, counters) = observations("pve-1", &parsed.items);
    assert_eq!((found.len(), counters.observed), (1, 1));
    assert!(found.iter().all(|one| !one.attributes.contains_key("virt.name")));
    Ok(())
}


#[test]
fn storage_has_a_kind_text_and_an_asset_kind() -> TestResult {
    assert_eq!(kind_text(ResourceKind::Storage), "storage");
    assert_eq!(asset_kind(ResourceKind::Storage), AssetKind::Server);
    assert_eq!(kind_text(ResourceKind::Lxc), "lxc");
    Ok(())
}


#[tokio::test]
async fn the_first_run_creates_and_the_second_updates_without_duplicates() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let truth = TruthMap::new();
    let first = sync(&exec, &settings("a", "pve-1"), &three()?, &truth, &Limits::default()).await?;
    assert_eq!((first.created, first.updated, first.unapplied), (THREE, 0, 0));
    let mut changed = guest("qemu", "100", "web");
    set(&mut changed, "/maxmem", &BIGGER_MEM_BYTES.to_string())?;
    let parsed = parsed_of(vec![changed, guest("lxc", "101", "ct"), node("pve")])?;
    let second = sync(&exec, &settings("a", "pve-1"), &parsed, &truth, &Limits::default()).await?;
    assert_eq!((second.created, second.updated, second.conflicts), (0, 1, 0));
    let tenants = lock(&db.tenants);
    let tenant = tenants.get("a").ok_or("no tenant a")?;
    assert_eq!(tenant.assets.len(), THREE);
    let stored = tenant
        .attributes
        .get(&("cloud_id:proxmox:pve-1/qemu/100".to_owned(), "virt.max_mem_bytes".to_owned()));
    assert_eq!(stored.map(|found| found.0.as_str()), Some("4294967296"));
    Ok(())
}


#[tokio::test]
async fn an_asset_of_the_same_name_from_another_source_is_never_merged() -> TestResult {
    let db = Db::default();
    seed(&db, "name:web", ("name", "web"));
    let exec = executor(&db);
    let report = sync(&exec, &settings("a", "pve-1"), &three()?, &TruthMap::new(), &Limits::default()).await?;
    assert_eq!(report.created, THREE);
    let tenants = lock(&db.tenants);
    let tenant = tenants.get("a").ok_or("no tenant a")?;
    assert_eq!(tenant.assets.get("name:web").map(|found| found.2), Some(1));
    assert!(tenant.attributes.keys().all(|(asset, _)| asset != "name:web"));
    assert_eq!(tenant.assets.len(), FOUR);
    Ok(())
}


#[tokio::test]
async fn a_derived_id_owned_by_another_asset_is_refused_alone() -> TestResult {
    let db = Db::default();
    seed(&db, "cloud_id:proxmox:pve-1/qemu/100", ("name", "x"));
    let exec = executor(&db);
    let report = sync(&exec, &settings("a", "pve-1"), &three()?, &TruthMap::new(), &Limits::default()).await?;
    assert_eq!((report.created, report.refused_by_cmdb), (TWO, 1));
    Ok(())
}


#[tokio::test]
async fn a_version_conflict_is_retried_then_reported_after_the_cap() -> TestResult {
    let db = Db::default();
    lock(&db.forced).extend([Forced::Stale, Forced::UniqueViolation]);
    let exec = executor(&db);
    let retried = sync(&exec, &settings("a", "pve-1"), &three()?, &TruthMap::new(), &Limits::default()).await?;
    assert_eq!((retried.created, retried.unapplied), (THREE, 0));
    let other = Db::default();
    lock(&other.forced).extend([Forced::Stale; ATTEMPTS]);
    let exec_other = executor(&other);
    let exhausted = sync(&exec_other, &settings("a", "pve-1"), &three()?, &TruthMap::new(), &Limits::default()).await?;
    assert_eq!((exhausted.created, exhausted.unapplied), (0, THREE));
    assert_eq!(*lock(&other.apply_calls), ATTEMPTS);
    Ok(())
}


#[tokio::test]
async fn another_store_error_stops_the_run() -> TestResult {
    let db = Db::default();
    lock(&db.forced).push_back(Forced::OtherError);
    let exec = executor(&db);
    let failed = sync(&exec, &settings("a", "pve-1"), &three()?, &TruthMap::new(), &Limits::default()).await;
    assert!(matches!(failed, Err(SyncError::Store(_))));
    assert!(failed.is_err_and(|error| error.to_string().starts_with("cmdb store")));
    Ok(())
}


#[tokio::test]
async fn only_the_settings_tenant_is_read_or_written() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    sync(&exec, &settings("a", "pve-1"), &three()?, &TruthMap::new(), &Limits::default()).await?;
    assert!(lock(&db.reads).iter().all(|(tenant, _)| tenant == "a"));
    assert!(!lock(&db.tenants).contains_key("b"));
    Ok(())
}


#[tokio::test]
async fn a_bad_tenant_or_cluster_is_refused_before_any_io() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let tenant = sync(&exec, &settings("-x", "pve-1"), &three()?, &TruthMap::new(), &Limits::default()).await;
    let cluster = sync(&exec, &settings("a", "-x"), &three()?, &TruthMap::new(), &Limits::default()).await;
    assert!(tenant.is_err_and(|error| error.to_string().starts_with("invalid tenant")));
    assert!(cluster.is_err_and(|error| error.to_string().starts_with("invalid cluster id")));
    assert!(lock(&db.reads).is_empty());
    let identity = observation_of("pve-1", &resource(ResourceKind::Qemu, "a b", None));
    assert!(identity.is_err_and(|error| error.to_string().contains("key")));
    Ok(())
}


#[tokio::test]
async fn a_large_inventory_is_applied_in_pages() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let items: Vec<Value> = (FIRST_VMID..FIRST_VMID + MANY_GUESTS)
        .map(|vmid| guest("qemu", &vmid.to_string(), "g"))
        .collect();
    let report = sync(&exec, &settings("a", "pve-1"), &parsed_of(items)?, &TruthMap::new(), &Limits::default()).await?;
    assert_eq!(report.created, MANY_GUESTS);
    assert_eq!(*lock(&db.apply_calls), MANY_GUESTS.div_ceil(PAGE_OBSERVATIONS));
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
    let report = sync(&exec, &settings("a", "pve-1"), &three()?, &TruthMap::new(), &limits).await?;
    assert_eq!(report.unapplied, THREE);
    assert_eq!(*lock(&db.apply_calls), ATTEMPT_CEILING);
    Ok(())
}


#[test]
fn a_key_over_the_part_cap_is_refused() -> TestResult {
    let long = "a".repeat(MAX_ID_PART_BYTES + 1);
    assert!(cloud_id("pve-1", &resource(ResourceKind::Node, &long, None)).is_err());
    assert!(cloud_id("pve-1", &resource(ResourceKind::Node, &"a".repeat(MAX_ID_PART_BYTES), None)).is_ok());
    Ok(())
}
