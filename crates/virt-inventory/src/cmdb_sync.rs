use crate::error::SyncError;
use crate::model::{Parsed, Resource, ResourceKind};
use crate::settings::FetchSettings;
use cmdb::error::StoreError;
use cmdb::model::{Asset, AssetKind, Event, IdentityKey, Limits, Observation, Outcome};
use cmdb::reconcile::{check_observation, reconcile};
use cmdb::store::{apply_outcome, check_one_conflict_per_triple, load_assets, ATTEMPT_CEILING};
use cmdb::types::{Executor, KeyMap, ObservedMap, TruthMap};
use core_pg::scope::{tenant_scope, TenantScope};
use tracing::warn;


pub const SOURCE_PREFIX: &str = "virt-inventory:proxmox:";


pub const CLOUD_ID_PREFIX: &str = "proxmox:";


pub const PAGE_OBSERVATIONS: usize = 100;


pub const MAX_ID_PART_BYTES: usize = 128;


pub const ID_PUNCTUATION: &str = "._-";


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    pub observed: usize,
    pub storage_skipped: usize,
    pub refused: usize,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub counters: Counters,
    pub created: usize,
    pub updated: usize,
    pub conflicts: usize,
    pub refused_conflicts: usize,
    pub duplicate_conflicts: usize,
    pub refused_by_cmdb: usize,
    pub unapplied: usize,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageResult {
    pub created: usize,
    pub updated: usize,
    pub conflicts: usize,
    pub refused_conflicts: usize,
    pub duplicate_conflicts: usize,
    pub refused_by_cmdb: usize,
}


pub fn source_of(cluster: &str) -> String {
    format!("{SOURCE_PREFIX}{cluster}")
}


/// An ASCII allowlist: the part of a cloud id is never free text.
pub fn check_part(field: &'static str, text: &str) -> Result<(), SyncError> {
    let sound = !text.is_empty()
        && text.len() <= MAX_ID_PART_BYTES
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ID_PUNCTUATION.contains(character));
    sound.then_some(()).ok_or(SyncError::BadIdentity { field })
}


pub fn kind_text(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Qemu => "qemu",
        ResourceKind::Lxc => "lxc",
        ResourceKind::Node => "node",
        ResourceKind::Storage => "storage",
    }
}


pub fn asset_kind(kind: ResourceKind) -> AssetKind {
    match kind {
        ResourceKind::Qemu => AssetKind::VirtualMachine,
        ResourceKind::Lxc => AssetKind::Container,
        ResourceKind::Node | ResourceKind::Storage => AssetKind::Server,
    }
}


/// `proxmox:<cluster>/<kind>/<key>`: the cluster comes from the settings, the key from the grammar-checked parse.
pub fn cloud_id(cluster: &str, resource: &Resource) -> Result<String, SyncError> {
    check_part("cluster", cluster)?;
    check_part("key", &resource.key)?;
    Ok(format!("{CLOUD_ID_PREFIX}{cluster}/{}/{}", kind_text(resource.kind), resource.key))
}


pub fn attributes_of(resource: &Resource) -> ObservedMap {
    let optional = [
        ("virt.name", resource.name.clone()),
        ("virt.status", resource.status.clone()),
        ("virt.max_cpu", resource.max_cpu.map(|value| value.to_string())),
        ("virt.max_mem_bytes", resource.max_mem.map(|value| value.to_string())),
        ("virt.max_disk_bytes", resource.max_disk.map(|value| value.to_string())),
    ];
    optional
        .into_iter()
        .filter_map(|(name, value)| value.map(|text| (name.to_owned(), text)))
        .chain([
            ("virt.node".to_owned(), resource.node.clone()),
            ("virt.template".to_owned(), resource.template.to_string()),
        ])
        .collect()
}


/// The only key is the cloud id, never the name: a name is chosen by whoever administers the guest.
pub fn observation_of(cluster: &str, resource: &Resource) -> Result<Observation, SyncError> {
    let observation = Observation {
        source: source_of(cluster),
        kind: asset_kind(resource.kind),
        keys: KeyMap::from([(IdentityKey::CloudId, cloud_id(cluster, resource)?)]),
        attributes: attributes_of(resource),
    };
    check_observation(&observation).map_err(StoreError::from)?;
    Ok(observation)
}


/// Pure: storage is skipped, a resource whose identity or text is refused is skipped alone; both are counted.
pub fn observations(cluster: &str, items: &[Resource]) -> (Vec<Observation>, Counters) {
    let mut found = Vec::new();
    let mut counters = Counters::default();
    items.iter().for_each(|resource| {
        if resource.kind == ResourceKind::Storage {
            counters.storage_skipped += 1;
        } else if let Ok(observation) = observation_of(cluster, resource) {
            counters.observed += 1;
            found.push(observation);
        } else {
            counters.refused += 1;
        }
    });
    (found, counters)
}


/// Folds the page over the evolving inventory; an observation `reconcile` refuses is skipped alone and counted.
pub fn reconcile_page(assets: &[Asset], page: &[Observation], truth: &TruthMap) -> (Outcome, usize) {
    let start = Outcome {
        inventory: assets.to_vec(),
        conflicts: Vec::new(),
        events: Vec::new(),
    };
    page.iter().fold((start, 0), |(state, refused), observation| {
        match reconcile(&state.inventory, observation, truth) {
            Ok(next) => (
                Outcome {
                    inventory: next.inventory,
                    conflicts: [state.conflicts, next.conflicts].concat(),
                    events: [state.events, next.events].concat(),
                },
                refused,
            ),
            Err(_) => (state, refused + 1),
        }
    })
}


pub fn created_count(outcome: &Outcome) -> usize {
    outcome.events.iter().filter(|event| matches!(event, Event::Created { .. })).count()
}


pub fn updated_count(assets: &[Asset], outcome: &Outcome) -> usize {
    outcome
        .inventory
        .iter()
        .filter(|after| assets.iter().any(|before| before.id == after.id && before != *after))
        .count()
}


/// Loads the tenant's assets, reconciles the page, applies it in one statement; a stale version fails the whole page.
pub async fn try_page(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    page: &[Observation],
    truth: &TruthMap,
    limits: &Limits,
) -> Result<PageResult, StoreError> {
    let snapshot = load_assets(exec, scope, limits).await?;
    let (outcome, refused_by_cmdb) = reconcile_page(&snapshot.assets, page, truth);
    check_one_conflict_per_triple(&outcome)?;
    let applied = apply_outcome(exec, scope, &snapshot, &outcome, limits).await?;
    Ok(PageResult {
        created: created_count(&outcome),
        updated: updated_count(&snapshot.assets, &outcome),
        conflicts: outcome.conflicts.len(),
        refused_conflicts: applied.refused.len(),
        duplicate_conflicts: applied.duplicates.len(),
        refused_by_cmdb,
    })
}


/// A version conflict reloads and retries the page up to `limits.max_attempts` (and `ATTEMPT_CEILING`) times, then `RetriesExhausted`.
pub async fn apply_page(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    page: &[Observation],
    truth: &TruthMap,
    limits: &Limits,
) -> Result<PageResult, StoreError> {
    let mut attempts = 0;
    let mut result = Err(StoreError::VersionConflict);
    while matches!(result, Err(StoreError::VersionConflict)) && attempts < ATTEMPT_CEILING && attempts < limits.max_attempts {
        attempts += 1;
        result = try_page(exec, scope, page, truth, limits).await;
    }
    match result {
        Err(StoreError::VersionConflict) => Err(StoreError::RetriesExhausted { attempts }),
        other => other,
    }
}


pub fn add_page(report: &mut SyncReport, done: &PageResult) {
    report.created += done.created;
    report.updated += done.updated;
    report.conflicts += done.conflicts;
    report.refused_conflicts += done.refused_conflicts;
    report.duplicate_conflicts += done.duplicate_conflicts;
    report.refused_by_cmdb += done.refused_by_cmdb;
}


/// The scope comes from `settings.tenant` once per run, nothing in the Proxmox answer selects a tenant; assets are reloaded for each page, whose versions the previous page bumped.
pub async fn sync(
    exec: Executor<'_, '_>,
    settings: &FetchSettings,
    parsed: &Parsed,
    truth: &TruthMap,
    limits: &Limits,
) -> Result<SyncReport, SyncError> {
    let scope = tenant_scope(&settings.tenant).map_err(SyncError::Tenant)?;
    tenant_scope(&settings.cluster).map_err(SyncError::Cluster)?;
    let (found, counters) = observations(&settings.cluster, &parsed.items);
    let mut report = SyncReport {
        counters,
        ..SyncReport::default()
    };
    for page in found.chunks(PAGE_OBSERVATIONS) {
        match apply_page(exec, &scope, page, truth, limits).await {
            Ok(done) => add_page(&mut report, &done),
            Err(StoreError::RetriesExhausted { .. }) => report.unapplied += page.len(),
            Err(other) => Err(other)?,
        }
    }
    let unapplied = report.unapplied;
    let refused = report.counters.refused + report.refused_by_cmdb;
    if unapplied > 0 || refused > 0 {
        warn!("proxmox cmdb sync: {unapplied} observations unapplied, {refused} refused");
    }
    Ok(report)
}
