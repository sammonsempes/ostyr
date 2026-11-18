use crate::error::SyncError;
use crate::model::{Parsed, Resource, ResourceKind};
use crate::settings::FetchSettings;
use cmdb::error::StoreError;
use cmdb::model::{Asset, AssetKind, Event, IdentityKey, Limits, Observation, Outcome, Snapshot};
use cmdb::reconcile::{check_observation, reconcile};
use cmdb::store::{apply_outcome, check_one_conflict_per_triple, load_assets, ASSETS_TABLE, ATTEMPT_CEILING, ATTRIBUTES_TABLE, KEYS_TABLE};
use cmdb::types::{Executor, KeyMap, ObservedMap, TruthMap};
use core_pg::scope::{tenant_scope, TenantScope};
use std::collections::BTreeSet;
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
    pub refused_no_room: usize,
    pub refused_attribute_room: usize,
    pub cap: Option<&'static str>,
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
    pub refused_no_room: usize,
    pub refused_attribute_room: usize,
    pub cap: Option<&'static str>,
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


/// What the tenant's store caps leave for creations: assets, identity key rows, attribute rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Room {
    pub assets: usize,
    pub keys: usize,
    pub attributes: usize,
}


/// The caps are the ones `load_assets` enforces and `apply.sql` re-checks under the tenant lock; this is only the snapshot's view of them.
pub fn room_of(snapshot: &Snapshot, limits: &Limits) -> Room {
    let keys: usize = snapshot.assets.iter().map(|asset| asset.keys.len()).sum();
    let attributes: usize = snapshot.assets.iter().map(|asset| asset.attributes.len()).sum();
    Room {
        assets: limits.max_assets.saturating_sub(snapshot.assets.len()),
        keys: limits.max_child_rows.saturating_sub(keys),
        attributes: limits.max_child_rows.saturating_sub(attributes),
    }
}


/// Takes the cost of one creation (an asset, its keys, its attributes) from the room, or leaves the room alone and says no.
pub fn take_room(room: &mut Room, observation: &Observation) -> bool {
    let keys = observation.keys.len();
    let attributes = observation.attributes.len();
    let fits = room.assets >= 1 && room.keys >= keys && room.attributes >= attributes;
    if fits {
        room.assets -= 1;
        room.keys -= keys;
        room.attributes -= attributes;
    }
    fits
}


/// Reconcile state of one page: the evolving inventory plus what the page created, changed and refused.
#[derive(Debug, Clone)]
pub struct Folded {
    pub outcome: Outcome,
    pub refused: usize,
    pub no_room: usize,
    pub cap: Option<&'static str>,
    pub room: Room,
    pub created: BTreeSet<String>,
    pub changed: BTreeSet<String>,
}


/// The only assets `reconcile` can look at for this observation: those sharing a key value or holding the id it would derive.
pub fn relevant(inventory: &[Asset], observation: &Observation) -> Vec<Asset> {
    let derived = observation.keys.iter().next().map(|(key, value)| format!("{key}:{value}"));
    inventory
        .iter()
        .filter(|asset| {
            derived.as_deref() == Some(asset.id.as_str()) || observation.keys.iter().any(|(key, value)| asset.keys.get(key) == Some(value))
        })
        .cloned()
        .collect()
}


/// The store table whose cap a creation that does not fit runs into: assets, then identity keys, then attributes.
pub fn blocked_cap(room: &Room, observation: &Observation) -> &'static str {
    if room.assets < 1 {
        ASSETS_TABLE
    } else if room.keys < observation.keys.len() {
        KEYS_TABLE
    } else {
        ATTRIBUTES_TABLE
    }
}


/// The words the warning uses for a store table.
pub fn cap_label(table: &str) -> &'static str {
    match table {
        ASSETS_TABLE => "asset",
        KEYS_TABLE => "identity key row",
        _ => "attribute row",
    }
}


/// Replaces the asset with the same id in place, or appends it.
pub fn put_asset(inventory: &mut Vec<Asset>, asset: Asset) {
    match inventory.iter_mut().find(|existing| existing.id == asset.id) {
        Some(slot) => *slot = asset,
        None => inventory.push(asset),
    }
}


/// One observation against the evolving inventory: refused by `reconcile`, refused for lack of room (a creation the room cannot pay), or merged.
pub fn fold_one(folded: &mut Folded, observation: &Observation, truth: &TruthMap) {
    let subset = relevant(&folded.outcome.inventory, observation);
    match reconcile(&subset, observation, truth) {
        Err(_) => folded.refused += 1,
        Ok(next) if created_count(&next) > 0 && !take_room(&mut folded.room, observation) => {
            let blocked = blocked_cap(&folded.room, observation);
            folded.cap.get_or_insert(blocked);
            folded.no_room += 1;
        }
        Ok(next) => {
            let created = next
                .inventory
                .iter()
                .filter(|after| !subset.iter().any(|before| before.id == after.id))
                .map(|after| after.id.clone());
            let changed = next
                .inventory
                .iter()
                .filter(|after| !subset.contains(after))
                .map(|after| after.id.clone());
            folded.created.extend(created);
            folded.changed.extend(changed);
            folded.outcome.conflicts.extend(next.conflicts);
            folded.outcome.events.extend(next.events);
            next.inventory
                .into_iter()
                .for_each(|asset| put_asset(&mut folded.outcome.inventory, asset));
        }
    }
}


/// Folds the page over the evolving inventory; creations the `room` cannot pay are counted `no_room`.
pub fn reconcile_page(assets: &[Asset], page: &[Observation], truth: &TruthMap, room: Room) -> Folded {
    let mut folded = Folded {
        outcome: Outcome {
            inventory: assets.to_vec(),
            conflicts: Vec::new(),
            events: Vec::new(),
        },
        refused: 0,
        no_room: 0,
        cap: None,
        room,
        created: BTreeSet::new(),
        changed: BTreeSet::new(),
    };
    page.iter().for_each(|observation| fold_one(&mut folded, observation, truth));
    folded
}


pub fn created_count(outcome: &Outcome) -> usize {
    outcome.events.iter().filter(|event| matches!(event, Event::Created { .. })).count()
}


/// Loads the tenant's assets, reconciles the page, applies it in one statement; a stale version fails the whole page. Without `creations` the room is empty.
pub async fn try_page(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    page: &[Observation],
    truth: &TruthMap,
    limits: &Limits,
    creations: bool,
) -> Result<PageResult, StoreError> {
    let snapshot = load_assets(exec, scope, limits).await?;
    let room = if creations { room_of(&snapshot, limits) } else { Room::default() };
    let folded = reconcile_page(&snapshot.assets, page, truth, room);
    let outcome = &folded.outcome;
    check_one_conflict_per_triple(outcome)?;
    let applied = apply_outcome(exec, scope, &snapshot, outcome, limits).await?;
    let refused_conflicts = applied.refused.len();
    let duplicate_conflicts = applied.duplicates.len();
    Ok(PageResult {
        created: folded.created.len(),
        updated: folded.changed.difference(&folded.created).count(),
        conflicts: outcome.conflicts.len().saturating_sub(refused_conflicts + duplicate_conflicts),
        refused_conflicts,
        duplicate_conflicts,
        refused_by_cmdb: folded.refused,
        refused_no_room: folded.no_room,
        refused_attribute_room: 0,
        cap: folded.cap,
    })
}


/// A version conflict reloads and retries the page up to `limits.max_attempts` (and `ATTEMPT_CEILING`) times, then `RetriesExhausted`.
pub async fn apply_attempts(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    page: &[Observation],
    truth: &TruthMap,
    limits: &Limits,
    creations: bool,
) -> Result<PageResult, StoreError> {
    let mut attempts = 0;
    let mut result = Err(StoreError::VersionConflict);
    while matches!(result, Err(StoreError::VersionConflict)) && attempts < ATTEMPT_CEILING && attempts < limits.max_attempts {
        attempts += 1;
        result = try_page(exec, scope, page, truth, limits, creations).await;
    }
    match result {
        Err(StoreError::VersionConflict) => Err(StoreError::RetriesExhausted { attempts }),
        other => other,
    }
}


/// The store refused the page for a cap (a concurrent writer used the room): the page goes again without creations; if even that passes a cap, all of it is counted `no_room`.
pub async fn apply_page(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    page: &[Observation],
    truth: &TruthMap,
    limits: &Limits,
) -> Result<PageResult, StoreError> {
    match apply_attempts(exec, scope, page, truth, limits, true).await {
        Err(StoreError::CapReached { table: first }) => match apply_attempts(exec, scope, page, truth, limits, false).await {
            Err(StoreError::CapReached { table }) => Ok(refused_page(table, page.len())),
            other => other.map(|done| PageResult {
                cap: done.cap.or(Some(first)),
                ..done
            }),
        },
        other => other,
    }
}


/// A page the store refuses even without creations: an asset cap counts creations, a row cap counts updates.
pub fn refused_page(table: &'static str, rows: usize) -> PageResult {
    let assets = table == ASSETS_TABLE;
    PageResult {
        refused_no_room: if assets { rows } else { 0 },
        refused_attribute_room: if assets { 0 } else { rows },
        cap: Some(table),
        ..PageResult::default()
    }
}


pub fn add_page(report: &mut SyncReport, done: &PageResult) {
    report.created += done.created;
    report.updated += done.updated;
    report.conflicts += done.conflicts;
    report.refused_conflicts += done.refused_conflicts;
    report.duplicate_conflicts += done.duplicate_conflicts;
    report.refused_by_cmdb += done.refused_by_cmdb;
    report.refused_no_room += done.refused_no_room;
    report.refused_attribute_room += done.refused_attribute_room;
    report.cap = report.cap.or(done.cap);
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
    let (mut found, counters) = observations(&settings.cluster, &parsed.items);
    found.sort_by_key(|observation| observation.keys.get(&IdentityKey::CloudId).cloned());
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
    let no_room = report.refused_no_room;
    let no_row_room = report.refused_attribute_room;
    let refused_conflicts = report.refused_conflicts;
    let cap = cap_label(report.cap.unwrap_or(ASSETS_TABLE));
    if unapplied > 0 || refused > 0 {
        warn!("proxmox cmdb sync: {unapplied} observations unapplied, {refused} refused");
    }
    if no_room + no_row_room > 0 {
        warn!("proxmox cmdb sync: tenant at the {cap} cap, {no_room} creations and {no_row_room} updates refused, inventory incomplete");
    }
    if refused_conflicts > 0 {
        warn!("proxmox cmdb sync: {refused_conflicts} conflicts refused at the open conflict cap");
    }
    Ok(report)
}
