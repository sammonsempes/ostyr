//! The bounded per-exporter template cache of NetFlow v9 and IPFIX (spec section 22).

use crate::flow_model::{FlowDrop, FlowLimits};
use crate::listen_settings::source_key;
use crate::template_model::{ExporterState, Template, TemplateCache, TemplateKey, MILLIS_PER_SECOND};
use crate::types::{LruIndex, SourceKeySet};
use std::net::IpAddr;
use std::sync::Arc;


const LRU_WINDOW: usize = 2;


pub fn exporter_bounds(exporter: IpAddr, domain: Option<u32>) -> (TemplateKey, TemplateKey) {
    let low = TemplateKey {
        exporter,
        domain: domain.unwrap_or(u32::MIN),
        template_id: u16::MIN,
    };
    let high = TemplateKey {
        exporter,
        domain: domain.unwrap_or(u32::MAX),
        template_id: u16::MAX,
    };
    (low, high)
}


pub fn age_limit_ms(limits: &FlowLimits) -> u64 {
    limits.max_template_age_seconds.saturating_mul(MILLIS_PER_SECOND)
}


pub fn is_expired(template: &Template, now_ms: u64, age_ms: u64) -> bool {
    now_ms.saturating_sub(template.refreshed_ms) > age_ms
}


pub fn remove_templates(cache: &mut TemplateCache, keys: &[TemplateKey]) -> usize {
    let removed: Vec<TemplateKey> = keys.iter().filter(|key| cache.templates.remove(key).is_some()).copied().collect();
    removed.iter().for_each(|key| release_slot(cache, key.exporter));
    removed.len()
}


pub fn release_slot(cache: &mut TemplateCache, exporter: IpAddr) {
    let remaining = cache.exporters.get_mut(&exporter).map(|state| {
        state.templates = state.templates.saturating_sub(1);
        state.templates
    });
    if remaining == Some(0) {
        drop_exporter(cache, exporter);
    }
}


/// The recency index an exporter belongs to: declared and undeclared exporters never share one, so eviction can prefer the undeclared.
pub fn lru_for(cache: &mut TemplateCache, exporter: IpAddr) -> &mut LruIndex {
    if is_declared(cache, exporter) {
        &mut cache.declared_lru
    } else {
        &mut cache.undeclared_lru
    }
}


pub fn add_exporter(cache: &mut TemplateCache, exporter: IpAddr) {
    cache.tick = cache.tick.saturating_add(1);
    let tick = cache.tick;
    cache.exporters.insert(
        exporter,
        ExporterState {
            last_used: tick,
            templates: 0,
        },
    );
    lru_for(cache, exporter).insert((tick, exporter));
    let count = cache.per_key.entry(source_key(exporter)).or_insert(0);
    *count = count.saturating_add(1);
}


pub fn drop_exporter(cache: &mut TemplateCache, exporter: IpAddr) {
    let removed = cache.exporters.remove(&exporter);
    removed.into_iter().for_each(|state| {
        lru_for(cache, exporter).remove(&(state.last_used, exporter));
        let key = source_key(exporter);
        let left = cache.per_key.get_mut(&key).map(|count| {
            *count = count.saturating_sub(1);
            *count
        });
        if left == Some(0) {
            cache.per_key.remove(&key);
        }
    });
}


/// Replaces the declared keys and rebuilds both recency indexes, since an exporter may change side.
pub fn set_declared(cache: &mut TemplateCache, declared: SourceKeySet) {
    cache.declared = declared;
    cache.undeclared_lru.clear();
    cache.declared_lru.clear();
    let entries: Vec<(IpAddr, u64)> = cache.exporters.iter().map(|(exporter, state)| (*exporter, state.last_used)).collect();
    entries.into_iter().for_each(|(exporter, last_used)| {
        lru_for(cache, exporter).insert((last_used, exporter));
    });
}


pub fn touch_exporter(cache: &mut TemplateCache, exporter: IpAddr) {
    cache.tick = cache.tick.saturating_add(1);
    let tick = cache.tick;
    let replaced = cache
        .exporters
        .get_mut(&exporter)
        .map(|state| std::mem::replace(&mut state.last_used, tick));
    replaced.into_iter().for_each(|old_tick| {
        let index = lru_for(cache, exporter);
        index.remove(&(old_tick, exporter));
        index.insert((tick, exporter));
    });
}


pub fn keys_in(cache: &TemplateCache, exporter: IpAddr, domain: Option<u32>) -> Vec<TemplateKey> {
    let (low, high) = exporter_bounds(exporter, domain);
    cache.templates.range(low..=high).map(|(key, _)| *key).collect()
}


pub fn withdraw_scope(cache: &mut TemplateCache, exporter: IpAddr, domain: u32) -> usize {
    let keys = keys_in(cache, exporter, Some(domain));
    remove_templates(cache, &keys)
}


pub fn withdraw_template(cache: &mut TemplateCache, key: &TemplateKey) -> usize {
    remove_templates(cache, &[*key])
}


pub fn expire_exporter(cache: &mut TemplateCache, exporter: IpAddr, now_ms: u64, age_ms: u64) -> usize {
    let stale: Vec<TemplateKey> = keys_in(cache, exporter, None)
        .into_iter()
        .filter(|key| cache.templates.get(key).is_some_and(|template| is_expired(template, now_ms, age_ms)))
        .collect();
    let removed = remove_templates(cache, &stale);
    cache.stats.expired_templates = cache.stats.expired_templates.saturating_add(removed as u64);
    removed
}


pub fn prune_expired(cache: &mut TemplateCache, now_ms: u64, age_ms: u64) -> usize {
    let exporters: Vec<IpAddr> = cache.exporters.keys().copied().collect();
    exporters
        .into_iter()
        .map(|exporter| expire_exporter(cache, exporter, now_ms, age_ms))
        .sum()
}


pub fn lookup_template(cache: &mut TemplateCache, key: &TemplateKey, now_ms: u64, age_ms: u64) -> Option<Arc<Template>> {
    let found = cache.templates.get(key).cloned();
    let fresh = found.filter(|template| !is_expired(template, now_ms, age_ms));
    if fresh.is_some() {
        touch_exporter(cache, key.exporter);
    } else if withdraw_template(cache, key) > 0 {
        cache.stats.expired_templates = cache.stats.expired_templates.saturating_add(1);
    }
    fresh
}


pub fn evict_least_recent_exporter(cache: &mut TemplateCache) -> usize {
    let oldest = cache
        .exporters
        .iter()
        .min_by_key(|(_, state)| state.last_used)
        .map(|(exporter, _)| *exporter);
    oldest.map_or(0, |exporter| evict_exporter(cache, exporter))
}


pub fn is_declared(cache: &TemplateCache, exporter: IpAddr) -> bool {
    cache.declared.contains(&source_key(exporter))
}


/// Exporters already holding templates under the admission key of `exporter`: one map lookup.
pub fn exporters_under_key(cache: &mut TemplateCache, exporter: IpAddr) -> usize {
    count_steps(cache, 1);
    cache.per_key.get(&source_key(exporter)).copied().unwrap_or(0)
}


pub fn count_steps(cache: &mut TemplateCache, steps: usize) {
    cache.stats.index_steps = cache.stats.index_steps.saturating_add(steps as u64);
}


/// The least recent exporter of an index other than `newcomer`, and the entries looked at: at most two, since only one entry is excluded.
pub fn least_recent_other(index: &LruIndex, newcomer: IpAddr) -> (Option<IpAddr>, usize) {
    let candidates: Vec<IpAddr> = index.iter().take(LRU_WINDOW).map(|(_, exporter)| *exporter).collect();
    let looked_at = candidates.len();
    (candidates.into_iter().find(|exporter| *exporter != newcomer), looked_at)
}


/// The exporter to evict for `newcomer`: the least recent undeclared one, or for a declared newcomer only, the least recent declared one.
pub fn eviction_victim(cache: &mut TemplateCache, newcomer: IpAddr) -> Option<IpAddr> {
    let (undeclared, undeclared_steps) = least_recent_other(&cache.undeclared_lru, newcomer);
    let try_declared = undeclared.is_none() && is_declared(cache, newcomer);
    let (declared, declared_steps) = if try_declared {
        least_recent_other(&cache.declared_lru, newcomer)
    } else {
        (None, 0)
    };
    count_steps(cache, undeclared_steps.saturating_add(declared_steps));
    undeclared.or(declared)
}


pub fn evict_exporter(cache: &mut TemplateCache, exporter: IpAddr) -> usize {
    let keys = keys_in(cache, exporter, None);
    cache.stats.evicted_exporters = cache.stats.evicted_exporters.saturating_add(u64::from(!keys.is_empty()));
    remove_templates(cache, &keys)
}


/// Only called for a template that is not a redefinition.
pub fn needs_room(cache: &TemplateCache, key: &TemplateKey, limits: &FlowLimits) -> bool {
    let new_exporter = !cache.exporters.contains_key(&key.exporter);
    (new_exporter && cache.exporters.len() >= limits.max_template_exporters) || cache.templates.len() >= limits.max_templates_total
}


/// Evicts whole exporters until the template fits; false when no exporter may be evicted for this newcomer.
pub fn make_room(cache: &mut TemplateCache, key: &TemplateKey, limits: &FlowLimits) -> bool {
    (0..=limits.max_template_exporters.max(cache.exporters.len()))
        .find_map(|_| {
            if !needs_room(cache, key, limits) {
                Some(true)
            } else {
                eviction_victim(cache, key.exporter).map_or(Some(false), |victim| {
                    evict_exporter(cache, victim);
                    None
                })
            }
        })
        .unwrap_or(false)
}


pub fn store_template(cache: &mut TemplateCache, key: TemplateKey, template: Template, limits: &FlowLimits) -> Result<(), FlowDrop> {
    let replaces = cache.templates.contains_key(&key);
    let known = cache.exporters.get(&key.exporter).copied();
    let exporter_full = known.is_some_and(|state| state.templates >= limits.max_templates_per_exporter);
    let key_full = known.is_none() && exporters_under_key(cache, key.exporter) >= limits.max_exporters_per_source_key;
    (replaces || !(exporter_full || key_full)).then_some(()).ok_or_else(|| refuse(cache))?;
    (replaces || make_room(cache, &key, limits)).then_some(()).ok_or_else(|| refuse(cache))?;
    if !replaces {
        if !cache.exporters.contains_key(&key.exporter) {
            add_exporter(cache, key.exporter);
        }
        cache
            .exporters
            .entry(key.exporter)
            .and_modify(|state| state.templates = state.templates.saturating_add(1));
    }
    cache.templates.insert(key, Arc::new(template));
    touch_exporter(cache, key.exporter);
    Ok(())
}


pub fn refuse(cache: &mut TemplateCache) -> FlowDrop {
    cache.stats.refused_templates = cache.stats.refused_templates.saturating_add(1);
    FlowDrop::TemplateRefused
}
