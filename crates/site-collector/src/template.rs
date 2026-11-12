//! The bounded per-exporter template cache of NetFlow v9 and IPFIX (spec section 22).

use crate::flow_model::{FlowDrop, FlowLimits};
use crate::template_model::{ExporterState, Template, TemplateCache, TemplateKey, MILLIS_PER_SECOND};
use std::net::IpAddr;
use std::sync::Arc;


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
        cache.exporters.remove(&exporter);
    }
}


pub fn touch_exporter(cache: &mut TemplateCache, exporter: IpAddr) {
    cache.tick = cache.tick.saturating_add(1);
    let tick = cache.tick;
    cache.exporters.entry(exporter).and_modify(|state| state.last_used = tick);
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
    let keys = oldest.map(|exporter| keys_in(cache, exporter, None)).unwrap_or_else(Vec::new);
    cache.stats.evicted_exporters = cache.stats.evicted_exporters.saturating_add(u64::from(!keys.is_empty()));
    remove_templates(cache, &keys)
}


pub fn store_template(cache: &mut TemplateCache, key: TemplateKey, template: Template, limits: &FlowLimits) -> Result<(), FlowDrop> {
    let replaces = cache.templates.contains_key(&key);
    let known = cache.exporters.get(&key.exporter).copied();
    let exporter_full = known.is_some_and(|state| state.templates >= limits.max_templates_per_exporter);
    (replaces || !exporter_full).then_some(()).ok_or_else(|| refuse(cache))?;
    if known.is_none() && cache.exporters.len() >= limits.max_template_exporters {
        evict_least_recent_exporter(cache);
    }
    if !replaces {
        cache.tick = cache.tick.saturating_add(1);
        let tick = cache.tick;
        let state = cache.exporters.entry(key.exporter).or_insert(ExporterState {
            last_used: tick,
            templates: 0,
        });
        state.templates = state.templates.saturating_add(1);
    }
    cache.templates.insert(key, Arc::new(template));
    touch_exporter(cache, key.exporter);
    Ok(())
}


pub fn refuse(cache: &mut TemplateCache) -> FlowDrop {
    cache.stats.refused_templates = cache.stats.refused_templates.saturating_add(1);
    FlowDrop::TemplateRefused
}
