use crate::error::ConfigError;
use crate::model::{
    Bucket, BucketLimits, Collector, CollectorConfig, DropReason, ScaledLimits, SourceCounters, SourceState, MAX_MESSAGE_BYTES, MAX_SHARE_PERCENT,
    MAX_UNKNOWN_SHARE_PERCENT, MILLIS_PER_SECOND, PERCENT, UNITS_PER_TOKEN,
};
use crate::types::{Millis, SourceId, SourceMap};


fn check(condition: bool, error: ConfigError) -> Result<(), ConfigError> {
    condition.then_some(()).ok_or(error)
}


pub fn validate_config(config: &CollectorConfig) -> Result<(), ConfigError> {
    check(config.global.rate_per_second > 0, ConfigError::ZeroRate)?;
    check(config.global.burst > 0, ConfigError::ZeroBurst)?;
    check((1..=MAX_SHARE_PERCENT).contains(&config.source_share_percent), ConfigError::BadShare)?;
    check(
        (1..=MAX_UNKNOWN_SHARE_PERCENT).contains(&config.unknown_share_percent),
        ConfigError::BadUnknownShare,
    )?;
    check(config.max_sources > 0, ConfigError::ZeroMaxSources)?;
    check(
        holds_one_message(&config.global, config.source_share_percent) && holds_one_message(&config.global, config.unknown_share_percent),
        ConfigError::ShareBelowOneMessage,
    )
}


pub fn share_limits(global: &BucketLimits, percent: u64) -> ScaledLimits {
    ScaledLimits {
        rate_per_ms: global.rate_per_second.saturating_mul(percent),
        burst: global.burst.saturating_mul(percent).saturating_mul(MILLIS_PER_SECOND),
    }
}


pub fn holds_one_message(global: &BucketLimits, percent: u64) -> bool {
    share_limits(global, percent).burst >= UNITS_PER_TOKEN
}


pub fn full_bucket(limits: &ScaledLimits, now: Millis) -> Bucket {
    Bucket {
        units: limits.burst,
        updated_ms: now,
    }
}


pub fn new_collector(config: CollectorConfig) -> Result<Collector, ConfigError> {
    validate_config(&config)?;
    let unknown_limits = share_limits(&config.global, config.unknown_share_percent);
    let global_limits = share_limits(&config.global, PERCENT);
    Ok(Collector {
        source_limits: share_limits(&config.global, config.source_share_percent),
        global: full_bucket(&global_limits, 0),
        global_limits,
        unknown: full_bucket(&unknown_limits, 0),
        unknown_limits,
        sources: SourceMap::new(),
        untracked_dropped: 0,
        config,
    })
}


pub fn reconfigure(collector: &mut Collector, config: CollectorConfig) -> Result<(), ConfigError> {
    validate_config(&config)?;
    collector.global_limits = share_limits(&config.global, PERCENT);
    collector.source_limits = share_limits(&config.global, config.source_share_percent);
    collector.unknown_limits = share_limits(&config.global, config.unknown_share_percent);
    collector.config = config;
    Ok(())
}


pub fn collector_config(collector: &Collector) -> &CollectorConfig {
    &collector.config
}


pub fn source_counters<'a>(collector: &'a Collector, source: &SourceId) -> Option<&'a SourceCounters> {
    collector.sources.get(source).map(|state| &state.counters)
}


pub fn tracked_sources(collector: &Collector) -> usize {
    collector.sources.len()
}


pub fn is_tracked(collector: &Collector, source: &SourceId) -> bool {
    collector.sources.contains_key(source)
}


pub fn untracked_dropped(collector: &Collector) -> u64 {
    collector.untracked_dropped
}


pub fn take_token(bucket: &mut Bucket, limits: &ScaledLimits, now: Millis) -> bool {
    let elapsed = now.saturating_sub(bucket.updated_ms);
    let refilled = bucket.units.saturating_add(elapsed.saturating_mul(limits.rate_per_ms)).min(limits.burst);
    let allowed = refilled >= UNITS_PER_TOKEN;
    bucket.updated_ms = bucket.updated_ms.max(now);
    bucket.units = if allowed { refilled - UNITS_PER_TOKEN } else { refilled };
    allowed
}


fn check_bucket(bucket: &mut Bucket, limits: &ScaledLimits, now: Millis, reason: DropReason) -> Result<(), DropReason> {
    take_token(bucket, limits, now).then_some(()).ok_or(reason)
}


fn check_known(known: bool, drop_unknown: bool) -> Result<(), DropReason> {
    (known || !drop_unknown).then_some(()).ok_or(DropReason::UnknownSource)
}


fn check_size(len: usize) -> Result<(), DropReason> {
    (len <= MAX_MESSAGE_BYTES).then_some(()).ok_or(DropReason::TooLarge)
}


fn check_unknown_rate(known: bool, collector_bucket: &mut Bucket, limits: &ScaledLimits, now: Millis) -> Result<(), DropReason> {
    if known {
        Ok(())
    } else {
        check_bucket(collector_bucket, limits, now, DropReason::UnknownRate)
    }
}


pub fn slot<'a>(sources: &'a mut SourceMap, limits: &ScaledLimits, source: SourceId, now: Millis) -> &'a mut SourceState {
    sources.entry(source).or_insert_with(|| SourceState {
        bucket: full_bucket(limits, now),
        last_seen_ms: now,
        counters: SourceCounters::default(),
    })
}


fn count_drop(counters: &mut SourceCounters, verdict: &Result<(), DropReason>) {
    match verdict {
        Ok(()) => {}
        Err(DropReason::UnknownSource) => counters.dropped_unknown = counters.dropped_unknown.saturating_add(1),
        Err(DropReason::TooLarge) => counters.dropped_size = counters.dropped_size.saturating_add(1),
        Err(DropReason::SourceRate | DropReason::UnknownRate | DropReason::GlobalRate | DropReason::SourceTableFull) => {
            counters.dropped_rate = counters.dropped_rate.saturating_add(1)
        }
    }
}


pub fn admit(collector: &mut Collector, source: SourceId, len: usize, now: Millis) -> Result<(), DropReason> {
    let known = collector.config.sources.contains(&source);
    let table_full = !known && !collector.sources.contains_key(&source) && collector.sources.len() >= collector.config.max_sources;
    if table_full {
        collector.untracked_dropped = collector.untracked_dropped.saturating_add(1);
        Err(DropReason::SourceTableFull)
    } else {
        let state = slot(&mut collector.sources, &collector.source_limits, source, now);
        state.last_seen_ms = now;
        state.counters.unknown_seen = state.counters.unknown_seen.saturating_add(u64::from(!known));
        let verdict = check_known(known, collector.config.drop_unknown)
            .and_then(|()| check_size(len))
            .and_then(|()| check_bucket(&mut state.bucket, &collector.source_limits, now, DropReason::SourceRate))
            .and_then(|()| check_unknown_rate(known, &mut collector.unknown, &collector.unknown_limits, now))
            .and_then(|()| check_bucket(&mut collector.global, &collector.global_limits, now, DropReason::GlobalRate));
        count_drop(&mut state.counters, &verdict);
        verdict
    }
}


pub fn prune_idle(collector: &mut Collector, now: Millis, idle_ms: Millis) -> usize {
    let before = collector.sources.len();
    let declared = &collector.config.sources;
    collector
        .sources
        .retain(|source, state| declared.contains(source) || now.saturating_sub(state.last_seen_ms) < idle_ms);
    before - collector.sources.len()
}
