use crate::error::ConfigError;
use crate::model::{
    Bucket, BucketLimits, Collector, CollectorConfig, DropReason, SourceCounters, SourceState, MAX_MESSAGE_BYTES, MAX_SHARE_PERCENT, MILLI_TOKENS,
};
use crate::types::{Millis, SourceId, SourceMap};


fn check(condition: bool, error: ConfigError) -> Result<(), ConfigError> {
    condition.then_some(()).ok_or(error)
}


pub fn validate_config(config: &CollectorConfig) -> Result<(), ConfigError> {
    check(config.global.rate_per_second > 0, ConfigError::ZeroRate)?;
    check(config.global.burst > 0, ConfigError::ZeroBurst)?;
    check((1..=MAX_SHARE_PERCENT).contains(&config.source_share_percent), ConfigError::BadShare)?;
    check(config.max_sources > 0, ConfigError::ZeroMaxSources)
}


pub fn share_limits(global: &BucketLimits, percent: u64) -> BucketLimits {
    BucketLimits {
        rate_per_second: (global.rate_per_second.saturating_mul(percent) / MAX_SHARE_PERCENT).max(1),
        burst: (global.burst.saturating_mul(percent) / MAX_SHARE_PERCENT).max(1),
    }
}


pub fn full_bucket(limits: &BucketLimits, now: Millis) -> Bucket {
    Bucket {
        milli_tokens: limits.burst.saturating_mul(MILLI_TOKENS),
        updated_ms: now,
    }
}


pub fn new_collector(config: CollectorConfig) -> Result<Collector, ConfigError> {
    validate_config(&config)?;
    Ok(Collector {
        source_limits: share_limits(&config.global, config.source_share_percent),
        global: full_bucket(&config.global, 0),
        sources: SourceMap::new(),
        untracked_dropped: 0,
        config,
    })
}


pub fn take_token(bucket: &mut Bucket, limits: &BucketLimits, now: Millis) -> bool {
    let elapsed = now.saturating_sub(bucket.updated_ms);
    let capacity = limits.burst.saturating_mul(MILLI_TOKENS);
    let refilled = bucket
        .milli_tokens
        .saturating_add(elapsed.saturating_mul(limits.rate_per_second))
        .min(capacity);
    let allowed = refilled >= MILLI_TOKENS;
    bucket.updated_ms = bucket.updated_ms.max(now);
    bucket.milli_tokens = if allowed { refilled - MILLI_TOKENS } else { refilled };
    allowed
}


fn check_bucket(bucket: &mut Bucket, limits: &BucketLimits, now: Millis, reason: DropReason) -> Result<(), DropReason> {
    take_token(bucket, limits, now).then_some(()).ok_or(reason)
}


fn check_known(known: bool, drop_unknown: bool) -> Result<(), DropReason> {
    (known || !drop_unknown).then_some(()).ok_or(DropReason::UnknownSource)
}


fn check_size(len: usize) -> Result<(), DropReason> {
    (len <= MAX_MESSAGE_BYTES).then_some(()).ok_or(DropReason::TooLarge)
}


pub fn slot<'a>(sources: &'a mut SourceMap, limits: &BucketLimits, source: SourceId, now: Millis) -> &'a mut SourceState {
    sources.entry(source).or_insert_with(|| SourceState {
        bucket: full_bucket(limits, now),
        last_seen_ms: now,
        counters: SourceCounters::default(),
    })
}


fn count_drop(counters: &mut SourceCounters, verdict: &Result<(), DropReason>) {
    match verdict {
        Ok(()) => {}
        Err(DropReason::UnknownSource) => counters.dropped_unknown += 1,
        Err(DropReason::TooLarge) => counters.dropped_size += 1,
        Err(DropReason::SourceRate | DropReason::GlobalRate | DropReason::SourceTableFull) => counters.dropped_rate += 1,
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
        state.counters.unknown_seen += u64::from(!known);
        let verdict = check_known(known, collector.config.drop_unknown)
            .and_then(|()| check_size(len))
            .and_then(|()| check_bucket(&mut state.bucket, &collector.source_limits, now, DropReason::SourceRate))
            .and_then(|()| check_bucket(&mut collector.global, &collector.config.global, now, DropReason::GlobalRate));
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
