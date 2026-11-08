#[path = "support/types.rs"]
mod types;


use site_collector::admission::{admit, new_collector, prune_idle, share_limits, take_token, validate_config};
use site_collector::error::ConfigError;
use site_collector::model::{Bucket, BucketLimits, Collector, CollectorConfig, DropReason, MAX_MESSAGE_BYTES};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use types::TestResult;


const GLOBAL_RATE: u64 = 10;


const GLOBAL_BURST: u64 = 10;


const SHARE: u64 = 50;


const MAX_SOURCES: usize = 3;


const MILLIS_PER_SECOND: u64 = 1000;


const HALF_SECOND: u64 = 500;


const IDLE: u64 = 100;


const NET: u8 = 10;


const HOST_A: u8 = 1;


const HOST_B: u8 = 2;


const HOST_C: u8 = 3;


const SOURCE_TOKENS: u64 = 5;


const BUCKET_RATE: u64 = 2;


const SPOOFED: u8 = 5;


const SPOOF_BASE: u8 = 100;


const FLOOD: usize = 50;


fn host(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(NET, 0, 0, last))
}


fn config(declared: &[u8], drop_unknown: bool) -> CollectorConfig {
    CollectorConfig {
        global: BucketLimits {
            rate_per_second: GLOBAL_RATE,
            burst: GLOBAL_BURST,
        },
        source_share_percent: SHARE,
        sources: declared.iter().map(|last| host(*last)).collect::<BTreeSet<_>>(),
        drop_unknown,
        max_sources: MAX_SOURCES,
    }
}


fn collector(declared: &[u8], drop_unknown: bool) -> Result<Collector, ConfigError> {
    new_collector(config(declared, drop_unknown))
}


#[test]
fn invalid_configs_are_refused() -> TestResult {
    let mut bad = config(&[], false);
    bad.global.rate_per_second = 0;
    assert_eq!(validate_config(&bad), Err(ConfigError::ZeroRate));
    let mut no_burst = config(&[], false);
    no_burst.global.burst = 0;
    assert_eq!(validate_config(&no_burst), Err(ConfigError::ZeroBurst));
    let mut no_share = config(&[], false);
    no_share.source_share_percent = 0;
    assert_eq!(validate_config(&no_share), Err(ConfigError::BadShare));
    no_share.source_share_percent = MILLIS_PER_SECOND;
    assert_eq!(validate_config(&no_share), Err(ConfigError::BadShare));
    let mut no_sources = config(&[], false);
    no_sources.max_sources = 0;
    assert_eq!(new_collector(no_sources).err(), Some(ConfigError::ZeroMaxSources));
    assert_eq!(validate_config(&config(&[], false)), Ok(()));
    Ok(())
}


#[test]
fn share_is_a_fraction_of_the_global_limits_and_never_zero() -> TestResult {
    let limits = share_limits(
        &BucketLimits {
            rate_per_second: GLOBAL_RATE,
            burst: GLOBAL_BURST,
        },
        SHARE,
    );
    assert_eq!(
        limits,
        BucketLimits {
            rate_per_second: SOURCE_TOKENS,
            burst: SOURCE_TOKENS
        }
    );
    let tiny = share_limits(
        &BucketLimits {
            rate_per_second: 1,
            burst: 1,
        },
        1,
    );
    assert_eq!(
        tiny,
        BucketLimits {
            rate_per_second: 1,
            burst: 1
        }
    );
    Ok(())
}


#[test]
fn bucket_refills_with_the_injected_clock_and_caps_at_burst() -> TestResult {
    let limits = BucketLimits {
        rate_per_second: BUCKET_RATE,
        burst: BUCKET_RATE,
    };
    let mut bucket = Bucket {
        milli_tokens: 0,
        updated_ms: 0,
    };
    assert!(!take_token(&mut bucket, &limits, 0));
    assert!(take_token(&mut bucket, &limits, HALF_SECOND));
    assert!(!take_token(&mut bucket, &limits, HALF_SECOND));
    assert!(take_token(&mut bucket, &limits, MILLIS_PER_SECOND * MILLIS_PER_SECOND));
    assert!(take_token(&mut bucket, &limits, MILLIS_PER_SECOND * MILLIS_PER_SECOND));
    assert!(!take_token(&mut bucket, &limits, MILLIS_PER_SECOND * MILLIS_PER_SECOND));
    assert!(!take_token(&mut bucket, &limits, 0));
    Ok(())
}


#[test]
fn size_cap_drops_and_counts() -> TestResult {
    let mut state = collector(&[HOST_A], true)?;
    assert_eq!(admit(&mut state, host(HOST_A), MAX_MESSAGE_BYTES, 0), Ok(()));
    assert_eq!(admit(&mut state, host(HOST_A), MAX_MESSAGE_BYTES + 1, 0), Err(DropReason::TooLarge));
    let counters = &state.sources.get(&host(HOST_A)).ok_or("tracked")?.counters;
    assert_eq!(counters.dropped_size, 1);
    assert_eq!(counters.unknown_seen, 0);
    Ok(())
}


#[test]
fn unknown_sources_are_counted_and_dropped_on_request() -> TestResult {
    let mut dropping = collector(&[HOST_A], true)?;
    assert_eq!(admit(&mut dropping, host(HOST_B), 1, 0), Err(DropReason::UnknownSource));
    let counters = &dropping.sources.get(&host(HOST_B)).ok_or("tracked")?.counters;
    assert_eq!((counters.unknown_seen, counters.dropped_unknown), (1, 1));
    let mut lenient = collector(&[HOST_A], false)?;
    assert_eq!(admit(&mut lenient, host(HOST_B), 1, 0), Ok(()));
    let lenient_counters = &lenient.sources.get(&host(HOST_B)).ok_or("tracked")?.counters;
    assert_eq!((lenient_counters.unknown_seen, lenient_counters.dropped_unknown), (1, 0));
    Ok(())
}


#[test]
fn flooding_source_does_not_starve_another() -> TestResult {
    let mut state = collector(&[HOST_A, HOST_B], true)?;
    let flood_results: Vec<_> = (0..FLOOD).map(|_| admit(&mut state, host(HOST_A), 1, 0)).collect();
    let admitted = flood_results.iter().filter(|result| result.is_ok()).count();
    assert_eq!(admitted as u64, SOURCE_TOKENS);
    assert!(flood_results.contains(&Err(DropReason::SourceRate)));
    assert_eq!(admit(&mut state, host(HOST_B), 1, 0), Ok(()));
    let flooder = &state.sources.get(&host(HOST_A)).ok_or("tracked")?.counters;
    assert_eq!(flooder.dropped_rate, FLOOD as u64 - SOURCE_TOKENS);
    Ok(())
}


#[test]
fn global_bucket_caps_the_total() -> TestResult {
    let mut state = collector(&[HOST_A, HOST_B, HOST_C], true)?;
    let results: Vec<_> = [HOST_A, HOST_B, HOST_C]
        .iter()
        .flat_map(|last| (0..SHARE).map(move |_| *last))
        .map(|last| admit(&mut state, host(last), 1, 0))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count() as u64, GLOBAL_BURST);
    assert!(results.contains(&Err(DropReason::GlobalRate)));
    Ok(())
}


#[test]
fn distinct_source_cap_drops_new_unknown_sources_only() -> TestResult {
    let mut state = collector(&[HOST_A], false)?;
    let spoofed: Vec<_> = (0..SPOOFED).map(|offset| admit(&mut state, host(SPOOF_BASE + offset), 1, 0)).collect();
    assert_eq!(state.sources.len(), MAX_SOURCES);
    assert_eq!(
        spoofed.iter().filter(|result| **result == Err(DropReason::SourceTableFull)).count(),
        usize::from(SPOOFED) - MAX_SOURCES
    );
    assert_eq!(state.untracked_dropped, (usize::from(SPOOFED) - MAX_SOURCES) as u64);
    assert_eq!(admit(&mut state, host(HOST_A), 1, 0), Ok(()));
    assert_eq!(admit(&mut state, host(SPOOF_BASE), 1, 0), Ok(()));
    assert_eq!(state.sources.len(), MAX_SOURCES + 1);
    Ok(())
}


#[test]
fn idle_unknown_sources_are_pruned_declared_ones_stay() -> TestResult {
    let mut state = collector(&[HOST_A], false)?;
    admit(&mut state, host(HOST_A), 1, 0)?;
    admit(&mut state, host(HOST_B), 1, 0)?;
    admit(&mut state, host(HOST_C), 1, IDLE)?;
    assert_eq!(prune_idle(&mut state, IDLE, IDLE), 1);
    assert!(state.sources.contains_key(&host(HOST_A)));
    assert!(!state.sources.contains_key(&host(HOST_B)));
    assert!(state.sources.contains_key(&host(HOST_C)));
    Ok(())
}
